use super::ExecError;

/// Windows in-memory execution stub.
///
/// A full implementation would:
///   1. Parse PE headers from the binary
///   2. VirtualAlloc with PAGE_EXECUTE_READWRITE
///   3. Map PE sections at correct RVAs
///   4. Process base relocations
///   5. Resolve imports via LoadLibraryA / GetProcAddress
///   6. Execute TLS callbacks, then call the entry point
pub fn exec_in_memory(_binary: Vec<u8>, _args: Vec<String>) -> Result<(), ExecError> {
    Err(ExecError::UnsupportedPlatform)
}
