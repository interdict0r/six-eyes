use std::collections::HashSet;
use std::sync::LazyLock;
use eframe::egui::Color32;
use crate::model::*;

pub static HIGH_SUSPICIOUS_IMPORTS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtCreateThreadEx",
        "ZwUnmapViewOfSection","SetThreadContext","RtlCreateUserThread","QueueUserAPC","NtUnmapViewOfSection",
    ].into_iter().collect()
});

pub static MED_SUSPICIOUS_IMPORTS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "IsDebuggerPresent","CheckRemoteDebuggerPresent","CryptEncrypt","CryptDecrypt",
        "BCryptEncrypt","BCryptDecrypt","InternetOpenA","InternetOpenW","HttpOpenRequestA",
        "WinHttpOpen","URLDownloadToFileA","VirtualAlloc","LoadLibraryA","GetProcAddress",
        "RegOpenKeyExA","RegSetValueExA","CreateProcessA","CreateProcessW","ShellExecuteA","WinExec",
    ].into_iter().collect()
});

pub fn suspicious_import_color(name: &str) -> Color32 {
    if HIGH_SUSPICIOUS_IMPORTS.contains(name) { Color32::from_rgb(220,80,80) }
    else if MED_SUSPICIOUS_IMPORTS.contains(name) { Color32::from_rgb(220,160,40) }
    else { Color32::GRAY }
}

pub struct CapabilityDef {
    pub name:        &'static str,
    pub description: &'static str,
    pub mitre:       &'static str,
    pub threat:      u8,
    pub apis:        &'static [&'static str],
}

pub const CAPABILITIES: &[CapabilityDef] = &[
    CapabilityDef {
        name: "Process Injection", description: "Inject code into remote processes",
        mitre: "T1055", threat: 2,
        apis: &["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtCreateThreadEx",
                "RtlCreateUserThread","QueueUserAPC"],
    },
    CapabilityDef {
        name: "Process Hollowing", description: "Unmap and replace process memory",
        mitre: "T1055.012", threat: 2,
        apis: &["ZwUnmapViewOfSection","NtUnmapViewOfSection","SetThreadContext","GetThreadContext"],
    },
    CapabilityDef {
        name: "Anti-Debug / Evasion", description: "Detect analysis tools or sandboxes",
        mitre: "T1622", threat: 2,
        apis: &["IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
                "FindWindowA","OutputDebugStringA","NtSetInformationThread"],
    },
    CapabilityDef {
        name: "Cryptographic Operations", description: "Encrypt or decrypt data at runtime",
        mitre: "T1027", threat: 1,
        apis: &["CryptAcquireContextA","CryptAcquireContextW","CryptEncrypt","CryptDecrypt",
                "CryptGenKey","BCryptEncrypt","BCryptDecrypt","BCryptGenRandom",
                "BCryptOpenAlgorithmProvider"],
    },
    CapabilityDef {
        name: "Network Communication", description: "Establish outbound network connections",
        mitre: "T1071", threat: 1,
        apis: &["InternetOpenA","InternetOpenW","HttpOpenRequestA","HttpSendRequestA",
                "WinHttpOpen","WinHttpConnect","URLDownloadToFileA","URLDownloadToFileW",
                "WSAStartup","connect","send","recv","getaddrinfo","socket"],
    },
    CapabilityDef {
        name: "Registry Modification", description: "Read or write Windows Registry keys",
        mitre: "T1112", threat: 1,
        apis: &["RegOpenKeyExA","RegOpenKeyExW","RegSetValueExA","RegSetValueExW",
                "RegCreateKeyExA","RegDeleteKeyA","RegQueryValueExA"],
    },
    CapabilityDef {
        name: "Process Creation", description: "Spawn new processes or execute commands",
        mitre: "T1106", threat: 1,
        apis: &["CreateProcessA","CreateProcessW","CreateProcessAsUserA","ShellExecuteA",
                "ShellExecuteW","ShellExecuteExA","WinExec","system"],
    },
    CapabilityDef {
        name: "Dynamic API Resolution", description: "Load libraries and resolve functions at runtime",
        mitre: "T1027.007", threat: 1,
        apis: &["LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW",
                "GetProcAddress","GetModuleHandleA","GetModuleHandleW","LdrLoadDll"],
    },
    CapabilityDef {
        name: "Service Management", description: "Install or control Windows services",
        mitre: "T1543.003", threat: 1,
        apis: &["OpenSCManagerA","OpenSCManagerW","CreateServiceA","CreateServiceW",
                "StartServiceA","ControlService","DeleteService","ChangeServiceConfigA"],
    },
    CapabilityDef {
        name: "Privilege Escalation", description: "Adjust process token privileges",
        mitre: "T1134", threat: 2,
        apis: &["OpenProcessToken","AdjustTokenPrivileges","LookupPrivilegeValueA",
                "ImpersonateLoggedOnUser","DuplicateTokenEx","SetTokenInformation"],
    },
    CapabilityDef {
        name: "File System Access", description: "Read, write, or enumerate files",
        mitre: "T1083", threat: 0,
        apis: &["CreateFileA","CreateFileW","ReadFile","WriteFile","DeleteFileA","DeleteFileW",
                "CopyFileA","MoveFileA","MoveFileExA","FindFirstFileA","FindFirstFileW",
                "GetTempPathA","GetTempFileNameA"],
    },
    CapabilityDef {
        name: "Memory Manipulation", description: "Allocate or change memory page protections",
        mitre: "T1055", threat: 1,
        apis: &["VirtualAlloc","VirtualAllocEx","VirtualProtect","VirtualProtectEx",
                "ReadProcessMemory","VirtualFree","HeapCreate","NtAllocateVirtualMemory"],
    },
    CapabilityDef {
        name: "Thread Control", description: "Create, suspend, or manipulate threads",
        mitre: "T1055", threat: 1,
        apis: &["CreateThread","SuspendThread","ResumeThread","TerminateThread",
                "NtCreateThreadEx","SetThreadContext","GetThreadContext"],
    },
    CapabilityDef {
        name: "Clipboard Access", description: "Read or write the system clipboard",
        mitre: "T1115", threat: 1,
        apis: &["OpenClipboard","GetClipboardData","SetClipboardData","EmptyClipboard"],
    },
    CapabilityDef {
        name: "Keystroke Logging", description: "Capture keyboard input",
        mitre: "T1056.001", threat: 2,
        apis: &["SetWindowsHookExA","SetWindowsHookExW","GetAsyncKeyState","GetKeyState",
                "GetKeyboardState","MapVirtualKeyA"],
    },
    CapabilityDef {
        name: "Screen Capture", description: "Capture screenshots or window content",
        mitre: "T1113", threat: 1,
        apis: &["BitBlt","GetDC","GetWindowDC","CreateCompatibleBitmap","PrintWindow"],
    },
    CapabilityDef {
        name: "Credential Dumping", description: "Dump credentials from memory or registry hives",
        mitre: "T1003", threat: 2,
        apis: &["MiniDumpWriteDump","SamConnect","SamOpenDomain","SamOpenUser",
                "SamGetMembersInAlias","LsaOpenPolicy","LsaQueryInformationPolicy",
                "NtReadVirtualMemory","ReadProcessMemory","LsaEnumerateLogonSessions"],
    },
    CapabilityDef {
        name: "AMSI Bypass", description: "Disable Antimalware Scan Interface to evade detection",
        mitre: "T1562.001", threat: 2,
        apis: &["AmsiScanBuffer","AmsiInitialize","AmsiOpenSession","AmsiScanString",
                "AmsiCloseSession","AmsiUninitialize"],
    },
    CapabilityDef {
        name: "ETW Bypass", description: "Disable Event Tracing for Windows to blind logging",
        mitre: "T1562.006", threat: 2,
        apis: &["EtwEventWrite","EtwEventWriteFull","NtTraceControl","NtTraceEvent",
                "EtwRegister","EtwUnregister"],
    },
    CapabilityDef {
        name: "Lateral Movement", description: "Access remote systems via network shares or WMI",
        mitre: "T1021", threat: 2,
        // CoCreateInstance and WinExec omitted: too broad (COM is ubiquitous; WinExec already
        // covered by Process Creation). IWbemServices is a COM interface, not an importable symbol.
        apis: &["WNetAddConnection2A","WNetAddConnection2W","WNetAddConnectionA","WNetOpenEnumA",
                "NetShareEnum","NetShareGetInfo","NetSessionEnum"],
    },
    CapabilityDef {
        name: "Scheduled Task / Job", description: "Create or modify scheduled tasks for persistence",
        mitre: "T1053.005", threat: 2,
        // ITaskService, IRegisteredTask, ITaskFolder, ITaskDefinition are COM interface names —
        // they never appear in a PE import table. Only importable scheduler APIs are listed.
        apis: &["NetScheduleJobAdd","NetScheduleJobEnum"],
    },
    CapabilityDef {
        name: "System Discovery", description: "Enumerate system information, users, or network config",
        mitre: "T1082", threat: 0,
        apis: &["GetSystemInfo","GetComputerNameA","GetComputerNameW","GetComputerNameExA",
                "GetUserNameA","GetUserNameW","GetAdaptersInfo","GetAdaptersAddresses",
                "EnumSystemLocalesA","GetNativeSystemInfo","RtlGetVersion",
                "NetGetJoinInformation","GetTcpTable","GetUdpTable"],
    },
    CapabilityDef {
        name: "Mouse / Input Capture", description: "Hook mouse events or capture input",
        mitre: "T1056.002", threat: 2,
        apis: &["SetWindowsHookExA","SetWindowsHookExW","mouse_event","SendInput",
                "GetCursorPos","SetCursorPos","GetDoubleClickTime"],
    },
    CapabilityDef {
        name: "Data Exfiltration", description: "Upload or send data to remote locations",
        mitre: "T1041", threat: 2,
        apis: &["InternetWriteFile","FtpPutFileA","FtpPutFileW","FtpOpenFileA",
                "WinHttpSendRequest","WinHttpWriteData","WSASend","sendto"],
    },
    CapabilityDef {
        name: "COM Object Hijacking", description: "Abuse COM infrastructure for execution or persistence",
        mitre: "T1546.015", threat: 2,
        apis: &["CoCreateInstance","CoCreateInstanceEx","CoGetClassObject",
                "OleInitialize","CoInitializeEx","CoRegisterClassObject"],
    },
    CapabilityDef {
        name: "Named Pipe / IPC", description: "Use named pipes for inter-process communication or C2",
        mitre: "T1071.004", threat: 1,
        apis: &["CreateNamedPipeA","CreateNamedPipeW","ConnectNamedPipe","DisconnectNamedPipe",
                "WaitNamedPipeA","CallNamedPipeA","TransactNamedPipe"],
    },
    CapabilityDef {
        name: "Window Enumeration", description: "Enumerate windows, possibly for process/sandbox detection",
        mitre: "T1010", threat: 0,
        apis: &["EnumWindows","FindWindowA","FindWindowW","FindWindowExA","FindWindowExW",
                "GetForegroundWindow","GetWindowTextA","GetWindowTextLengthA",
                "GetClassName","GetWindowThreadProcessId"],
    },
];

pub struct MatchedCapability {
    pub name:        &'static str,
    pub description: &'static str,
    pub mitre:       &'static str,
    pub threat:      u8,
    pub matched:     Vec<&'static str>,
}

pub fn detect_capabilities(pe: &PeInfo) -> Vec<MatchedCapability> {
    let all_fns: HashSet<&str> = pe.imports.iter()
        .flat_map(|i| i.functions.iter().map(|s| s.as_str())).collect();
    let mut caps = Vec::new();
    for def in CAPABILITIES {
        let matched: Vec<&'static str> = def.apis.iter()
            .filter(|a| all_fns.contains(*a))
            .copied().collect();
        if !matched.is_empty() {
            caps.push(MatchedCapability {
                name: def.name, description: def.description,
                mitre: def.mitre, threat: def.threat, matched,
            });
        }
    }
    caps.sort_by(|a, b| b.threat.cmp(&a.threat));
    caps
}

#[derive(Clone)]
pub struct HeuristicFlag {
    pub severity: Severity,
    pub category: &'static str,
    pub message:  String,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity { Info, Warn, Critical }

impl Severity {
    #[inline] pub fn color(self) -> Color32 {
        match self {
            Self::Info     => Color32::from_rgb(100, 170, 255),
            Self::Warn     => Color32::from_rgb(220, 170, 40),
            Self::Critical => Color32::from_rgb(220, 60, 60),
        }
    }
    #[inline] pub fn icon(self) -> &'static str {
        match self { Self::Info => "i", Self::Warn => "!", Self::Critical => "!!" }
    }
    #[inline] pub fn label(self) -> &'static str {
        match self { Self::Info => "INFO", Self::Warn => "WARN", Self::Critical => "CRIT" }
    }
}

pub fn build_heuristic_flags(pe: &PeInfo) -> Vec<HeuristicFlag> {
    let mut flags = Vec::new();
    macro_rules! f {
        ($sev:expr, $cat:expr, $msg:expr) => {
            flags.push(HeuristicFlag { severity: $sev, category: $cat, message: $msg.to_string() })
        };
    }

    for s in &pe.sections {
        if s.entropy > 7.2 {
            f!(Severity::Critical, "Packing/Obfuscation",
               format!("'{}' entropy {:.2} — likely packed or encrypted", s.name, s.entropy));
        } else if s.entropy > 6.8 {
            f!(Severity::Warn, "Packing/Obfuscation",
               format!("'{}' entropy {:.2} — possibly compressed", s.name, s.entropy));
        }
        if s.name.trim().is_empty() && s.characteristics.contains(&"EXECUTE") {
            f!(Severity::Critical, "Packing/Obfuscation", "Unnamed executable section");
        }
        if s.characteristics.contains(&"WRITE") && s.characteristics.contains(&"EXECUTE") {
            f!(Severity::Warn, "Packing/Obfuscation", format!("'{}' is RWX — self-modifying code", s.name));
        }
        if s.raw_size > 0 && s.virtual_size > s.raw_size * 10 {
            let ratio = s.virtual_size / s.raw_size;
            f!(Severity::Warn, "Packing/Obfuscation",
               format!("'{}' VirtualSize/RawSize = {}x — likely unpacks at runtime", s.name, ratio));
        }
        if s.raw_size == 0 && s.virtual_size > 0x1000 {
            f!(Severity::Warn, "Packing/Obfuscation",
               format!("'{}' has zero raw data but 0x{:X} virtual size — runtime-allocated", s.name, s.virtual_size));
        }
    }

    let obf_count = pe.strings.iter().filter(|s| s.kind == StringKind::Obfuscated).count();
    if obf_count > 20 {
        f!(Severity::Critical, "Packing/Obfuscation", format!("{obf_count} obfuscated strings detected"));
    } else if obf_count > 5 {
        f!(Severity::Warn, "Packing/Obfuscation", format!("{obf_count} possibly encoded strings"));
    }

    let embedded_pe = pe.embedded.iter().filter(|a| a.kind == ArtifactKind::Pe).count();
    let embedded_sc = pe.embedded.iter().filter(|a| a.kind == ArtifactKind::Shellcode).count();
    if embedded_pe > 0 {
        f!(Severity::Critical, "Packing/Obfuscation",
           format!("{embedded_pe} embedded PE(s) detected — possible dropper or resource-based payload"));
    }
    if embedded_sc > 0 {
        f!(Severity::Critical, "Packing/Obfuscation",
           format!("{embedded_sc} shellcode pattern(s) detected — position-independent code stubs"));
    }

    if let Some(ref pk) = pe.packer {
        let sev = match pk.confidence {
            PackerConfidence::High   => Severity::Critical,
            PackerConfidence::Medium => Severity::Warn,
            PackerConfidence::Low    => Severity::Warn,
        };
        f!(sev, "Packing/Obfuscation",
           format!("Identified packer: {} [{}] — {}", pk.name, pk.confidence.label(), pk.details));
    }

    if let Some(ov) = &pe.overlay {
        let pct = ov.size * 100 / pe.file_size.max(1);
        if pct > 20 {
            f!(Severity::Critical, "Packing/Obfuscation",
               format!("Large overlay: {} bytes ({pct}%) at 0x{:X}", ov.size, ov.offset));
        } else {
            f!(Severity::Warn, "Packing/Obfuscation",
               format!("Overlay: {} bytes at 0x{:X}", ov.size, ov.offset));
        }
    }

    if let Some(ep_sec) = pe.sections.iter().find(|s| s.is_ep) {
        if !matches!(ep_sec.name.trim(), ".text" | "CODE" | ".code") {
            f!(Severity::Warn, "Packing/Obfuscation",
               format!("Entry point in '{}', not .text", ep_sec.name));
        }
        if ep_sec.entropy > 6.8 {
            f!(Severity::Critical, "Packing/Obfuscation",
               format!("EP section '{}' has high entropy ({:.2})", ep_sec.name, ep_sec.entropy));
        }
    }

    let total_imports: usize = pe.imports.iter().map(|i| i.functions.len()).sum();
    if pe.imports.is_empty() || total_imports == 0 {
        f!(Severity::Critical, "Imports", "No imports — likely runtime API resolution");
    } else if total_imports < 5 {
        f!(Severity::Warn, "Imports", format!("Only {total_imports} imports — possible stub/loader"));
    }

    let all_fns: HashSet<&str> = pe.imports.iter().flat_map(|i| i.functions.iter().map(|s| s.as_str())).collect();

    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtCreateThreadEx","RtlCreateUserThread","QueueUserAPC"],
        "Process Injection [T1055]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["ZwUnmapViewOfSection","NtUnmapViewOfSection","SetThreadContext","GetThreadContext"],
        "Process Hollowing [T1055.012]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Warn,
        &["CryptAcquireContext","CryptEncrypt","CryptDecrypt","BCryptEncrypt","BCryptDecrypt","BCryptGenRandom"],
        "Crypto Operations [T1027]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Warn,
        &["InternetOpenA","InternetOpenW","HttpOpenRequestA","WinHttpOpen","URLDownloadToFileA","WSAStartup","connect","send","recv"],
        "Network I/O [T1071]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Warn,
        &["IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","FindWindowA","OutputDebugStringA"],
        "Anti-Debug [T1622]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Warn,
        &["RegOpenKeyExA","RegSetValueExA","RegCreateKeyExA"],
        "Registry Access [T1112]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Warn,
        &["CreateProcessA","CreateProcessW","ShellExecuteA","ShellExecuteW","WinExec"],
        "Process Creation [T1106]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["SetWindowsHookExA","SetWindowsHookExW","GetAsyncKeyState","GetKeyState","GetKeyboardState"],
        "Keylogging [T1056.001]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["OpenProcessToken","AdjustTokenPrivileges","LookupPrivilegeValueA","ImpersonateLoggedOnUser"],
        "Token Manipulation [T1134]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["MiniDumpWriteDump","SamConnect","LsaOpenPolicy","LsaQueryInformationPolicy","SamOpenDomain"],
        "Credential Dumping [T1003]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["AmsiScanBuffer","AmsiInitialize","AmsiOpenSession"],
        "AMSI Bypass [T1562.001]");
    // EtwEventWrite omitted: imported by any program emitting ETW diagnostic events (normal).
    // NtTraceControl / NtTraceEvent are low-level Nt* calls not used in legitimate user-mode code.
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["NtTraceControl","NtTraceEvent"],
        "ETW Bypass [T1562.006]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["WNetAddConnection2A","WNetAddConnection2W","NetShareEnum","NetSessionEnum"],
        "Lateral Movement [T1021]");
    // ITaskService is a COM interface name, not an importable symbol — excluded.
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["NetScheduleJobAdd","NetScheduleJobEnum"],
        "Scheduled Task [T1053.005]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Critical,
        &["InternetWriteFile","FtpPutFileA","FtpPutFileW","WinHttpWriteData"],
        "Data Exfiltration [T1041]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Warn,
        &["CreateNamedPipeA","CreateNamedPipeW","ConnectNamedPipe"],
        "Named Pipe IPC [T1071.004]");
    check_api_set(&mut flags, &all_fns, "Imports", Severity::Warn,
        &["GetSystemInfo","GetComputerNameA","GetComputerNameW","GetAdaptersInfo","GetNativeSystemInfo"],
        "System Discovery [T1082]");

    // String-based heuristics — catches evidence invisible to import-only analysis
    {
        let string_vals: Vec<&str> = pe.strings.iter().map(|s| s.value.as_str()).collect();

        // Persistence via registry Run key
        if string_vals.iter().any(|s| s.contains("CurrentVersion\\Run") || s.contains("CurrentVersion/Run")) {
            f!(Severity::Critical, "Strings", "Registry Run key path detected — likely persistence [T1547.001]");
        }

        // LSASS memory access pattern
        if string_vals.iter().any(|s| s.contains("lsass") || s.contains("LSASS")) {
            f!(Severity::Critical, "Strings", "LSASS process name in strings — possible credential dumping [T1003.001]");
        }

        // Scheduled task command
        // "at.exe" is excluded as a substring match — it matches "bloat.exe", "data.exe", etc.
        // Require schtasks or a combined /create+task signal instead.
        if string_vals.iter().any(|s| {
            let l = s.to_ascii_lowercase();
            l.contains("schtasks") || (l.contains("/create") && l.contains("task"))
        }) {
            f!(Severity::Critical, "Strings", "Scheduled task command in strings — likely persistence [T1053.005]");
        }

        // PowerShell encoded command (common stager)
        if string_vals.iter().any(|s| {
            let l = s.to_ascii_lowercase();
            l.contains("powershell") && (l.contains("-enc") || l.contains("-encodedcommand") || l.contains("-nop"))
        }) {
            f!(Severity::Critical, "Strings", "PowerShell encoded/no-profile command — likely stager [T1059.001]");
        }

        // cmd /c execution
        if string_vals.iter().any(|s| {
            let l = s.to_ascii_lowercase();
            (l.contains("cmd.exe") || l.contains("cmd /c") || l.contains("cmd.exe /c")) && l.len() > 6
        }) {
            f!(Severity::Warn, "Strings", "cmd.exe execution string — command execution [T1059.003]");
        }

        // Temp/shadow drop paths
        if string_vals.iter().any(|s| {
            let l = s.to_ascii_lowercase();
            l.contains("%temp%") || l.contains("%appdata%") || l.contains("\\temp\\") || l.contains("/tmp/")
        }) {
            f!(Severity::Warn, "Strings", "Temp/AppData path in strings — possible dropper staging [T1027]");
        }

        // Volume shadow copy deletion (ransomware tell)
        if string_vals.iter().any(|s| {
            let l = s.to_ascii_lowercase();
            l.contains("vssadmin") || l.contains("shadowcopy") || l.contains("wmic shadowcopy delete")
        }) {
            f!(Severity::Critical, "Strings", "Shadow copy deletion strings — ransomware indicator [T1490]");
        }

        // Named pipe C2 pattern
        if string_vals.iter().any(|s| s.starts_with("\\\\.\\pipe\\") || s.starts_with("\\\\\\\\")) {
            f!(Severity::Warn, "Strings", "Named pipe path in strings — possible C2 or lateral movement channel");
        }

        // AMSI/ETW patch signatures in strings (in-memory patching)
        if string_vals.iter().any(|s| {
            let l = s.to_ascii_lowercase();
            l.contains("amsi.dll") || l.contains("amsiscanbuffer")
        }) {
            f!(Severity::Critical, "Strings", "AMSI DLL/function name in strings — likely in-memory bypass [T1562.001]");
        }

        // Tor / onion C2
        if string_vals.iter().any(|s| s.contains(".onion")) {
            f!(Severity::Critical, "Strings", "Tor .onion address detected — anonymized C2 infrastructure");
        }
    }

    if !pe.checksum_ok {
        f!(Severity::Warn, "Structure",
           format!("Checksum mismatch (0x{:08X} vs 0x{:08X})", pe.stored_cs, pe.calc_cs));
    }
    if pe.sections.len() > 12 {
        f!(Severity::Info, "Structure", format!("{} sections — unusually high", pe.sections.len()));
    }
    if pe.sections.len() == 1 {
        f!(Severity::Warn, "Structure", "Single section — likely packed");
    }

    {
        let (mut has_aslr, mut has_dep, mut has_cfg, mut has_no_seh) = (false, false, false, false);
        for dc in &pe.dll_chars {
            if !has_aslr  && dc.contains("ASLR")     { has_aslr = true; }
            if !has_dep   && dc.contains("DEP")       { has_dep = true; }
            if !has_cfg   && dc.contains("GUARD_CF")  { has_cfg = true; }
            if !has_no_seh && dc.contains("NO_SEH")   { has_no_seh = true; }
        }
        if !has_aslr { f!(Severity::Warn, "Security", "ASLR not enabled"); }
        if !has_dep  { f!(Severity::Warn, "Security", "DEP not enabled"); }
        if !has_cfg  { f!(Severity::Info, "Security", "CFG not enabled"); }
        if has_no_seh { f!(Severity::Info, "Security", "SEH disabled"); }
    }

    if pe.rich_hint.is_none() {
        f!(Severity::Info, "Metadata", "No Rich header — possibly stripped");
    }

    if !pe.rich_entries.is_empty() && pe.pe_timestamp != 0 {
        let max_pid = pe.rich_entries.iter().map(|(pid, _, _)| *pid).max().unwrap_or(0);
        let rich_era = match max_pid {
            0x0104..=0x01FF => 2022u32,
            0x00F0..=0x0103 => 2019,
            0x00D8..=0x00EF => 2017,
            0x00C0..=0x00D7 => 2015,
            0x00A8..=0x00BF => 2013,
            0x0083..=0x00A7 => 2012,
            _ => 0,
        };
        if rich_era > 0 {
            let ts_year = 1970 + (pe.pe_timestamp / 31_536_000);
            let diff = ts_year.abs_diff(rich_era);
            if diff > 5 {
                f!(Severity::Warn, "Metadata",
                   format!("Rich header suggests ~{rich_era} compiler, PE timestamp ~{ts_year} — possible tampering"));
            }
        }
    }

    if let Some(ref exp) = pe.exports {
        let fwd_count = exp.exports.iter().filter(|e| e.forwarded.is_some()).count();
        let total = exp.exports.len();
        if fwd_count > 20 && total > 0 && fwd_count * 100 / total > 50 {
            f!(Severity::Critical, "Exports",
               format!("{fwd_count}/{total} exports are forwarded — possible proxy/sideloading DLL"));
        } else if fwd_count > 5 {
            f!(Severity::Warn, "Exports",
               format!("{fwd_count} forwarded exports detected"));
        }
    }

    if pe.certificate.is_none() {
        f!(Severity::Info, "Security", "No Authenticode signature");
    }

    flags.sort_by(|a, b| b.severity.cmp(&a.severity));
    flags
}

fn check_api_set(flags: &mut Vec<HeuristicFlag>, all_fns: &HashSet<&str>, cat: &'static str, sev: Severity, apis: &[&str], label: &str) {
    let matched: Vec<&str> = apis.iter().copied().filter(|a| all_fns.contains(a)).collect();
    if !matched.is_empty() {
        flags.push(HeuristicFlag {
            severity: sev, category: cat,
            message: format!("{label}: {}", matched.join(", ")),
        });
    }
}
