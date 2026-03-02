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
];

pub struct MatchedCapability {
    pub name:        &'static str,
    pub description: &'static str,
    pub mitre:       &'static str,
    pub threat:      u8,
    pub matched:     Vec<String>,
}

pub fn detect_capabilities(pe: &PeInfo) -> Vec<MatchedCapability> {
    let all_fns: HashSet<&str> = pe.imports.iter()
        .flat_map(|i| i.functions.iter().map(|s| s.as_str())).collect();
    let mut caps = Vec::new();
    for def in CAPABILITIES {
        let matched: Vec<String> = def.apis.iter()
            .filter(|a| all_fns.contains(*a))
            .map(|a| a.to_string()).collect();
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

    if !pe.dll_chars.iter().any(|f| f.contains("ASLR")) {
        f!(Severity::Warn, "Security", "ASLR not enabled");
    }
    if !pe.dll_chars.iter().any(|f| f.contains("DEP")) {
        f!(Severity::Warn, "Security", "DEP not enabled");
    }
    if !pe.dll_chars.iter().any(|f| f.contains("GUARD_CF")) {
        f!(Severity::Info, "Security", "CFG not enabled");
    }
    if pe.dll_chars.iter().any(|f| f.contains("NO_SEH")) {
        f!(Severity::Info, "Security", "SEH disabled");
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
