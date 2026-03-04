use std::collections::HashSet;
use crate::model::{PeInfo, ExtractedString, GoInfo, RustInfo, PackerInfo, PackerConfidence, SectionInfo, EmbeddedArtifact, ArtifactKind};
use crate::hashing::md5_hex;

pub struct RichHeaderInfo {
    pub hint:    String,
    pub hash:    String,
    pub entries: Vec<(u16, u16, u32)>,
}

pub fn parse_rich_header(data: &[u8]) -> Option<RichHeaderInfo> {
    let pos = data.windows(4).position(|w| w == b"Rich")?;
    if pos + 8 > data.len() { return None; }
    let base = data.as_ptr();
    let key = unsafe { std::ptr::read_unaligned(base.add(pos + 4) as *const u32) };
    let key = u32::from_le(key);
    let dans_enc = key ^ 0x536E6144;
    let start = data[..pos].windows(4)
        .rposition(|w| {
            let val = unsafe { std::ptr::read_unaligned(w.as_ptr() as *const u32) };
            u32::from_le(val) == dans_enc
        })?;
    let mut entries: Vec<(u16, u16, u32)> = Vec::new();
    let mut i = start + 16;
    while i + 8 <= pos {
        let dw1 = unsafe { u32::from_le(std::ptr::read_unaligned(base.add(i) as *const u32)) } ^ key;
        let dw2 = unsafe { u32::from_le(std::ptr::read_unaligned(base.add(i + 4) as *const u32)) } ^ key;
        entries.push(((dw1 >> 16) as u16, (dw1 & 0xFFFF) as u16, dw2));
        i += 8;
    }
    if entries.is_empty() { return None; }

    let decoded_len = pos - start;
    let mut decoded = Vec::with_capacity(decoded_len);
    let key_bytes = key.to_le_bytes();
    for j in 0..decoded_len {
        decoded.push(data[start + j] ^ key_bytes[j % 4]);
    }
    let hash = md5_hex(&decoded);

    let hint = entries.iter().find_map(|(pid, bid, _)| match pid {
        0x0104..=0x010F => Some(format!("MSVC/VS2022 (build {bid})")),
        0x00F0..=0x0103 => Some(format!("MSVC/VS2019 (build {bid})")),
        0x00D8..=0x00EF => Some(format!("MSVC/VS2017 (build {bid})")),
        0x00C0..=0x00D7 => Some(format!("MSVC/VS2015 (build {bid})")),
        0x00A8..=0x00BF => Some(format!("MSVC/VS2013 (build {bid})")),
        _ => None,
    });
    let hint = hint.unwrap_or_else(|| format!("{} entries (key 0x{key:08X})", entries.len()));

    Some(RichHeaderInfo { hint, hash, entries })
}

pub fn dll_char_tooltip(flag: &str) -> &'static str {
    match flag {
        _ if flag.contains("HIGH_ENTROPY_VA") => "Supports 64-bit ASLR with high-entropy address space, making memory layout harder to predict",
        _ if flag.contains("ASLR")            => "Address Space Layout Randomization — randomizes base address on each load to prevent exploits",
        _ if flag.contains("FORCE_INTEGRITY") => "Enforces code-signing integrity checks at load time",
        _ if flag.contains("DEP")             => "Data Execution Prevention — marks data pages as non-executable to block code injection",
        _ if flag.contains("NO_ISOLATION")    => "Disables manifest-based side-by-side assembly isolation",
        _ if flag.contains("NO_SEH")          => "Does not use Structured Exception Handling — may indicate .NET or custom unwinding",
        _ if flag.contains("NO_BIND")         => "Image cannot be bound, forcing the loader to resolve imports every time",
        _ if flag.contains("APPCONTAINER")    => "Must run inside a Windows AppContainer sandbox with restricted privileges",
        _ if flag.contains("WDM_DRIVER")      => "Kernel-mode WDM (Windows Driver Model) driver",
        _ if flag.contains("GUARD_CF")        => "Control Flow Guard — validates indirect call targets at runtime to prevent hijacking",
        _ if flag.contains("TERMINAL_SERVER") => "Application is aware of and compatible with Terminal Server / Remote Desktop sessions",
        _ => "",
    }
}

pub fn detect_language(pe: &PeInfo, buffer: &[u8]) -> Option<String> {
    let all_fns: HashSet<&str> = pe.imports.iter()
        .flat_map(|i| i.functions.iter().map(|s| s.as_str())).collect();
    let sec_names: HashSet<&str> = pe.sections.iter().map(|s| s.name.as_str()).collect();

    #[inline]
    fn has_dll(pe: &PeInfo, name: &str) -> bool {
        pe.imports.iter().any(|i| i.dll.eq_ignore_ascii_case(name))
    }

    if has_dll(pe, "mscoree.dll")
        && (all_fns.contains("_CorExeMain") || all_fns.contains("_CorDllMain")) {
        return Some(".NET (CLR)".into());
    }

    let (mut has_go, mut has_rust, mut has_python, mut has_autoit, mut has_nim, mut has_mingw) =
        (false, false, false, false, false, false);

    for s in &pe.strings {
        let v = &s.value;
        if !has_go && (v.contains("runtime.main") || v.contains("go.buildid")
            || v.contains("runtime/internal/") || v.contains("runtime.goexit")) { has_go = true; }
        if !has_rust && (v.contains("/rustc/") || v.contains(".cargo/registry")
            || v.contains("core::panicking")) { has_rust = true; }
        if !has_python && (v.contains("_pyi_main_co") || v.contains("PYZ-00.pyz")) { has_python = true; }
        if !has_autoit && (v.contains("AutoIt") || v.contains("AU3!")) { has_autoit = true; }
        if !has_nim && (v.contains("nimMain") || v.contains("nim_program_result")) { has_nim = true; }
        if !has_mingw && v.contains("__mingw") { has_mingw = true; }
        if has_go && has_rust && has_python && has_autoit && has_nim && has_mingw { break; }
    }

    if has_go || validate_pclntab(buffer) {
        return Some("Go".into());
    }

    if has_rust {
        return Some("Rust".into());
    }

    if sec_names.contains("CODE") && sec_names.contains("DATA") && sec_names.contains("BSS") {
        return Some("Delphi/Borland".into());
    }

    if has_python {
        return Some("Python (PyInstaller)".into());
    }

    if has_autoit {
        return Some("AutoIt".into());
    }

    if has_nim {
        return Some("Nim".into());
    }

    if has_dll(pe, "msvcrt.dll") && (has_mingw || sec_names.contains(".CRT")) {
        return Some("C/C++ (GCC/MinGW)".into());
    }

    if let Some(ref hint) = pe.rich_hint {
        if hint.contains("MSVC") {
            return Some(format!("C/C++ ({hint})"));
        }
    }

    None
}

fn validate_pclntab(buffer: &[u8]) -> bool {
    const MAGICS: [u32; 4] = [
        u32::from_le_bytes([0xFB, 0xFF, 0xFF, 0xFF]),
        u32::from_le_bytes([0xFA, 0xFF, 0xFF, 0xFF]),
        u32::from_le_bytes([0xF0, 0xFF, 0xFF, 0xFF]),
        u32::from_le_bytes([0xF1, 0xFF, 0xFF, 0xFF]),
    ];
    if buffer.len() < 8 { return false; }
    let base = buffer.as_ptr();
    let end = buffer.len() - 7;
    for &magic in &MAGICS {
        let mut pos = 0;
        while pos < end {
            // SAFETY: pos + 7 < buffer.len(), guaranteed by end bound
            let word = unsafe { std::ptr::read_unaligned(base.add(pos) as *const u32) };
            if word == magic {
                let ptr = unsafe { base.add(pos) };
                let pad_ok   = unsafe { *ptr.add(4) == 0 && *ptr.add(5) == 0 };
                let quantum  = unsafe { *ptr.add(6) };
                let ptr_size = unsafe { *ptr.add(7) };
                if pad_ok && matches!(quantum, 1 | 2 | 4) && matches!(ptr_size, 4 | 8) {
                    return true;
                }
            }
            pos += 1;
        }
    }
    false
}

pub fn parse_go_pclntab(buffer: &[u8]) -> Option<GoInfo> {
    let magic_versions: &[(u32, &str)] = &[
        (u32::from_le_bytes([0xF1, 0xFF, 0xFF, 0xFF]), "Go 1.20+"),
        (u32::from_le_bytes([0xF0, 0xFF, 0xFF, 0xFF]), "Go 1.18-1.19"),
        (u32::from_le_bytes([0xFA, 0xFF, 0xFF, 0xFF]), "Go 1.16-1.17"),
        (u32::from_le_bytes([0xFB, 0xFF, 0xFF, 0xFF]), "Go 1.2-1.15"),
    ];

    let buf_len = buffer.len();
    if buf_len < 8 { return None; }
    let base = buffer.as_ptr();

    for &(magic, version_hint) in magic_versions {
        let mut pos = 0usize;
        let search_end = buf_len - 7;
        while pos < search_end {
            let word = unsafe { std::ptr::read_unaligned(base.add(pos) as *const u32) };
            if word != magic { pos += 1; continue; }

            let hdr = unsafe { base.add(pos) };
            if unsafe { *hdr.add(4) != 0 || *hdr.add(5) != 0 } { pos += 4; continue; }
            let quantum  = unsafe { *hdr.add(6) };
            let ptr_size = unsafe { *hdr.add(7) };
            if !matches!(quantum, 1 | 2 | 4) || !matches!(ptr_size, 4 | 8) { pos += 4; continue; }

            let mut functions = Vec::new();
            let mut source_files = Vec::new();
            let mut seen = HashSet::new();

            let mut i = pos;
            while i < buf_len {
                let b = unsafe { *base.add(i) };
                if b == 0 { i += 1; continue; }
                let str_start = i;
                while i < buf_len {
                    let c = unsafe { *base.add(i) };
                    if c < 0x20 || c > 0x7E { break; }
                    i += 1;
                }
                let slen = i - str_start;
                if slen >= 4 {
                    let slice = unsafe { std::slice::from_raw_parts(base.add(str_start), slen) };
                    if let Ok(s) = std::str::from_utf8(slice) {
                        if s.contains('.') && !s.contains(' ') && s.len() < 200 {
                            if (s.contains('/') || s.starts_with("main.") || s.starts_with("runtime."))
                                && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'/' | b'_' | b'-' | b'*' | b'(' | b')'))
                            {
                                if seen.insert(s.to_string()) {
                                    if s.ends_with(".go") || s.ends_with(".s") {
                                        source_files.push(s.to_string());
                                    } else {
                                        functions.push(s.to_string());
                                    }
                                }
                                if functions.len() + source_files.len() > 5000 { break; }
                            }
                        }
                    }
                }
                i += 1;
            }

            if !functions.is_empty() || !source_files.is_empty() {
                return Some(GoInfo { version_hint: version_hint.into(), functions, source_files });
            }
            return Some(GoInfo { version_hint: version_hint.into(), functions: vec![], source_files: vec![] });
        }
    }
    None
}

pub fn extract_rust_info(strings: &[ExtractedString]) -> Option<RustInfo> {
    let mut compiler_version = None;
    let mut crates = Vec::new();
    let mut seen_crates = HashSet::new();
    let mut is_rust = false;

    for s in strings {
        if let Some(idx) = s.value.find("/rustc/") {
            is_rust = true;
            let hash_start = idx + 7;
            let rest = &s.value[hash_start..];
            let hash_end = rest.find('/').unwrap_or(rest.len()).min(40);
            if compiler_version.is_none() && hash_end >= 7 {
                compiler_version = Some(rest[..hash_end].to_string());
            }
        }
        if let Some(idx) = s.value.find(".cargo/registry/src/") {
            is_rust = true;
            let after = &s.value[idx + 20..];
            if let Some(slash) = after.find('/') {
                let crate_path = &after[slash+1..];
                if let Some(end) = crate_path.find('/') {
                    let crate_ver = &crate_path[..end];
                    if !crate_ver.is_empty() && seen_crates.insert(crate_ver.to_string()) {
                        crates.push(crate_ver.to_string());
                    }
                }
            }
        }
        if s.value.contains("core::panicking") { is_rust = true; }
    }

    if is_rust {
        crates.sort();
        Some(RustInfo { compiler_version, crates })
    } else {
        None
    }
}


struct EpSignature {
    name:   &'static str,
    bytes:  &'static [u8],
    mask:   &'static [u8],  // 0xFF = must match, 0x00 = wildcard
    detail: &'static str,
}

static EP_SIGNATURES: &[EpSignature] = &[
    // UPX — standard x86 stub: PUSHAD; MOV ESI, <addr>; LEA EDI, [ESI+<off>]
    EpSignature {
        name: "UPX",
        bytes:  &[0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE, 0x00, 0x00, 0x00, 0x00],
        mask:   &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
        detail: "UPX entry stub (PUSHAD; MOV ESI; LEA EDI)",
    },
    // UPX — x64 stub: PUSH RBX; PUSH RSI; PUSH RDI; LEA RSI, [RIP+<off>]; LEA RDI, [RSI+<off>]
    EpSignature {
        name: "UPX",
        bytes: &[0x53, 0x56, 0x57, 0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x3E],
        mask:  &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF],
        detail: "UPX x64 entry stub (PUSH RBX/RSI/RDI; LEA RSI,[RIP]; LEA RDI,[RSI])",
    },
    // ASPack: PUSHAD; CALL $+5; POP EBP; SUB EBP, <off>
    EpSignature {
        name: "ASPack",
        bytes: &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED],
        mask:  &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        detail: "ASPack stub (PUSHAD; CALL $+5; POP EBP)",
    },
    // PECompact: MOV EAX, <addr>; PUSH EAX; PUSH DWORD FS:[...]
    EpSignature {
        name: "PECompact",
        bytes: &[0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35],
        mask:  &[0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        detail: "PECompact SEH setup",
    },
    // MPRESS: PUSHAD; CALL <rel>; POP EAX; ADD EAX, <off>
    EpSignature {
        name: "MPRESS",
        bytes: &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05],
        mask:  &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
        detail: "MPRESS entry stub",
    },
    // Petite: MOV EAX, <addr>; PUSHFW; PUSHAD; PUSH EAX
    EpSignature {
        name: "Petite",
        bytes: &[0xB8, 0x00, 0x00, 0x00, 0x00, 0x66, 0x9C, 0x60, 0x50],
        mask:  &[0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        detail: "Petite packer stub",
    },
    // FSG: MOV ESI, <addr>; LODSW; XCHG EAX, EBX; LODSW
    EpSignature {
        name: "FSG",
        bytes: &[0xBE, 0x00, 0x00, 0x00, 0x00, 0xAD, 0x93, 0xAD],
        mask:  &[0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF],
        detail: "FSG packer stub",
    },
    // MEW: MOV ESI, <addr>; MOV EDI, ESI; XOR EAX, EAX; MOV ECX, <n>
    EpSignature {
        name: "MEW",
        bytes: &[0xBE, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xFE, 0x33, 0xC0, 0xB9],
        mask:  &[0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        detail: "MEW packer stub",
    },
    // Themida/WinLicense: MOV EAX, <addr>; PUSHAD; OR EAX, EAX; JZ <off>
    EpSignature {
        name: "Themida/WinLicense",
        bytes: &[0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x0B, 0xC0, 0x74, 0x68],
        mask:  &[0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        detail: "Themida VM entry stub",
    },
    // Obsidium: JMP +2; <junk>; CALL
    EpSignature {
        name: "Obsidium",
        bytes: &[0xEB, 0x02, 0x00, 0x00, 0xE8],
        mask:  &[0xFF, 0xFF, 0x00, 0x00, 0xFF],
        detail: "Obsidium junk-jump entry",
    },
];

struct SectionPattern {
    name:   &'static str,
    names:  &'static [&'static str],
    detail: &'static str,
}

static SECTION_PATTERNS: &[SectionPattern] = &[
    SectionPattern { name: "UPX",          names: &["UPX0", "UPX1", "UPX2"],       detail: "UPX section names" },
    SectionPattern { name: "ASPack",       names: &[".aspack", ".adata"],            detail: "ASPack section names" },
    SectionPattern { name: "PECompact",    names: &["pec1", "pec2", "PEC2"],         detail: "PECompact section names" },
    SectionPattern { name: "Petite",       names: &[".petite"],                      detail: "Petite section name" },
    SectionPattern { name: "MPRESS",       names: &[".MPRESS1", ".MPRESS2"],         detail: "MPRESS section names" },
    SectionPattern { name: "Themida/WinLicense", names: &[".themida", ".winlice"],   detail: "Themida section names" },
    SectionPattern { name: "VMProtect",    names: &[".vmp0", ".vmp1", ".vmp2"],      detail: "VMProtect section names" },
    SectionPattern { name: "Enigma",       names: &[".enigma1", ".enigma2"],         detail: "Enigma Protector section names" },
    SectionPattern { name: "Obsidium",     names: &[".obsidiu"],                     detail: "Obsidium section name" },
    SectionPattern { name: "NSPack",       names: &[".nsp0", ".nsp1", ".nsp2"],      detail: "NSPack section names" },
    SectionPattern { name: "RLPack",       names: &[".RLPack"],                        detail: "RLPack section name" },
];

fn match_ep_signature(ep_bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    for sig in EP_SIGNATURES {
        let len = sig.bytes.len();
        if ep_bytes.len() < len { continue; }
        let matched = (0..len).all(|i| sig.mask[i] == 0x00 || ep_bytes[i] == sig.bytes[i]);
        if matched {
            return Some((sig.name, sig.detail));
        }
    }
    None
}

fn match_section_names(sections: &[SectionInfo]) -> Option<(&'static str, &'static str)> {
    let sec_names: Vec<&str> = sections.iter().map(|s| s.name.as_str()).collect();
    for pat in SECTION_PATTERNS {
        if pat.names.iter().any(|n| sec_names.iter().any(|s| s.eq_ignore_ascii_case(n))) {
            return Some((pat.name, pat.detail));
        }
    }
    None
}


pub fn detect_packer(
    sections: &[SectionInfo],
    buffer: &[u8],
    ep_file_offset: Option<usize>,
    has_overlay: bool,
    total_imports: usize,
) -> Option<PackerInfo> {
    let ep_bytes = ep_file_offset
        .filter(|&off| off + 16 <= buffer.len())
        .map(|off| &buffer[off..off + 16]);

    let ep_match   = ep_bytes.and_then(match_ep_signature);
    let sec_match  = match_section_names(sections);

    if let (Some((ep_name, ep_detail)), Some((sec_name, sec_detail))) = (ep_match, sec_match) {
        if ep_name == sec_name {
            return Some(PackerInfo {
                name: ep_name,
                confidence: PackerConfidence::High,
                details: format!("{ep_detail}; {sec_detail}"),
            });
        }

        return Some(PackerInfo {
            name: sec_name,
            confidence: PackerConfidence::High,
            details: format!("{sec_detail} (EP also matches {ep_name})"),
        });
    }

    if let Some((name, detail)) = sec_match {
        return Some(PackerInfo {
            name,
            confidence: PackerConfidence::High,
            details: detail.to_string(),
        });
    }

    if let Some((name, detail)) = ep_match {
        return Some(PackerInfo {
            name,
            confidence: PackerConfidence::Medium,
            details: detail.to_string(),
        });
    }

    let ep_section = sections.iter().find(|s| s.is_ep);

    // High-entropy EP section + very few imports + overlay → likely packed (unknown packer)
    if let Some(ep_sec) = ep_section {
        if ep_sec.entropy > 7.0 && total_imports < 5 && has_overlay {
            return Some(PackerInfo {
                name: "Unknown Packer",
                confidence: PackerConfidence::Low,
                details: format!(
                    "EP section '{}' entropy {:.2}, {} imports, overlay present",
                    ep_sec.name, ep_sec.entropy, total_imports,
                ),
            });
        }
        // RWX EP section with high entropy
        if ep_sec.entropy > 7.0
            && ep_sec.characteristics.contains(&"WRITE")
            && ep_sec.characteristics.contains(&"EXECUTE")
        {
            return Some(PackerInfo {
                name: "Unknown Packer",
                confidence: PackerConfidence::Low,
                details: format!(
                    "EP section '{}' is RWX with entropy {:.2}",
                    ep_sec.name, ep_sec.entropy,
                ),
            });
        }
    }

    None
}


pub fn scan_embedded_artifacts(buffer: &[u8], sections: &[SectionInfo]) -> Vec<EmbeddedArtifact> {
    let mut results = Vec::new();
    let len = buffer.len();
    if len < 64 { return results; }

    let base = buffer.as_ptr();

    let mut pos = 4usize;
    while pos + 64 <= len && results.len() < 32 {
        // Quick check for 'MZ' (0x5A4D LE)
        let mz = unsafe { std::ptr::read_unaligned(base.add(pos) as *const u16) };
        if mz == 0x5A4D {
            // Validate: e_lfanew must point to a PE\0\0 signature within bounds
            if pos + 0x3C + 4 <= len {
                let e_lfanew = unsafe {
                    u32::from_le(std::ptr::read_unaligned(base.add(pos + 0x3C) as *const u32))
                } as usize;
                let pe_sig_off = pos + e_lfanew;
                if e_lfanew >= 0x40 && e_lfanew < 0x1000 && pe_sig_off + 4 <= len {
                    let pe_sig = unsafe {
                        u32::from_le(std::ptr::read_unaligned(base.add(pe_sig_off) as *const u32))
                    };
                    if pe_sig == 0x0000_4550 { // "PE\0\0"
                        let section_name = find_section_for_offset(sections, pos as u32);
                        let est_size = estimate_pe_size(buffer, pos);
                        results.push(EmbeddedArtifact {
                            kind: ArtifactKind::Pe,
                            offset: pos as u32,
                            size: est_size,
                            detail: format!(
                                "MZ+PE at 0x{pos:X} (~{:.1} KB) in {section_name}",
                                est_size as f64 / 1024.0,
                            ),
                        });
                    }
                }
            }
        }
        pos += 4;
    }

    for sec in sections {
        if !sec.characteristics.contains(&"EXECUTE") { continue; }
        let sec_start = sec.raw_offset as usize;
        let sec_end = (sec_start + sec.raw_size as usize).min(len);
        if sec_start >= sec_end || sec_end - sec_start < 16 { continue; }

        // Skip .text — GetPC / NOP patterns are common in compiler-generated code.
        let is_main_code = matches!(sec.name.trim(), ".text" | "CODE" | ".code");

        let mut i = sec_start;
        while i + 16 <= sec_end && results.len() < 32 {
            let b = unsafe { *base.add(i) };

            if b == 0x90 {
                let start = i;
                while i < sec_end && unsafe { *base.add(i) } == 0x90 { i += 1; }
                let run = i - start;
                if run >= 32 {
                    results.push(EmbeddedArtifact {
                        kind: ArtifactKind::Shellcode,
                        offset: start as u32,
                        size: run as u32,
                        detail: format!("{run}-byte NOP sled in {}", sec.name),
                    });
                }
                continue;
            }

            // fnstenv GetPC: D9 74 24 F4
            if i + 4 <= sec_end && b == 0xD9 {
                let b1 = unsafe { *base.add(i + 1) };
                let b2 = unsafe { *base.add(i + 2) };
                let b3 = unsafe { *base.add(i + 3) };
                if b1 == 0x74 && b2 == 0x24 && b3 == 0xF4 {
                    results.push(EmbeddedArtifact {
                        kind: ArtifactKind::Shellcode,
                        offset: i as u32,
                        size: 4,
                        detail: format!("fnstenv GetPC stub at 0x{i:X} in {}", sec.name),
                    });
                    i += 4;
                    continue;
                }
            }

            if !is_main_code && i + 6 <= sec_end && b == 0xE8 {
                let call_rel = unsafe {
                    std::ptr::read_unaligned(base.add(i + 1) as *const u32)
                };
                if call_rel == 0 {
                    let pop = unsafe { *base.add(i + 5) };
                    let prev = if i > sec_start { unsafe { *base.add(i - 1) } } else { 0 };
                    if (0x58..=0x5F).contains(&pop) && prev != 0x60 {
                        results.push(EmbeddedArtifact {
                            kind: ArtifactKind::Shellcode,
                            offset: i as u32,
                            size: 6,
                            detail: format!("CALL $+5; POP GetPC at 0x{i:X} in {}", sec.name),
                        });
                        i += 6;
                        continue;
                    }
                }
            }

            i += 1;
        }
    }

    results
}

fn estimate_pe_size(buffer: &[u8], mz_offset: usize) -> u32 {
    let remaining = (buffer.len() - mz_offset) as u32;
    if mz_offset + 0x3C + 4 > buffer.len() { return 0; }
    let base = buffer.as_ptr();
    let e_lfanew = unsafe {
        u32::from_le(std::ptr::read_unaligned(base.add(mz_offset + 0x3C) as *const u32))
    } as usize;
    let pe_off = mz_offset + e_lfanew;
    if pe_off + 0x18 > buffer.len() { return 0; }
    let num_sections = unsafe {
        u16::from_le(std::ptr::read_unaligned(base.add(pe_off + 6) as *const u16))
    } as usize;
    let opt_hdr_size = unsafe {
        u16::from_le(std::ptr::read_unaligned(base.add(pe_off + 0x14) as *const u16))
    } as usize;
    let first_sec = pe_off + 0x18 + opt_hdr_size;
    let mut max_end: u32 = 0;
    for i in 0..num_sections.min(96) {
        let sh = first_sec + i * 40;
        if sh + 40 > buffer.len() { break; }
        let raw_offset = unsafe {
            u32::from_le(std::ptr::read_unaligned(base.add(sh + 20) as *const u32))
        };
        let raw_size = unsafe {
            u32::from_le(std::ptr::read_unaligned(base.add(sh + 16) as *const u32))
        };
        let end = raw_offset.saturating_add(raw_size);
        if end > max_end { max_end = end; }
    }
    if max_end == 0 { remaining } else { max_end.min(remaining) }
}

fn find_section_for_offset(sections: &[SectionInfo], file_offset: u32) -> &str {
    sections.iter()
        .find(|s| file_offset >= s.raw_offset
            && s.raw_offset.checked_add(s.raw_size).is_some_and(|end| file_offset < end))
        .map(|s| s.name.as_str())
        .unwrap_or("overlay")
}
