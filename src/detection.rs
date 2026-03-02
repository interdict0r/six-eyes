use std::collections::HashSet;
use crate::model::{PeInfo, ExtractedString, GoInfo, RustInfo};
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

    {
        let has_go_strings = pe.strings.iter().any(|s|
            s.value.contains("runtime.main")
            || s.value.contains("go.buildid")
            || s.value.contains("runtime/internal/")
            || s.value.contains("runtime.goexit")
        );
        let has_pclntab = validate_pclntab(buffer);
        if has_go_strings || has_pclntab {
            return Some("Go".into());
        }
    }

    if pe.strings.iter().any(|s|
        s.value.contains("/rustc/") || s.value.contains(".cargo/registry") || s.value.contains("core::panicking")
    ) {
        return Some("Rust".into());
    }

    if sec_names.contains("CODE") && sec_names.contains("DATA") && sec_names.contains("BSS") {
        return Some("Delphi/Borland".into());
    }

    if pe.strings.iter().any(|s| s.value.contains("_pyi_main_co") || s.value.contains("PYZ-00.pyz")) {
        return Some("Python (PyInstaller)".into());
    }

    if pe.strings.iter().any(|s| s.value.contains("AutoIt") || s.value.contains("AU3!")) {
        return Some("AutoIt".into());
    }

    if pe.strings.iter().any(|s| s.value.contains("nimMain") || s.value.contains("nim_program_result")) {
        return Some("Nim".into());
    }

    if has_dll(pe, "msvcrt.dll")
        && (pe.strings.iter().any(|s| s.value.contains("__mingw")) || sec_names.contains(".CRT")) {
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
