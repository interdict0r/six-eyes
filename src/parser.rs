use std::collections::HashSet;
use exe::pe::*;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, Instruction};
use crate::model::*;
use crate::hashing::*;
use crate::detection::*;

pub fn parse_pe(path: &str) -> PeInfo {
    let mut info = PeInfo { path: path.to_string(), ..Default::default() };

    let buffer = match std::fs::read(path) {
        Ok(b)  => b,
        Err(e) => { info.error = Some(format!("Failed to read file: {e}")); return info; }
    };

    info.file_size = buffer.len() as u32;
    info.md5       = md5_hex(&buffer);
    info.sha256    = sha256_hex(&buffer);

    let pe = VecPE::from_disk_data(&buffer);

    let is_64;
    if let Ok(nt) = pe.get_nt_headers_64() {
        is_64 = true;
        info.pe_timestamp = nt.file_header.time_date_stamp;
        let oh = &nt.optional_header;
        info.entry_point = oh.address_of_entry_point.0;
        info.arch        = "x64".into();
        info.stored_cs   = oh.checksum;
        info.image_base  = oh.image_base;
        info.linker_ver  = format!("{}.{}", oh.major_linker_version, oh.minor_linker_version);
        info.os_ver      = format!("{}.{}", oh.major_operating_system_version, oh.minor_operating_system_version);
        info.subsystem   = subsystem_name(oh.subsystem);
        info.dll_chars   = decode_dll_characteristics(oh.dll_characteristics.bits());
    } else if let Ok(nt) = pe.get_nt_headers_32() {
        is_64 = false;
        info.pe_timestamp = nt.file_header.time_date_stamp;
        let oh = &nt.optional_header;
        info.entry_point = oh.address_of_entry_point.0;
        info.arch        = "x86".into();
        info.stored_cs   = oh.checksum;
        info.image_base  = oh.image_base as u64;
        info.linker_ver  = format!("{}.{}", oh.major_linker_version, oh.minor_linker_version);
        info.os_ver      = format!("{}.{}", oh.major_operating_system_version, oh.minor_operating_system_version);
        info.subsystem   = subsystem_name(oh.subsystem);
        info.dll_chars   = decode_dll_characteristics(oh.dll_characteristics.bits());
    } else {
        info.error = Some("Not a valid PE file".into());
        return info;
    };

    info.calc_cs    = calculate_checksum(&buffer);
    info.checksum_ok = info.stored_cs == 0 || info.stored_cs == info.calc_cs;

    if let Some(rich) = parse_rich_header(&buffer) {
        info.rich_hint    = Some(rich.hint);
        info.rich_hash    = Some(rich.hash);
        info.rich_entries = rich.entries;
    }

    let mut last_end: u32 = 0;
    if let Ok(sections) = pe.get_section_table() {
        for section in sections {
            let raw_name: [u8; 8] = std::array::from_fn(|i| u8::from(section.name[i]));
            let name = std::str::from_utf8(&raw_name)
                .unwrap_or("????????").trim_end_matches('\0').to_string();

            let data  = section.read(&pe).unwrap_or(&[]);
            let ent   = shannon_entropy_bytes(data);
            let start = section.virtual_address.0;
            let end   = start + section.virtual_size;
            let is_ep = info.entry_point >= start && info.entry_point < end;

            let raw_end = section.pointer_to_raw_data.0 + section.size_of_raw_data;
            if raw_end > last_end { last_end = raw_end; }

            info.strings.extend(extract_strings(data, section.pointer_to_raw_data.0 as usize, &name));
            info.sections.push(SectionInfo {
                name, virtual_addr: start, virtual_size: section.virtual_size,
                raw_size: section.size_of_raw_data,
                raw_offset: section.pointer_to_raw_data.0,
                entropy: ent, is_ep,
                characteristics: decode_section_characteristics(section.characteristics.bits()),
            });
        }
    }

    if (last_end as usize) < buffer.len() {
        let size = (buffer.len() - last_end as usize) as u32;
        info.strings.extend(extract_strings(&buffer[last_end as usize..], last_end as usize, "overlay"));
        info.overlay = Some(OverlayInfo { offset: last_end, size });
    }

    info.imports = parse_imports(&pe, &buffer, is_64);
    info.imphash = compute_imphash(&info.imports);

    info.exports = parse_exports(&pe, &buffer);

    info.block_entropy = compute_block_entropy(&buffer, 1024);

    info.resources = parse_resources(&pe, &buffer);

    info.certificate = parse_certificate(&pe, &buffer);

    info.detected_language = detect_language(&info, &buffer);
    if info.detected_language.as_deref() == Some("Go") {
        info.go_info = parse_go_pclntab(&buffer);
    }
    if info.detected_language.as_deref() == Some("Rust") {
        info.rust_info = extract_rust_info(&info.strings);
    }

    info.iat_map = build_iat_map(&pe, &buffer, is_64, info.image_base);

    let (dlines, dmeta) = compute_disasm_lines(&info, &buffer);
    info.disasm_lines = dlines;
    info.disasm_meta  = Some(dmeta);

    info.buffer = buffer;

    info
}

#[inline(always)]
unsafe fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    unsafe {
        u32::from_le(std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const u32))
    }
}

#[inline(always)]
unsafe fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    unsafe {
        u64::from_le(std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const u64))
    }
}

#[inline(always)]
unsafe fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    unsafe {
        u16::from_le(std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const u16))
    }
}

fn compute_imphash(imports: &[ImportInfo]) -> String {
    if imports.is_empty() { return String::new(); }
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut first = true;
    for imp in imports {
        let dll_bytes = imp.dll.as_bytes();
        let dll_end = if dll_bytes.len() > 4 {
            let dot_pos = dll_bytes.len() - 4;
            if dll_bytes[dot_pos] == b'.' { dot_pos } else { dll_bytes.len() }
        } else {
            dll_bytes.len()
        };
        for f in &imp.functions {
            if !first { buf.push(b','); }
            for i in 0..dll_end {
                buf.push(unsafe { *dll_bytes.get_unchecked(i) }.to_ascii_lowercase());
            }
            buf.push(b'.');
            for &b in f.as_bytes() {
                buf.push(b.to_ascii_lowercase());
            }
            first = false;
        }
    }
    if buf.is_empty() { return String::new(); }
    md5_hex(&buf)
}

fn parse_exports(pe: &VecPE, buffer: &[u8]) -> Option<ExportInfo> {
    let dd = pe.get_data_directory(exe::ImageDirectoryEntry::Export).ok()?;
    let export_rva = dd.virtual_address.0;
    let export_size = dd.size;
    if export_rva == 0 || export_size == 0 { return None; }

    let base_off = rva_to_offset(pe, export_rva)?;
    if base_off + 40 > buffer.len() { return None; }

    let name_rva     = unsafe { read_u32_le(buffer, base_off + 12) };
    let ordinal_base = unsafe { read_u32_le(buffer, base_off + 16) };
    let num_funcs    = unsafe { read_u32_le(buffer, base_off + 20) };
    let num_names    = unsafe { read_u32_le(buffer, base_off + 24) };
    let func_rva_tbl = unsafe { read_u32_le(buffer, base_off + 28) };
    let name_rva_tbl = unsafe { read_u32_le(buffer, base_off + 32) };
    let ord_tbl      = unsafe { read_u32_le(buffer, base_off + 36) };

    let dll_name = rva_to_offset(pe, name_rva)
        .map(|o| read_cstring(buffer, o))
        .unwrap_or_default();

    let func_off = rva_to_offset(pe, func_rva_tbl)?;
    let name_off = rva_to_offset(pe, name_rva_tbl);
    let ord_off  = rva_to_offset(pe, ord_tbl);

    let count = (num_funcs as usize).min(8192);
    let mut name_map: Vec<Option<String>> = vec![None; count];
    if let (Some(no), Some(oo)) = (name_off, ord_off) {
        let ncount = (num_names as usize).min(8192);
        for i in 0..ncount {
            if no + i * 4 + 4 > buffer.len() || oo + i * 2 + 2 > buffer.len() { break; }
            let n_rva = unsafe { read_u32_le(buffer, no + i * 4) };
            let ord   = unsafe { read_u16_le(buffer, oo + i * 2) } as usize;
            if ord < count {
                if let Some(off) = rva_to_offset(pe, n_rva) {
                    name_map[ord] = Some(read_cstring(buffer, off));
                }
            }
        }
    }

    let export_end_rva = export_rva + export_size;
    let mut exports = Vec::with_capacity(count);

    for i in 0..count {
        if func_off + i * 4 + 4 > buffer.len() { break; }
        let frva = unsafe { read_u32_le(buffer, func_off + i * 4) };
        if frva == 0 { continue; }

        let ordinal = (ordinal_base as u16).wrapping_add(i as u16);
        let name = name_map[i].take();

        let forwarded = if frva >= export_rva && frva < export_end_rva {
            rva_to_offset(pe, frva).map(|o| read_cstring(buffer, o))
        } else {
            None
        };

        exports.push(ExportEntry { ordinal, name, rva: frva, forwarded });
    }

    Some(ExportInfo { dll_name, num_funcs, num_names, base: ordinal_base, exports })
}

fn compute_block_entropy(buffer: &[u8], block_size: usize) -> Vec<f32> {
    let n = (buffer.len() + block_size - 1) / block_size;
    let mut result = Vec::with_capacity(n);
    let mut offset = 0usize;
    while offset < buffer.len() {
        let end = (offset + block_size).min(buffer.len());
        result.push(shannon_entropy_bytes(&buffer[offset..end]));
        offset = end;
    }
    result
}

fn compute_disasm_lines(pe: &PeInfo, buffer: &[u8]) -> (Vec<DisasmLine>, DisasmMeta) {
    let empty = || (Vec::new(), DisasmMeta { calls: 0u16, jumps: 0u16, rets: 0u16, nops: 0u16, func_starts: Vec::new(), user_code: None, arcs: Vec::new() });
    if buffer.is_empty() { return empty(); }

    let ep_off = match find_ep_file_offset(pe) {
        Some(o) if o < buffer.len() => o,
        _ => return empty(),
    };

    let bitness = if pe.arch == "x64" { 64 } else { 32 };
    let code = &buffer[ep_off..];
    let ip = pe.image_base + pe.entry_point as u64;

    let mut decoder = Decoder::with_ip(bitness, code, ip, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::with_capacity(4000);
    while decoder.can_decode() && instructions.len() < 4000 {
        instructions.push(decoder.decode());
    }
    if instructions.is_empty() { return empty(); }

    let mut formatter = IntelFormatter::new();
    let mut output = String::new();
    let lut = HEX_LUT.as_ptr();
    let mut lines = Vec::with_capacity(instructions.len());

    let mut meta = DisasmMeta { calls: 0u16, jumps: 0u16, rets: 0u16, nops: 0u16, func_starts: Vec::new(), user_code: None, arcs: Vec::new() };

    let first_ip = instructions[0].ip();
    let last_ip  = instructions.last().map(|i| i.ip()).unwrap_or(first_ip);

    let string_va_map = build_string_va_map(pe);

    for (idx, instr) in instructions.iter().enumerate() {
        output.clear();
        formatter.format(instr, &mut output);

        let instr_ip = instr.ip();
        let instr_len = instr.len();

        let (opcode, operands) = split_opcode_operands(&output);

        let rva = (instr_ip - pe.image_base) as u32;
        let hex_bytes = if let Some(foff) = rva_to_file_offset_sections(pe, rva) {
            let end = (foff + instr_len).min(buffer.len());
            let mut buf = Vec::with_capacity(instr_len * 3);
            let ptr = buffer.as_ptr();
            for j in foff..end {
                let b = unsafe { *ptr.add(j) } as usize;
                let li = b * 2;
                unsafe {
                    buf.push(*lut.add(li));
                    buf.push(*lut.add(li + 1));
                }
                buf.push(b' ');
            }
            unsafe { String::from_utf8_unchecked(buf) }
        } else {
            String::new()
        };

        let fc = instr.flow_control();
        let kind = match fc {
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => InstrKind::Jump,
            FlowControl::ConditionalBranch => InstrKind::CondJump,
            FlowControl::Call | FlowControl::IndirectCall => InstrKind::Call,
            FlowControl::Return => InstrKind::Ret,
            FlowControl::Interrupt => InstrKind::Int,
            _ => {
                if output.starts_with("nop") { InstrKind::Nop } else { InstrKind::Other }
            }
        };

        let target = match fc {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call => {
                let t = instr.near_branch_target();
                if t != 0 { Some(t) } else { None }
            }
            _ => None,
        };

        let is_prologue = detect_prologue(&instructions, idx, bitness);

        match kind {
            InstrKind::Call     => meta.calls += 1,
            InstrKind::Jump | InstrKind::CondJump => meta.jumps += 1,
            InstrKind::Ret      => meta.rets += 1,
            InstrKind::Nop      => meta.nops += 1,
            _ => {}
        }

        if is_prologue {
            meta.func_starts.push(idx as u16);
        }

        let comment = build_comment(instr, &pe.iat_map, &string_va_map, target, bitness);

        lines.push(DisasmLine {
            ip: instr_ip, rva, hex_bytes,
            opcode: opcode.to_string(), operands: operands.to_string(),
            mnemonic: output.clone(),
            kind, target, is_prologue, comment,
        });
    }

    if meta.user_code.is_none() {
        for (idx, line) in lines.iter().enumerate() {
            if line.kind == InstrKind::Call {
                if let Some(tgt) = line.target {
                    if tgt >= first_ip && tgt <= last_ip {
                        if let Some(tgt_idx) = lines.iter().position(|l| l.ip == tgt) {
                            if lines[tgt_idx].is_prologue {
                                if tgt_idx != 0 && idx > 0 {
                                    meta.user_code = Some(tgt_idx as u16);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut ip_to_idx: std::collections::HashMap<u64, usize> = std::collections::HashMap::with_capacity(lines.len());
    for (i, l) in lines.iter().enumerate() {
        ip_to_idx.insert(l.ip, i);
    }

    let mut arcs: Vec<BranchArc> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if matches!(line.kind, InstrKind::Call | InstrKind::Jump | InstrKind::CondJump) {
            if let Some(tgt) = line.target {
                if let Some(&tgt_idx) = ip_to_idx.get(&tgt) {
                    arcs.push(BranchArc { from: i as u16, to: tgt_idx as u16, kind: line.kind, col: 0 });
                }
            }
        }
    }

    arcs.sort_by_key(|a| {
        let lo = a.from.min(a.to);
        let hi = a.from.max(a.to);
        hi - lo
    });
    for i in 0..arcs.len() {
        let lo = arcs[i].from.min(arcs[i].to) as usize;
        let hi = arcs[i].from.max(arcs[i].to) as usize;
        let mut used = [false; 12];
        for j in 0..i {
            let jlo = arcs[j].from.min(arcs[j].to) as usize;
            let jhi = arcs[j].from.max(arcs[j].to) as usize;
            if jlo <= hi && jhi >= lo {
                let c = arcs[j].col as usize;
                if c < used.len() { used[c] = true; }
            }
        }
        arcs[i].col = used.iter().position(|&u| !u).unwrap_or(0) as u8;
    }

    meta.arcs = arcs;

    (lines, meta)
}

fn split_opcode_operands(text: &str) -> (&str, &str) {
    match text.find(' ') {
        Some(pos) => (&text[..pos], text[pos + 1..].trim_start()),
        None      => (text, ""),
    }
}

fn build_string_va_map(pe: &PeInfo) -> std::collections::HashMap<u64, String> {
    let mut map = std::collections::HashMap::new();
    for es in &pe.strings {
        let off = es.offset;
        for s in &pe.sections {
            let sec_raw_start = s.raw_offset;
            let sec_raw_end   = sec_raw_start + s.raw_size;
            if off >= sec_raw_start && off < sec_raw_end {
                let rva = s.virtual_addr as u64 + (off - sec_raw_start) as u64;
                let va  = pe.image_base + rva;
                let preview = if es.value.len() > 40 {
                    format!("\"{}...\"", &es.value[..40])
                } else {
                    format!("\"{}\"", es.value)
                };
                map.insert(va, preview);
                break;
            }
        }
    }
    map
}

fn build_comment(
    instr: &Instruction,
    iat_map: &std::collections::HashMap<u64, String>,
    string_map: &std::collections::HashMap<u64, String>,
    target: Option<u64>,
    _bitness: u32,
) -> String {
    let mem_disp = instr.memory_displacement64();

    if mem_disp != 0 {
        if let Some(sym) = iat_map.get(&mem_disp) {
            return sym.clone();
        }
    }

    if let Some(t) = target {
        if let Some(sym) = iat_map.get(&t) {
            return sym.clone();
        }
    }

    for addr in [mem_disp, instr.immediate64()] {
        if addr != 0 {
            if let Some(s) = string_map.get(&addr) {
                return s.clone();
            }
        }
    }

    String::new()
}

fn detect_prologue(instrs: &[Instruction], idx: usize, bitness: u32) -> bool {
    let instr = &instrs[idx];
    let code = instr.code();
    let code_val = code as u32;

    let is_push_bp = {
        let op_count = instr.op_count();
        if op_count >= 1 {
            let reg = instr.op0_register();
            use iced_x86::Register;
            matches!(reg, Register::RBP | Register::EBP)
                && instr.flow_control() == FlowControl::Next
                && is_push_code(code_val)
        } else {
            false
        }
    };

    if is_push_bp {
        if idx + 1 < instrs.len() {
            let next = &instrs[idx + 1];
            let nreg0 = next.op0_register();
            let nreg1 = next.op1_register();
            use iced_x86::Register;
            if matches!(nreg0, Register::RBP | Register::EBP)
                && matches!(nreg1, Register::RSP | Register::ESP)
            {
                return true;
            }
        }
    }

    if bitness == 64 && idx > 0 {
        let reg = instr.op0_register();
        use iced_x86::Register;
        if reg == Register::RSP && instr.op_count() >= 2 {
            if idx > 0 && instrs[idx - 1].flow_control() == FlowControl::Return {
                return true;
            }
        }
    }

    false
}

#[inline]
fn is_push_code(_code_val: u32) -> bool {
    true
}

fn find_ep_file_offset(pe: &PeInfo) -> Option<usize> {
    let ep = pe.entry_point;
    for s in &pe.sections {
        let va = s.virtual_addr;
        let vsize = s.virtual_size.max(s.raw_size);
        if ep >= va && ep < va + vsize {
            return Some((s.raw_offset + (ep - va)) as usize);
        }
    }
    None
}

fn rva_to_file_offset_sections(pe: &PeInfo, rva: u32) -> Option<usize> {
    for s in &pe.sections {
        let va = s.virtual_addr;
        let vsize = s.virtual_size.max(s.raw_size);
        if rva >= va && rva < va + vsize {
            return Some((s.raw_offset + (rva - va)) as usize);
        }
    }
    None
}

fn parse_resources(pe: &VecPE, buffer: &[u8]) -> Option<ResourceInfo> {
    let dd = pe.get_data_directory(exe::ImageDirectoryEntry::Resource).ok()?;
    let rsrc_rva = dd.virtual_address.0;
    if rsrc_rva == 0 || dd.size == 0 { return None; }
    let rsrc_off = rva_to_offset(pe, rsrc_rva)?;
    if rsrc_off + 16 > buffer.len() { return None; }

    let mut info = ResourceInfo {
        has_manifest: false, manifest_xml: None,
        has_version: false, version_info: None,
        has_icon: false, resource_types: Vec::new(),
    };

    let num_named = unsafe { read_u16_le(buffer, rsrc_off + 12) } as usize;
    let num_id    = unsafe { read_u16_le(buffer, rsrc_off + 14) } as usize;
    let total = (num_named + num_id).min(64);

    for i in 0..total {
        let entry_off = rsrc_off + 16 + i * 8;
        if entry_off + 8 > buffer.len() { break; }
        let name_or_id = unsafe { read_u32_le(buffer, entry_off) };
        let offset_val = unsafe { read_u32_le(buffer, entry_off + 4) };

        let type_id = if name_or_id & 0x8000_0000 != 0 { 0 } else { name_or_id };
        let type_name = match type_id {
            1  => "RT_CURSOR",     2  => "RT_BITMAP",      3  => "RT_ICON",
            4  => "RT_MENU",       5  => "RT_DIALOG",      6  => "RT_STRING",
            7  => "RT_FONTDIR",    8  => "RT_FONT",        9  => "RT_ACCELERATOR",
            10 => "RT_RCDATA",     11 => "RT_MESSAGETABLE", 12 => "RT_GROUP_CURSOR",
            14 => "RT_GROUP_ICON", 16 => "RT_VERSION",     24 => "RT_MANIFEST",
            _ => "",
        };
        if !type_name.is_empty() {
            info.resource_types.push(type_name.into());
        }

        match type_id {
            14 => { info.has_icon = true; }
            24 => {
                info.has_manifest = true;
                if offset_val & 0x8000_0000 != 0 {
                    let l2_off = rsrc_off + (offset_val & 0x7FFF_FFFF) as usize;
                    if let Some(data) = walk_resource_to_data(buffer, rsrc_off, l2_off) {
                        info.manifest_xml = std::str::from_utf8(data).ok().map(|s| s.to_string());
                    }
                }
            }
            16 => {
                info.has_version = true;
                if offset_val & 0x8000_0000 != 0 {
                    let l2_off = rsrc_off + (offset_val & 0x7FFF_FFFF) as usize;
                    if let Some(data) = walk_resource_to_data(buffer, rsrc_off, l2_off) {
                        info.version_info = parse_version_info(data);
                    }
                }
            }
            _ => {}
        }
    }

    if info.resource_types.is_empty() && !info.has_manifest && !info.has_version && !info.has_icon {
        return None;
    }
    Some(info)
}

fn walk_resource_to_data<'a>(buffer: &'a [u8], rsrc_off: usize, l2_off: usize) -> Option<&'a [u8]> {
    if l2_off + 16 > buffer.len() { return None; }
    let num2 = (unsafe { read_u16_le(buffer, l2_off + 12) } as usize
              + unsafe { read_u16_le(buffer, l2_off + 14) } as usize).min(16);
    if num2 == 0 { return None; }

    let e2_off = l2_off + 16;
    if e2_off + 8 > buffer.len() { return None; }
    let offset2 = unsafe { read_u32_le(buffer, e2_off + 4) };

    if offset2 & 0x8000_0000 != 0 {
        let l3_off = rsrc_off + (offset2 & 0x7FFF_FFFF) as usize;
        if l3_off + 16 > buffer.len() { return None; }
        let num3 = (unsafe { read_u16_le(buffer, l3_off + 12) } as usize
                  + unsafe { read_u16_le(buffer, l3_off + 14) } as usize).min(16);
        if num3 == 0 { return None; }
        let e3_off = l3_off + 16;
        if e3_off + 8 > buffer.len() { return None; }
        let data_entry_off = unsafe { read_u32_le(buffer, e3_off + 4) };
        if data_entry_off & 0x8000_0000 != 0 { return None; }
        return read_resource_data_entry(buffer, rsrc_off + data_entry_off as usize);
    }

    read_resource_data_entry(buffer, rsrc_off + offset2 as usize)
}

fn read_resource_data_entry<'a>(buffer: &'a [u8], entry_off: usize) -> Option<&'a [u8]> {
    if entry_off + 16 > buffer.len() { return None; }
    let data_rva  = unsafe { read_u32_le(buffer, entry_off) };
    let data_size = unsafe { read_u32_le(buffer, entry_off + 4) } as usize;
    if data_size == 0 || data_size > buffer.len() { return None; }

    let file_off = rva_to_offset_raw(buffer, data_rva)?;
    if file_off + data_size > buffer.len() { return None; }
    Some(&buffer[file_off..file_off + data_size])
}

fn rva_to_offset_raw(buffer: &[u8], rva: u32) -> Option<usize> {
    if buffer.len() < 64 { return None; }
    let pe_off = unsafe { read_u32_le(buffer, 0x3C) } as usize;
    if pe_off + 6 > buffer.len() { return None; }
    let num_sections = unsafe { read_u16_le(buffer, pe_off + 6) } as usize;
    let opt_hdr_size = unsafe { read_u16_le(buffer, pe_off + 20) } as usize;
    let sec_table = pe_off + 24 + opt_hdr_size;

    for i in 0..num_sections.min(96) {
        let s_off = sec_table + i * 40;
        if s_off + 40 > buffer.len() { break; }
        let va    = unsafe { read_u32_le(buffer, s_off + 12) };
        let vsize = unsafe { read_u32_le(buffer, s_off + 8) };
        let raw_d = unsafe { read_u32_le(buffer, s_off + 16) };
        let raw_s = unsafe { read_u32_le(buffer, s_off + 20) };
        let effective_size = vsize.max(raw_s);
        if rva >= va && rva < va + effective_size {
            return Some((raw_d + (rva - va)) as usize);
        }
    }
    None
}

fn parse_version_info(data: &[u8]) -> Option<VersionInfo> {
    let sig_pos = data.windows(4).position(|w| {
        w == [0xBD, 0x04, 0xEF, 0xFE]
    })?;
    if sig_pos + 52 > data.len() { return None; }

    let ms_file = unsafe { read_u32_le(data, sig_pos + 8) };
    let ls_file = unsafe { read_u32_le(data, sig_pos + 12) };
    let ms_prod = unsafe { read_u32_le(data, sig_pos + 16) };
    let ls_prod = unsafe { read_u32_le(data, sig_pos + 20) };

    let file_version = format!("{}.{}.{}.{}",
        ms_file >> 16, ms_file & 0xFFFF, ls_file >> 16, ls_file & 0xFFFF);
    let product_version = format!("{}.{}.{}.{}",
        ms_prod >> 16, ms_prod & 0xFFFF, ls_prod >> 16, ls_prod & 0xFFFF);

    let company_name      = find_version_string(data, "CompanyName");
    let file_description  = find_version_string(data, "FileDescription");
    let original_filename = find_version_string(data, "OriginalFilename");

    Some(VersionInfo { file_version, product_version, company_name, file_description, original_filename })
}

fn find_version_string(data: &[u8], key: &str) -> Option<String> {
    let key_utf16: Vec<u8> = key.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let pos = data.windows(key_utf16.len()).position(|w| w == key_utf16.as_slice())?;
    let after_key = pos + key_utf16.len() + 2; // +2 for UTF-16 null
    let aligned = (after_key + 3) & !3;
    if aligned + 2 > data.len() { return None; }

    let mut chars = Vec::new();
    let mut i = aligned;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        if lo == 0 && hi == 0 { break; }
        chars.push(u16::from_le_bytes([lo, hi]));
        i += 2;
        if chars.len() > 512 { break; }
    }
    if chars.is_empty() { return None; }
    Some(String::from_utf16_lossy(&chars))
}

fn parse_certificate(pe: &VecPE, buffer: &[u8]) -> Option<CertificateInfo> {
    let dd = pe.get_data_directory(exe::ImageDirectoryEntry::Security).ok()?;
    let offset = dd.virtual_address.0;
    let size = dd.size;
    if offset == 0 || size == 0 { return None; }
    let off = offset as usize;
    if off + 8 > buffer.len() { return None; }

    let _dw_length = unsafe { read_u32_le(buffer, off) };
    let w_revision = unsafe { read_u16_le(buffer, off + 4) };
    let w_cert_type = unsafe { read_u16_le(buffer, off + 6) };

    let type_label = match w_cert_type {
        0x0001 => "X.509",
        0x0002 => "PKCS#7 SignedData",
        0x0003 => "Reserved",
        0x0004 => "Terminal Server",
        _ => "Unknown",
    }.into();

    Some(CertificateInfo { offset, size, revision: w_revision, cert_type: w_cert_type, type_label })
}

fn parse_imports(pe: &VecPE, buffer: &[u8], is_64: bool) -> Vec<ImportInfo> {
    let mut result = Vec::new();

    let (import_rva, import_size) = match pe.get_data_directory(exe::ImageDirectoryEntry::Import) {
        Ok(dd) => (dd.virtual_address.0, dd.size),
        Err(_) => return result,
    };

    if import_rva == 0 || import_size == 0 { return result; }

    let raw_import_offset = match rva_to_offset(pe, import_rva) {
        Some(o) => o,
        None    => return result,
    };

    let mut desc_offset = raw_import_offset;
    loop {
        if desc_offset + 20 > buffer.len() { break; }

        let name_rva    = unsafe { read_u32_le(buffer, desc_offset + 12) };
        let thunk_rva   = unsafe { read_u32_le(buffer, desc_offset) };
        let first_thunk = unsafe { read_u32_le(buffer, desc_offset + 16) };

        if name_rva == 0 && thunk_rva == 0 && first_thunk == 0 { break; }

        let dll_name = if name_rva != 0 {
            rva_to_offset(pe, name_rva)
                .map(|off| read_cstring(buffer, off))
                .unwrap_or_else(|| "(unknown)".into())
        } else {
            "(unknown)".into()
        };

        let mut functions = Vec::new();
        let thunk_start = if thunk_rva != 0 { thunk_rva } else { first_thunk };

        if thunk_start != 0 {
            if let Some(mut thunk_off) = rva_to_offset(pe, thunk_start) {
                let thunk_size = if is_64 { 8usize } else { 4usize };
                let ordinal_flag: u64 = if is_64 { 0x8000_0000_0000_0000 } else { 0x8000_0000 };
                loop {
                    if thunk_off + thunk_size > buffer.len() { break; }
                    let val: u64 = unsafe {
                        if is_64 { read_u64_le(buffer, thunk_off) }
                        else     { read_u32_le(buffer, thunk_off) as u64 }
                    };
                    if val == 0 { break; }
                    if val & ordinal_flag != 0 {
                        functions.push(format!("Ordinal#{}", val & 0xFFFF));
                    } else {
                        let hint_rva = (val & 0x7FFF_FFFF) as u32;
                        if let Some(hoff) = rva_to_offset(pe, hint_rva) {
                            let fname = read_cstring(buffer, hoff + 2);
                            if !fname.is_empty() { functions.push(fname); }
                        }
                    }
                    thunk_off += thunk_size;
                    if functions.len() > 2000 { functions.push("... (truncated)".into()); break; }
                }
            }
        }

        result.push(ImportInfo { dll: dll_name, functions });
        desc_offset += 20;
        if result.len() > 512 { break; }
    }

    result
}

fn build_iat_map(pe: &VecPE, buffer: &[u8], is_64: bool, image_base: u64) -> std::collections::HashMap<u64, String> {
    let mut map = std::collections::HashMap::new();

    let (import_rva, import_size) = match pe.get_data_directory(exe::ImageDirectoryEntry::Import) {
        Ok(dd) => (dd.virtual_address.0, dd.size),
        Err(_) => return map,
    };
    if import_rva == 0 || import_size == 0 { return map; }

    let raw_import_offset = match rva_to_offset(pe, import_rva) {
        Some(o) => o,
        None    => return map,
    };

    let thunk_size: usize = if is_64 { 8 } else { 4 };
    let ordinal_flag: u64 = if is_64 { 0x8000_0000_0000_0000 } else { 0x8000_0000 };

    let mut desc_offset = raw_import_offset;
    loop {
        if desc_offset + 20 > buffer.len() { break; }
        let name_rva    = unsafe { read_u32_le(buffer, desc_offset + 12) };
        let thunk_rva   = unsafe { read_u32_le(buffer, desc_offset) };
        let first_thunk = unsafe { read_u32_le(buffer, desc_offset + 16) };

        if name_rva == 0 && thunk_rva == 0 && first_thunk == 0 { break; }

        let dll_name = if name_rva != 0 {
            rva_to_offset(pe, name_rva)
                .map(|off| read_cstring(buffer, off))
                .unwrap_or_default()
        } else {
            String::new()
        };

        let name_thunk_start = if thunk_rva != 0 { thunk_rva } else { first_thunk };
        let iat_rva_start = first_thunk;

        if name_thunk_start != 0 && iat_rva_start != 0 {
            if let Some(mut name_off) = rva_to_offset(pe, name_thunk_start) {
                let mut idx = 0u32;
                loop {
                    if name_off + thunk_size > buffer.len() { break; }
                    let val: u64 = unsafe {
                        if is_64 { read_u64_le(buffer, name_off) }
                        else     { read_u32_le(buffer, name_off) as u64 }
                    };
                    if val == 0 { break; }

                    let func_name = if val & ordinal_flag != 0 {
                        format!("Ordinal#{}", val & 0xFFFF)
                    } else {
                        let hint_rva = (val & 0x7FFF_FFFF) as u32;
                        rva_to_offset(pe, hint_rva)
                            .map(|hoff| read_cstring(buffer, hoff + 2))
                            .unwrap_or_default()
                    };

                    if !func_name.is_empty() {
                        let entry_va = image_base + iat_rva_start as u64 + (idx as u64 * thunk_size as u64);
                        map.insert(entry_va, format!("{}!{}", dll_name, func_name));
                    }

                    name_off += thunk_size;
                    idx += 1;
                    if idx > 4000 { break; }
                }
            }
        }

        desc_offset += 20;
        if map.len() > 16000 { break; }
    }

    map
}

fn rva_to_offset(pe: &VecPE, rva: u32) -> Option<usize> {
    if let Ok(sections) = pe.get_section_table() {
        for s in sections {
            let va    = s.virtual_address.0;
            let vsize = s.virtual_size.max(s.size_of_raw_data);
            if rva >= va && rva < va + vsize {
                return Some((s.pointer_to_raw_data.0 + (rva - va)) as usize);
            }
        }
    }
    None
}

#[inline]
fn read_cstring(data: &[u8], offset: usize) -> String {
    if offset >= data.len() { return String::new(); }
    let slice = &data[offset..];
    let len = unsafe {
        let ptr = slice.as_ptr();
        let end = ptr.add(slice.len());
        let mut p = ptr;
        while p < end && *p != 0 { p = p.add(1); }
        p.offset_from(ptr) as usize
    };
    String::from_utf8_lossy(&slice[..len]).into_owned()
}

fn extract_strings(data: &[u8], base_offset: usize, section: &str) -> Vec<ExtractedString> {
    const MIN_LEN: usize = 5;
    let len = data.len();
    let mut results = Vec::new();
    let sec = section.to_string();

    {
        let ptr = data.as_ptr();
        let mut i = 0usize;
        let mut run_start = 0usize;
        let mut in_run = false;

        while i < len {
            let b = unsafe { *ptr.add(i) };
            let printable = b.is_ascii_graphic() || b == b' ' || b == b'\t';
            if printable {
                if !in_run { run_start = i; in_run = true; }
            } else if in_run {
                let run_len = i - run_start;
                if run_len >= MIN_LEN {
                    let slice = unsafe { std::slice::from_raw_parts(ptr.add(run_start), run_len) };
                    let value = String::from_utf8_lossy(slice).into_owned();
                    let kind = classify_string(&value);
                    results.push(ExtractedString { value, offset: (base_offset + run_start) as u32, kind, section: sec.clone() });
                }
                in_run = false;
            }
            i += 1;
        }
        if in_run && (len - run_start) >= MIN_LEN {
            let slice = &data[run_start..];
            let value = String::from_utf8_lossy(slice).into_owned();
            let kind = classify_string(&value);
            results.push(ExtractedString { value, offset: (base_offset + run_start) as u32, kind, section: sec.clone() });
        }
    }

    {
        let seen: HashSet<String> = results.iter().map(|r| r.value.clone()).collect();
        let mut wstart: Option<usize> = None;
        let mut wbuf: Vec<u8> = Vec::with_capacity(256);
        let mut i = 0usize;
        let aligned_end = len & !1;

        while i < aligned_end {
            let lo = unsafe { *data.get_unchecked(i) };
            let hi = unsafe { *data.get_unchecked(i + 1) };
            let printable = hi == 0 && ((lo >= 0x20 && lo <= 0x7E) || lo == 0x09);
            if printable {
                if wstart.is_none() { wstart = Some(i); }
                wbuf.push(lo);
            } else if let Some(ws) = wstart.take() {
                if wbuf.len() >= MIN_LEN {
                    let value = unsafe { String::from_utf8_unchecked(wbuf.clone()) };
                    if !seen.contains(value.as_str()) {
                        let kind = if classify_string(&value) == StringKind::Obfuscated { StringKind::Obfuscated } else { StringKind::Wide };
                        results.push(ExtractedString { value, offset: (base_offset + ws) as u32, kind, section: sec.clone() });
                    }
                }
                wbuf.clear();
            }
            i += 2;
        }
    }

    results
}

struct ByteStats {
    alpha:  u16,
    digits: u16,
    all_numeric_like: bool,
}

#[inline]
fn byte_stats(s: &str) -> ByteStats {
    let len = s.len();
    let ptr = s.as_ptr();
    let (mut alpha, mut digits) = (0u16, 0u16);
    let mut all_numeric_like = true;
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        if b.is_ascii_alphabetic() {
            alpha += 1;
            all_numeric_like = false;
        } else if b.is_ascii_digit() {
            digits += 1;
        } else if !matches!(b, b'.' | b'-' | b'+' | b'e' | b'E') {
            all_numeric_like = false;
        }
    }
    ByteStats { alpha, digits, all_numeric_like }
}

fn classify_string(s: &str) -> StringKind {
    if looks_like_version(s) || looks_like_path(s) || looks_like_known_identifier(s)
        || is_camel_or_pascal_case(s)
    {
        return StringKind::Ascii;
    }

    let total = s.len();
    let stats = byte_stats(s);

    if stats.all_numeric_like && stats.digits > 0 { return StringKind::Ascii; }
    if total < 8 { return StringKind::Ascii; }
    if total >= 32 && looks_like_hex_string(s) { return StringKind::Obfuscated; }

    if total >= 16 && looks_like_base64(s) {
        let ent = shannon_entropy_str(s);
        if ent > 4.0 && stats.digits > 0 { return StringKind::Obfuscated; }
    }

    if looks_like_url_encoded(s) { return StringKind::Obfuscated; }
    if looks_like_xor_artifact(s) { return StringKind::Obfuscated; }

    let alpha = stats.alpha as usize;
    if total > 0 && alpha * 100 / total < 10 { return StringKind::Obfuscated; }

    if total >= 20 {
        let ent = shannon_entropy_str(s);
        if ent > 4.8 && alpha * 100 / total < 35 { return StringKind::Obfuscated; }
    }

    StringKind::Ascii
}

#[inline]
fn looks_like_version(s: &str) -> bool {
    let len = s.len();
    if len == 0 { return false; }
    let ptr = s.as_ptr();
    let mut has_dot = false;
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        if b == b'.' { has_dot = true; }
        else if !b.is_ascii_digit() { return false; }
    }
    has_dot
}

#[inline]
fn looks_like_path(s: &str) -> bool {
    let len = s.len();
    if len == 0 { return false; }
    let ptr = s.as_ptr();
    if unsafe { *ptr } == b'.' { return true; }
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        if b == b'\\' || b == b'/' { return true; }
    }
    false
}

#[inline]
fn is_camel_or_pascal_case(s: &str) -> bool {
    let len = s.len();
    if len < 4 { return false; }
    let ptr = s.as_ptr();
    let first = unsafe { *ptr };
    if !first.is_ascii_uppercase() { return false; }
    let (mut uppers, mut has_lower) = (1u16, false);
    for i in 1..len {
        let b = unsafe { *ptr.add(i) };
        if b.is_ascii_uppercase() { uppers += 1; }
        else if b.is_ascii_lowercase() { has_lower = true; }
        else if !b.is_ascii_digit() && b != b'_' { return false; }
    }
    has_lower && uppers >= 2
}

#[inline]
fn looks_like_known_identifier(s: &str) -> bool {
    let bytes = s.as_bytes();
    let suffixes: &[&[u8]] = &[
        b".dll", b".DLL", b".exe", b".EXE", b".sys", b".SYS",
        b".ocx", b".OCX", b".cpl", b".CPL", b".scr", b".SCR",
        b".mui", b".MUI", b".pdb", b".PDB", b".drv", b".DRV",
    ];
    if suffixes.iter().any(|suf| bytes.ends_with(suf)) { return true; }
    let prefixes: &[&[u8]] = &[
        b"MSVC", b"VCRUN", b"UCRTBASE", b"KERNEL", b"NTDLL", b"USER32", b"ADVAPI",
        b"SHELL32", b"OLE32", b"COMCTL", b"COMDLG", b"MSVCP", b"__", b"_CRT",
        b"WS2_", b"WINHTTP", b"WININET", b"GDI32", b"WINSPOOL", b"IMM32",
        b"IMAGEHLP", b"DBGHELP", b"SHLWAPI", b"PSAPI", b"API-MS-",
    ];
    prefixes.iter().any(|p| starts_with_ignore_ascii_case(bytes, p))
}

#[inline]
fn starts_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() { return false; }
    let ptr_h = haystack.as_ptr();
    let ptr_n = needle.as_ptr();
    for i in 0..needle.len() {
        let h = unsafe { (*ptr_h.add(i)).to_ascii_uppercase() };
        let n = unsafe { *ptr_n.add(i) };
        if h != n { return false; }
    }
    true
}


#[inline]
fn looks_like_base64(s: &str) -> bool {
    let len = s.len();
    if len < 16 || len % 4 != 0 { return false; }
    let ptr = s.as_ptr();
    let (mut eq, mut has_upper, mut has_lower, mut has_digit) = (0u8, false, false, false);
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        if b.is_ascii_uppercase()      { has_upper = true; }
        else if b.is_ascii_lowercase() { has_lower = true; }
        else if b.is_ascii_digit()     { has_digit = true; }
        else if b == b'='              { eq += 1; }
        else if b != b'+' && b != b'/' { return false; }
    }
    eq <= 2 && has_upper && has_lower && has_digit
}

#[inline]
fn looks_like_hex_string(s: &str) -> bool {
    let len = s.len();
    if len < 32 { return false; }
    let ptr = s.as_ptr();
    let mut has_alpha = false;
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        if !b.is_ascii_hexdigit() { return false; }
        if b.is_ascii_alphabetic() { has_alpha = true; }
    }
    has_alpha
}

#[inline]
fn looks_like_url_encoded(s: &str) -> bool {
    let len = s.len();
    let ptr = s.as_ptr();
    let mut pct = 0u16;
    for i in 0..len {
        if unsafe { *ptr.add(i) } == b'%' { pct += 1; }
    }
    pct >= 3 && (pct as usize) * 3 <= len
}

#[inline]
fn looks_like_xor_artifact(s: &str) -> bool {
    let len = s.len();
    if len < 8 { return false; }
    let ptr = s.as_ptr();
    let first = unsafe { *ptr };
    let mut first_count = 0u16;
    for i in 0..len {
        if unsafe { *ptr.add(i) } == first { first_count += 1; }
    }
    if first_count as usize * 100 / len > 80 { return true; }
    let p0 = unsafe { *ptr };
    let p1 = unsafe { *ptr.add(1) };
    let pairs = len / 2;
    let mut pair_matches = 0u16;
    for i in (0..pairs * 2).step_by(2) {
        if unsafe { *ptr.add(i) } == p0 && unsafe { *ptr.add(i + 1) } == p1 {
            pair_matches += 1;
        }
    }
    pair_matches as usize * 100 / pairs > 70
}

#[inline]
fn shannon_entropy_str(s: &str) -> f64 {
    let len = s.len();
    if len == 0 { return 0.0; }
    let mut freq = [0u32; 256];
    let ptr = s.as_ptr();
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        unsafe { *freq.get_unchecked_mut(b as usize) += 1; }
    }
    let flen = len as f64;
    let mut ent = 0.0f64;
    for i in 0..256 {
        let c = unsafe { *freq.get_unchecked(i) };
        if c > 0 {
            let p = c as f64 / flen;
            ent -= p * p.log2();
        }
    }
    ent
}

#[inline]
fn shannon_entropy_bytes(data: &[u8]) -> f32 {
    let len = data.len();
    if len == 0 { return 0.0; }
    let mut freq = [0u32; 256];
    let ptr = data.as_ptr();
    for i in 0..len {
        let b = unsafe { *ptr.add(i) };
        unsafe { *freq.get_unchecked_mut(b as usize) += 1; }
    }
    let flen = len as f64;
    let mut ent = 0.0f64;
    for i in 0..256 {
        let c = unsafe { *freq.get_unchecked(i) };
        if c > 0 {
            let p = c as f64 / flen;
            ent -= p * p.log2();
        }
    }
    ent as f32
}

fn subsystem_name(sub: u16) -> String {
    match sub {
        1  => "Native",
        2  => "Windows GUI",
        3  => "Windows Console",
        9  => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Driver",
        12 => "EFI Runtime Driver",
        14 => "Xbox",
        16 => "Windows Boot Application",
        _  => return format!("Unknown ({sub})"),
    }.into()
}

fn decode_dll_characteristics(flags: u16) -> Vec<String> {
    let mut out = Vec::new();
    if flags & 0x0020 != 0 { out.push("HIGH_ENTROPY_VA".into()); }
    if flags & 0x0040 != 0 { out.push("DYNAMIC_BASE (ASLR)".into()); }
    if flags & 0x0080 != 0 { out.push("FORCE_INTEGRITY".into()); }
    if flags & 0x0100 != 0 { out.push("NX_COMPAT (DEP)".into()); }
    if flags & 0x0200 != 0 { out.push("NO_ISOLATION".into()); }
    if flags & 0x0400 != 0 { out.push("NO_SEH".into()); }
    if flags & 0x0800 != 0 { out.push("NO_BIND".into()); }
    if flags & 0x1000 != 0 { out.push("APPCONTAINER".into()); }
    if flags & 0x2000 != 0 { out.push("WDM_DRIVER".into()); }
    if flags & 0x4000 != 0 { out.push("GUARD_CF".into()); }
    if flags & 0x8000 != 0 { out.push("TERMINAL_SERVER_AWARE".into()); }
    out
}

fn decode_section_characteristics(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x0000_0020 != 0 { out.push("CODE"); }
    if flags & 0x0000_0040 != 0 { out.push("INITIALIZED_DATA"); }
    if flags & 0x0000_0080 != 0 { out.push("UNINITIALIZED_DATA"); }
    if flags & 0x0200_0000 != 0 { out.push("DISCARDABLE"); }
    if flags & 0x1000_0000 != 0 { out.push("SHARED"); }
    if flags & 0x2000_0000 != 0 { out.push("EXECUTE"); }
    if flags & 0x4000_0000 != 0 { out.push("READ"); }
    if flags & 0x8000_0000 != 0 { out.push("WRITE"); }
    out
}
