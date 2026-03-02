# Six Eyes

A Windows PE (Portable Executable) static analysis tool built in Rust. It parses `.exe`, `.dll`, `.sys`, `.ocx`, and `.scr` files and presents the results across six analysis tabs in a custom desktop GUI.

All analysis runs locally — hashing, disassembly, heuristics, and string extraction are handled without external services or network calls.

![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Features

### Overview
- File hashes: MD5, SHA-256, ImpHash, RichHash (all implemented from scratch, zero crypto dependencies)
- PE metadata: architecture, subsystem, entry point, image base, linker/OS versions, timestamps
- Security flags: ASLR, DEP, CFG, NX, SEH — displayed as color-coded badges
- Section table with entropy bars, sizes, and characteristics
- Full-file entropy heatmap (1KB block resolution)
- Exports table, resources (manifest, version info), overlay detection
- Language/compiler detection: MSVC, GCC/MinGW, .NET, Go, Rust, Delphi, Python (PyInstaller), AutoIt, Nim
- Go symbol extraction (functions + source files) and Rust crate detection

### Imports
- Imported functions grouped by DLL, color-coded by risk level
- Capability detection mapped to 16 categories (process injection, anti-debug, crypto, network, registry, privilege escalation, etc.), each tagged with a MITRE ATT&CK technique ID

### Strings
- ASCII, Wide (UTF-16LE), and obfuscated string extraction
- Virtualized table for handling thousands of strings efficiently
- Live text search and kind filter

### Heuristics
- Threat score (0–100) based on weighted findings: critical, warning, and informational
- Categorized checks: packing/obfuscation, suspicious imports, structural anomalies, missing security flags, metadata inconsistencies, export forwarding, missing signatures

### Hex View
- Virtualized hex dump — classic offset | hex | ASCII layout, 16 bytes per row

### Disassembly
- x86/x86-64 disassembly from the entry point (up to 4000 instructions, Intel syntax)
- Syntax highlighting inspired by IDA/Ghidra color schemes
- IAT resolution: `call [IAT]` instructions annotated with `DLL!FunctionName`
- String reference resolution in `mov`/`lea` instructions
- Function prologue detection and boundary separators
- Branch arc gutter with column-assigned arcs to avoid overlap
- Jump-to-address, function list dropdown, and live search
- Heuristic detection of user code entry (`main()`)

---

## Building

### Requirements
- Rust 1.85+ (edition 2024)
- MSVC toolchain (Windows)

### Build
```bash
# Debug
cargo build

# Release (optimized for size, fully stripped)
cargo build --release
```

The release binary is at `target/release/six-eyes.exe`.

### Run
```bash
cargo run --release
```

Open a PE file using the "Open PE..." button in the titlebar.

---

## Project Structure

```
src/
  main.rs        — Application entry point, window setup
  app.rs         — App state, tab routing, eframe::App implementation
  model.rs       — Data structures (PeInfo, SectionInfo, DisasmLine, etc.)
  parser.rs      — PE parsing engine, string extraction, disassembly generation
  hashing.rs     — MD5, SHA-256, PE checksum, ImpHash, RichHash
  detection.rs   — Language/compiler detection, Rich header parsing, Go/Rust analysis
  heuristics.rs  — Threat scoring, suspicious import detection, capability mapping
  ui/
    mod.rs       — Shared UI helpers (key-value layouts, badges, gradients, easing)
    titlebar.rs  — Custom frameless titlebar with window controls
    overview.rs  — Overview tab
    imports.rs   — Imports tab
    strings.rs   — Strings tab
    heuristics.rs — Heuristics tab
    hexview.rs   — Hex viewer tab
    disasm.rs    — Disassembly tab
```

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| [exe](https://crates.io/crates/exe) | PE file parsing |
| [eframe](https://crates.io/crates/eframe) / [egui](https://crates.io/crates/egui) | GUI framework |
| [egui_extras](https://crates.io/crates/egui_extras) | Virtualized table rendering |
| [rfd](https://crates.io/crates/rfd) | Native file dialog |
| [iced-x86](https://crates.io/crates/iced-x86) | x86/x86-64 instruction decoding |

---

## License

All rights reserved.
