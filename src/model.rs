use eframe::egui::Color32;

// ── Data model ────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct PeInfo {
    pub path:        String,
    pub file_size:   usize,
    pub arch:        String,
    pub entry_point: u32,
    pub image_base:  u64,
    pub pe_timestamp: u32,
    pub linker_ver:  String,
    pub os_ver:      String,
    pub subsystem:   String,
    pub dll_chars:   Vec<String>,
    pub md5:         String,
    pub sha256:      String,
    pub imphash:     String,
    pub sections:    Vec<SectionInfo>,
    pub imports:     Vec<ImportInfo>,
    pub strings:     Vec<ExtractedString>,
    pub checksum_ok: bool,
    pub stored_cs:   u32,
    pub calc_cs:     u32,
    pub overlay:           Option<OverlayInfo>,
    pub rich_hint:         Option<String>,
    pub rich_hash:         Option<String>,
    pub rich_entries:      Vec<(u16, u16, u32)>,
    pub error:             Option<String>,
    pub detected_language: Option<String>,
    pub go_info:           Option<GoInfo>,
    pub rust_info:         Option<RustInfo>,
    pub exports:           Option<ExportInfo>,
    pub block_entropy:     Vec<f32>,
    pub resources:         Option<ResourceInfo>,
    pub certificate:       Option<CertificateInfo>,
    pub disasm_lines:      Vec<DisasmLine>,
    pub disasm_meta:       Option<DisasmMeta>,
    pub iat_map:           std::collections::HashMap<u64, String>,  // VA -> "DLL!Function"
    pub buffer:            Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InstrKind {
    Call,
    Jump,
    CondJump,
    Ret,
    Nop,
    Int,
    Other,
}

impl InstrKind {
    #[inline]
    pub fn color(self) -> Color32 {
        match self {
            Self::Call     => Color32::from_rgb(255, 180, 80),   // orange
            Self::Jump     => Color32::from_rgb(100, 220, 100),  // green
            Self::CondJump => Color32::from_rgb(200, 220, 80),   // yellow-green
            Self::Ret      => Color32::from_rgb(230, 90, 90),    // red
            Self::Nop      => Color32::from_rgb(90, 90, 100),    // dim gray
            Self::Int      => Color32::from_rgb(200, 130, 230),  // purple
            Self::Other    => Color32::from_rgb(210, 210, 220),  // near-white
        }
    }
}

pub struct DisasmLine {
    pub ip:          u64,
    pub rva:         u32,
    pub hex_bytes:   String,
    pub opcode:      String,          // mnemonic only (e.g. "push", "call")
    pub operands:    String,          // operand text (e.g. "rbp", "qword ptr [rax+10h]")
    pub mnemonic:    String,          // full text for search compat
    pub kind:        InstrKind,
    pub target:      Option<u64>,     // branch/call target VA (near only)
    pub is_prologue: bool,
    pub comment:     String,          // auto-generated comment (IAT symbol, string preview, xref)
}

/// A visual connector between a branch/call source and its target.
pub struct BranchArc {
    pub from: usize,      // source line index (the branch instruction)
    pub to:   usize,      // target line index
    pub kind: InstrKind,
    pub col:  u8,         // visual nesting column (0 = closest to instructions)
}

/// Aggregate stats + heuristic pointers for the disasm tab.
pub struct DisasmMeta {
    pub calls:       u32,
    pub jumps:       u32,
    pub rets:        u32,
    pub nops:        u32,
    pub func_starts: Vec<usize>,      // indices into disasm_lines that are prologues
    pub user_code:   Option<usize>,   // index of likely user-code entry (first internal call target prologue)
    pub arcs:        Vec<BranchArc>,  // pre-computed branch connectors with column assignments
}

pub struct SectionInfo {
    pub name:            String,
    pub virtual_addr:    u32,
    pub virtual_size:    u32,
    pub raw_size:        u32,
    pub raw_offset:      u32,
    pub entropy:         f32,
    pub is_ep:           bool,
    pub characteristics: Vec<&'static str>,
}

pub struct ImportInfo {
    pub dll:       String,
    pub functions: Vec<String>,
}

pub struct OverlayInfo {
    pub offset: u32,
    pub size:   usize,
}

#[allow(dead_code)]
pub struct ExportInfo {
    pub dll_name:  String,
    pub num_funcs: u32,
    pub num_names: u32,
    pub base:      u32,
    pub exports:   Vec<ExportEntry>,
}

pub struct ExportEntry {
    pub ordinal:   u16,
    pub name:      Option<String>,
    pub rva:       u32,
    pub forwarded: Option<String>,
}

pub struct ResourceInfo {
    pub has_manifest:   bool,
    pub manifest_xml:   Option<String>,
    pub has_version:    bool,
    pub version_info:   Option<VersionInfo>,
    pub has_icon:       bool,
    pub resource_types: Vec<String>,
}

pub struct VersionInfo {
    pub file_version:      String,
    pub product_version:   String,
    pub company_name:      Option<String>,
    pub file_description:  Option<String>,
    pub original_filename: Option<String>,
}

#[allow(dead_code)]
pub struct CertificateInfo {
    pub offset:     u32,
    pub size:       u32,
    pub revision:   u16,
    pub cert_type:  u16,
    pub type_label: String,
}

#[derive(Default)]
pub struct GoInfo {
    pub version_hint: String,
    pub functions:    Vec<String>,
    pub source_files: Vec<String>,
}

#[derive(Default)]
pub struct RustInfo {
    pub compiler_version: Option<String>,
    pub crates:           Vec<String>,
}

pub struct ExtractedString {
    pub value:   String,
    pub offset:  usize,
    pub kind:    StringKind,
    pub section: String,
}

#[derive(PartialEq, Clone, Copy)]
pub enum StringKind { Ascii, Wide, Obfuscated }

impl StringKind {
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ascii      => "ASCII",
            Self::Wide       => "WIDE",
            Self::Obfuscated => "OBFUSCATED",
        }
    }
    #[inline]
    pub fn color(self) -> Color32 {
        match self {
            Self::Ascii      => Color32::from_rgb(100, 200, 130),
            Self::Wide       => Color32::from_rgb(100, 170, 255),
            Self::Obfuscated => Color32::from_rgb(230, 120, 50),
        }
    }
}

// ── Disasm display settings ───────────────────────────────────────────────────

pub struct DisasmSettings {
    pub show_hex:      bool,
    pub show_arcs:     bool,
    pub show_comments: bool,     // IAT symbols, string previews, xrefs
    pub use_rva:       bool,     // show RVA instead of full VA
    pub rel_addr:      bool,     // show relative offsets on clickable branch targets
    pub max_arc_span:  usize,
}

impl Default for DisasmSettings {
    fn default() -> Self {
        Self {
            show_hex:      true,
            show_arcs:     true,
            show_comments: true,
            use_rva:       true,
            rel_addr:      true,
            max_arc_span:  200,
        }
    }
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Tab { #[default] Overview, Imports, Strings, Heuristics, HexView, Disasm }

#[derive(Default, PartialEq, Clone, Copy)]
pub enum StringKindFilter { #[default] All, Ascii, Wide, Obfuscated }
