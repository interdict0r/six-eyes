use std::rc::Rc;
use eframe::egui::Color32;

#[derive(Default)]
pub struct PeInfo {
    pub path:        String,
    pub file_size:   u32,
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
    pub packer:            Option<PackerInfo>,
    pub embedded:          Vec<EmbeddedArtifact>,
    pub disasm_lines:      Vec<DisasmLine>,
    pub disasm_meta:       Option<DisasmMeta>,
    pub iat_map:           std::collections::HashMap<u64, String>,
    pub string_xrefs:      std::collections::HashMap<u32, Vec<usize>>,
    pub relocations:       Option<RelocationInfo>,
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
            Self::Call     => Color32::from_rgb(255, 180, 80),
            Self::Jump     => Color32::from_rgb(100, 220, 100),
            Self::CondJump => Color32::from_rgb(200, 220, 80),
            Self::Ret      => Color32::from_rgb(230, 90, 90),
            Self::Nop      => Color32::from_rgb(90, 90, 100),
            Self::Int      => Color32::from_rgb(200, 130, 230),
            Self::Other    => Color32::from_rgb(210, 210, 220),
        }
    }
}

pub struct DisasmLine {
    pub ip:          u64,
    pub rva:         u32,
    pub hex_bytes:   String,
    pub opcode:      String,
    pub operands:    String,
    pub kind:        InstrKind,
    pub target:      Option<u64>,
    pub is_prologue: bool,
    pub comment:     String,
}

pub struct BranchArc {
    pub from: u16,
    pub to:   u16,
    pub kind: InstrKind,
    pub col:  u8,
}

pub struct DisasmMeta {
    pub calls:       u16,
    pub jumps:       u16,
    pub rets:        u16,
    pub nops:        u16,
    pub func_starts: Vec<u16>,
    pub user_code:   Option<u16>,
    pub arcs:        Vec<BranchArc>,
    pub ip_to_idx:   std::collections::HashMap<u64, usize>,
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
    pub size:   u32,
}

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

pub struct CertificateInfo {
    pub offset:     u32,
    pub size:       u32,
    pub revision:   u16,
    pub cert_type:  u16,
    pub type_label: String,
}

pub struct PackerInfo {
    pub name:       &'static str,
    pub confidence: PackerConfidence,
    pub details:    String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PackerConfidence { High, Medium, Low }

impl PackerConfidence {
    #[inline]
    pub fn label(self) -> &'static str {
        match self { Self::High => "HIGH", Self::Medium => "MED", Self::Low => "LOW" }
    }
    #[inline]
    pub fn color(self) -> Color32 {
        match self {
            Self::High   => Color32::from_rgb(220, 60, 60),
            Self::Medium => Color32::from_rgb(220, 170, 40),
            Self::Low    => Color32::from_rgb(100, 170, 255),
        }
    }
}

pub struct EmbeddedArtifact {
    pub kind:   ArtifactKind,
    pub offset: u32,
    pub size:   u32,
    pub detail: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind { Pe, Shellcode }

impl ArtifactKind {
    #[inline]
    pub fn label(self) -> &'static str {
        match self { Self::Pe => "Embedded PE", Self::Shellcode => "Shellcode" }
    }
    #[inline]
    pub fn color(self) -> Color32 {
        match self {
            Self::Pe        => Color32::from_rgb(220, 60, 60),
            Self::Shellcode => Color32::from_rgb(220, 130, 40),
        }
    }
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
    pub offset:  u32,
    pub kind:    StringKind,
    pub section: Rc<str>,
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

pub struct DisasmSettings {
    pub show_hex:      bool,
    pub show_arcs:     bool,
    pub show_comments: bool,
    pub use_rva:       bool,
    pub rel_addr:      bool,
    pub max_arc_span:  u16,
}

impl Default for DisasmSettings {
    fn default() -> Self {
        Self {
            show_hex:      true,
            show_arcs:     true,
            show_comments: true,
            use_rva:       true,
            rel_addr:      true,
            max_arc_span:  200u16,
        }
    }
}

pub struct RelocationInfo {
    pub total_entries: u32,
    pub blocks:        Vec<RelocBlock>,
}

pub struct RelocBlock {
    pub page_rva: u32,
    pub count:    u16,
    pub types:    Vec<(u8, u16)>,
}

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Tab { #[default] Overview, Imports, Exports, Strings, Heuristics, HexView, Disasm }

#[derive(Default, PartialEq, Clone, Copy)]
pub enum StringKindFilter { #[default] All, Ascii, Wide, Obfuscated }
