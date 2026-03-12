use eframe::egui::{self, Color32, RichText, Ui};
use egui_extras::{TableBuilder, Column};
use crate::model::*;

#[inline]
fn ascii_contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() { return false; }
    haystack.as_bytes().windows(needle.len()).any(|w|
        w.iter().zip(needle.as_bytes()).all(|(a, b)| a.to_ascii_lowercase() == *b)
    )
}

/// Returns Some(disasm_line_index) if the user wants to navigate to a string xref.
pub fn render_strings(ui: &mut Ui, pe: &PeInfo, filter: &mut String, kind_filter: &mut StringKindFilter) -> Option<usize> {
    let fl = filter.to_ascii_lowercase();
    let visible: Vec<&ExtractedString> = pe.strings.iter().filter(|s| {
        let ko = match kind_filter {
            StringKindFilter::All        => true,
            StringKindFilter::Ascii      => s.kind == StringKind::Ascii,
            StringKindFilter::Wide       => s.kind == StringKind::Wide,
            StringKindFilter::Obfuscated => s.kind == StringKind::Obfuscated,
        };
        ko && (fl.is_empty() || ascii_contains_ci(&s.value, &fl))
    }).collect();

    let normal: Vec<&ExtractedString> = visible.iter().copied().filter(|s| s.kind != StringKind::Obfuscated).collect();
    let obf:    Vec<&ExtractedString> = visible.iter().copied().filter(|s| s.kind == StringKind::Obfuscated).collect();

    let mut nav_target: Option<usize> = None;

    egui::Frame::none().inner_margin(egui::Margin::symmetric(12.0, 8.0)).show(ui, |ui| {
        let avail = ui.available_width();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Filter:").size(14.0));
            ui.add(egui::TextEdit::singleline(filter).desired_width((avail*0.45).min(400.0)).hint_text("Search strings..."));
            ui.separator();
            ui.label(RichText::new("Kind:").size(14.0));
            ui.selectable_value(kind_filter, StringKindFilter::All,        "All");
            ui.selectable_value(kind_filter, StringKindFilter::Ascii,      "ASCII");
            ui.selectable_value(kind_filter, StringKindFilter::Wide,       "Wide");
            ui.selectable_value(kind_filter, StringKindFilter::Obfuscated, "Obfuscated");
        });
        ui.add_space(2.0);
        ui.label(RichText::new(format!("{} shown  ({} normal · {} obfuscated)", visible.len(), normal.len(), obf.len())).weak().size(12.0));
    });

    egui::ScrollArea::vertical()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
        .show(ui, |ui| {
        egui::Frame::none().inner_margin(egui::Margin::symmetric(12.0, 4.0)).show(ui, |ui| {
        if !normal.is_empty() {
            ui.collapsing(RichText::new(format!("Strings  ({})", normal.len())).strong().size(14.0), |ui| {
                if let Some(idx) = string_table(ui, &normal, &pe.string_xrefs) {
                    nav_target = Some(idx);
                }
            });
        }
        ui.add_space(6.0);
        if !obf.is_empty() {
            ui.collapsing(
                RichText::new(format!("Possibly Encrypted / Obfuscated  ({})", obf.len()))
                    .color(Color32::from_rgb(230,120,50)).strong().size(14.0),
                |ui| {
                    ui.label(RichText::new("Low alphabetic density or high character diversity — may be XOR keys, base64, hashes, or encoded payloads.").weak().italics().size(12.0));
                    ui.add_space(4.0);
                    if let Some(idx) = string_table(ui, &obf, &pe.string_xrefs) {
                        nav_target = Some(idx);
                    }
                },
            );
        }
        if normal.is_empty() && obf.is_empty() {
            ui.label(RichText::new("No strings match the current filter.").weak().italics().size(14.0));
        }
        });
    });

    nav_target
}

fn string_table(ui: &mut Ui, strings: &[&ExtractedString], xrefs: &std::collections::HashMap<u32, Vec<usize>>) -> Option<usize> {
    let available = ui.available_height().max(200.0);
    let mut nav_target: Option<usize> = None;

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(95.0))
        .column(Column::exact(80.0))
        .column(Column::exact(90.0))
        .column(Column::exact(50.0))
        .column(Column::remainder().clip(true))
        .max_scroll_height(available)
        .header(20.0, |mut header| {
            header.col(|ui| { ui.label(RichText::new("Offset").strong().size(13.0)); });
            header.col(|ui| { ui.label(RichText::new("Section").strong().size(13.0)); });
            header.col(|ui| { ui.label(RichText::new("Kind").strong().size(13.0)); });
            header.col(|ui| { ui.label(RichText::new("Xrefs").strong().size(13.0)); });
            header.col(|ui| { ui.label(RichText::new("Value").strong().size(13.0)); });
        })
        .body(|body| {
            body.rows(18.0, strings.len(), |mut row| {
                let s = strings[row.index()];
                let refs = xrefs.get(&s.offset);
                let ref_count = refs.map_or(0, |v| v.len());

                row.col(|ui| { ui.label(RichText::new(format!("0x{:08X}", s.offset)).monospace().size(12.0)); });
                row.col(|ui| { ui.label(RichText::new(&*s.section).monospace().size(12.0)); });
                row.col(|ui| { ui.label(RichText::new(s.kind.label()).color(s.kind.color()).size(12.0)); });
                row.col(|ui| {
                    if ref_count > 0 {
                        ui.label(RichText::new(format!("{}", ref_count)).monospace().size(12.0).color(Color32::from_rgb(80, 180, 255)));
                    }
                });
                row.col(|ui| {
                    let text = if s.value.len() > 120 {
                        format!("{}...", &s.value[..120])
                    } else {
                        s.value.clone()
                    };
                    let resp = ui.label(RichText::new(&text).monospace().size(12.0));

                    // Right-click context menu for xrefs
                    if ref_count > 0 {
                        resp.context_menu(|ui| {
                            let refs = refs.unwrap();
                            if refs.len() == 1 {
                                if ui.button(RichText::new("Go to Xref in Disasm").size(12.0)).clicked() {
                                    nav_target = Some(refs[0]);
                                    ui.close_menu();
                                }
                            } else {
                                ui.label(RichText::new(format!("{} references:", refs.len())).weak().size(11.0));
                                ui.separator();
                                for (i, &line_idx) in refs.iter().enumerate().take(20) {
                                    let label = format!("Xref #{}", i + 1);
                                    if ui.button(RichText::new(label).size(12.0)).clicked() {
                                        nav_target = Some(line_idx);
                                        ui.close_menu();
                                    }
                                }
                            }
                        });
                    }
                });
            });
        });

    nav_target
}
