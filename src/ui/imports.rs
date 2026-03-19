use eframe::egui::{self, Color32, RichText, Ui, Stroke};
use crate::model::*;
use crate::heuristics::{MatchedCapability, suspicious_import_color};
use super::*;

pub fn render_imports(ui: &mut Ui, pe: &PeInfo, caps: &[MatchedCapability]) {
    if pe.imports.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("No imports found — binary may be packed or use manual IAT.").weak().size(14.0));
        });
        return;
    }

    let total = pe.total_imports();

    egui::ScrollArea::vertical()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
        .show(ui, |ui| {
        let margin = egui::Margin::symmetric(12.0, 8.0);
        egui::Frame::none().inner_margin(margin).show(ui, |ui| {

        ui.label(RichText::new(format!("{} DLLs  ·  {} functions  ·  {} capabilities detected",
            pe.imports.len(), total, caps.len())).weak().size(13.0));
        ui.add_space(8.0);

        if !caps.is_empty() {
            section_header(ui, "Detected Capabilities");
            for cap in caps {
                let (c, icon) = match cap.threat {
                    2 => (Color32::from_rgb(220,60,60), "!!"),
                    1 => (Color32::from_rgb(220,170,40), "!"),
                    _ => (Color32::from_rgb(100,170,255), "i"),
                };
                let fill   = Color32::from_rgba_premultiplied(c.r()/6, c.g()/6, c.b()/6, 255);
                let border = Color32::from_rgba_premultiplied(c.r()/3, c.g()/3, c.b()/3, 255);
                egui::Frame::none()
                    .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                    .rounding(0.0).fill(fill).stroke(Stroke::new(1.0, border))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icon).color(c).size(14.0));
                            ui.label(RichText::new(cap.name).color(c).strong().size(13.0));
                            ui.label(RichText::new(format!("[{}]", cap.mitre))
                                .color(Color32::from_rgb(140,140,160)).monospace().size(11.0));
                            ui.label(RichText::new("—").weak().size(12.0));
                            ui.label(RichText::new(cap.description).weak().size(12.0));
                        });
                        ui.horizontal_wrapped(|ui| {
                            ui.add_space(22.0);
                            for api in &cap.matched {
                                egui::Frame::none()
                                    .rounding(0.0).inner_margin(egui::Margin::symmetric(4.0, 1.0))
                                    .fill(Color32::from_rgb(40,40,50))
                                    .stroke(Stroke::new(0.5, Color32::from_rgb(70,70,80)))
                                    .show(ui, |ui| {
                                        ui.label(RichText::new(*api).monospace().size(11.0)
                                            .color(suspicious_import_color(api)));
                                    });
                            }
                        });
                    });
                ui.add_space(3.0);
            }
            ui.add_space(12.0);
        }

        section_header(ui, "Raw Imports by DLL");
        for imp in &pe.imports {
            let hdr = RichText::new(format!("{}  ({})", imp.dll, imp.functions.len()))
                .color(Color32::from_rgb(100,200,255)).strong().size(14.0);
            ui.collapsing(hdr, |ui| {
                egui::Grid::new(format!("imp_{}", imp.dll)).num_columns(1).spacing([8.0,2.0]).striped(true).show(ui, |ui| {
                    for f in &imp.functions {
                        ui.label(RichText::new(f).monospace().size(13.0).color(suspicious_import_color(f)));
                        ui.end_row();
                    }
                });
            });
        }

        }); // margin frame
    });
}
