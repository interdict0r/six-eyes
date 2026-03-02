use eframe::egui::{self, Color32, RichText, Ui, Vec2, Rect, Stroke};
use crate::model::*;
use crate::detection::dll_char_tooltip;
use super::*;

pub fn render_overview(ui: &mut Ui, pe: &PeInfo, score: u8) {
    egui::ScrollArea::vertical()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
        .show(ui, |ui| {
        let margin = egui::Margin::symmetric(14.0, 10.0);
        egui::Frame::none().inner_margin(margin).show(ui, |ui| {

        // 1. Quick Summary
        let sc = score_color(score);
        section_card(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::new(48.0, 48.0), egui::Sense::hover());
                ui.painter().circle_stroke(rect.center(), 22.0, Stroke::new(3.0, Color32::from_rgb(40,42,52)));
                let sweep = std::f32::consts::TAU * score as f32 / 100.0;
                for i in 0..(sweep * 60.0) as usize {
                    let angle = -std::f32::consts::FRAC_PI_2 + (i as f32) / 60.0;
                    let p = rect.center() + Vec2::new(angle.cos(), angle.sin()) * 22.0;
                    ui.painter().circle_filled(p, 1.5, sc);
                }
                ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER,
                    format!("{score}"), egui::FontId::proportional(18.0), sc);

                ui.add_space(12.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&pe.arch).monospace().strong().size(14.0));
                        ui.label(RichText::new("·").weak().size(14.0));
                        ui.label(RichText::new(&pe.subsystem).size(14.0));
                        if let Some(lang) = &pe.detected_language {
                            ui.label(RichText::new("·").weak().size(14.0));
                            ui.label(RichText::new(lang).color(Color32::from_rgb(180,140,255)).strong().size(14.0));
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{} sections", pe.sections.len())).weak().size(12.0));
                        ui.label(RichText::new("·").weak().size(12.0));
                        let total_imp: usize = pe.imports.iter().map(|i| i.functions.len()).sum();
                        ui.label(RichText::new(format!("{} imports from {} DLLs", total_imp, pe.imports.len())).weak().size(12.0));
                        if let Some(ref exp) = pe.exports {
                            ui.label(RichText::new("·").weak().size(12.0));
                            ui.label(RichText::new(format!("{} exports", exp.exports.len())).weak().size(12.0));
                        }
                        ui.label(RichText::new("·").weak().size(12.0));
                        ui.label(RichText::new(format!("{} strings", pe.strings.len())).weak().size(12.0));
                        let obf = pe.strings.iter().filter(|s| s.kind == StringKind::Obfuscated).count();
                        if obf > 0 {
                            ui.label(RichText::new(format!("({obf} obfuscated)")).color(Color32::from_rgb(230,120,50)).size(12.0));
                        }
                    });
                });
            });
        });
        ui.add_space(16.0);

        // 2. Security Flags
        section_header(ui, "Security Flags");
        section_card(ui, |ui| {
            if pe.dll_chars.is_empty() {
                ui.label(RichText::new("(none set)").weak().italics().size(13.0));
            } else {
                ui.horizontal_wrapped(|ui| {
                    for flag in &pe.dll_chars {
                        let c = dll_char_color(flag);
                        let tooltip = dll_char_tooltip(flag);
                        let response = egui::Frame::none()
                            .rounding(0.0).inner_margin(egui::Margin::symmetric(6.0, 2.0))
                            .fill(Color32::from_rgba_premultiplied(c.r()/10, c.g()/10, c.b()/10, 255))
                            .stroke(Stroke::new(1.0, c))
                            .show(ui, |ui| { ui.label(RichText::new(flag).color(c).size(12.0)); })
                            .response;
                        if !tooltip.is_empty() { response.on_hover_text(tooltip); }
                    }
                });
            }
        });
        ui.add_space(16.0);

        // 3. PE Identity
        section_header(ui, "PE Identity");
        section_card(ui, |ui| {
            grid(ui, "ov_pe", |ui| {
                kv(ui, "Architecture",   &pe.arch);
                kv(ui, "Subsystem",      &pe.subsystem);
                kv(ui, "Entry Point",    &format!("0x{:08X}  (RVA)", pe.entry_point));
                kv(ui, "Image Base",     &format!("0x{:016X}", pe.image_base));
                kv(ui, "Linker Version", &pe.linker_ver);
                kv(ui, "Min OS Version", &pe.os_ver);
                if pe.pe_timestamp != 0 {
                    kv(ui, "PE Timestamp", &format!("0x{:08X}  (~{})", pe.pe_timestamp, 1970 + pe.pe_timestamp / 31_536_000));
                }
                if let Some(rh) = &pe.rich_hint { kv(ui, "Rich Header", rh); }
                if let Some(rh) = &pe.rich_hash { kv(ui, "RichHash", rh); }
                if !pe.imphash.is_empty() { kv(ui, "ImpHash", &pe.imphash); }
                if let Some(lang) = &pe.detected_language {
                    kv(ui, "Language", lang);
                }
                if let Some(ref cert) = pe.certificate {
                    kv(ui, "Certificate", &format!("{} ({} bytes at 0x{:X})", cert.type_label, cert.size, cert.offset));
                }
                if let Some(go) = &pe.go_info {
                    kv(ui, "Go Version", &go.version_hint);
                    if !go.functions.is_empty() {
                        kv(ui, "Go Symbols", &format!("{} functions, {} source files", go.functions.len(), go.source_files.len()));
                    }
                }
                if let Some(ri) = &pe.rust_info {
                    if let Some(ver) = &ri.compiler_version {
                        kv(ui, "Rust Compiler", &format!("rustc {}", &ver[..ver.len().min(12)]));
                    }
                    if !ri.crates.is_empty() {
                        kv(ui, "Rust Crates", &format!("{} detected", ri.crates.len()));
                    }
                }
            });
        });
        ui.add_space(16.0);

        // Go/Rust expanded info (collapsible)
        if let Some(go) = &pe.go_info {
            if !go.functions.is_empty() {
                ui.collapsing(RichText::new(format!("Go Symbols  ({})", go.functions.len())).strong().color(Color32::from_rgb(140,190,255)).size(14.0), |ui| {
                    section_card(ui, |ui| {
                        for f in go.functions.iter().take(200) {
                            ui.label(RichText::new(f).monospace().size(11.0));
                        }
                        if go.functions.len() > 200 {
                            ui.label(RichText::new(format!("... {} more", go.functions.len() - 200)).weak().italics().size(11.0));
                        }
                    });
                });
                ui.add_space(8.0);
            }
        }
        if let Some(ri) = &pe.rust_info {
            if !ri.crates.is_empty() {
                ui.collapsing(RichText::new(format!("Rust Crates  ({})", ri.crates.len())).strong().color(Color32::from_rgb(140,190,255)).size(14.0), |ui| {
                    section_card(ui, |ui| {
                        for c in &ri.crates {
                            ui.label(RichText::new(c).monospace().size(11.0));
                        }
                    });
                });
                ui.add_space(8.0);
            }
        }

        // 4. Sections
        section_header(ui, "Sections");
        section_card(ui, |ui| {
            let bar_max = (ui.available_width() - 300.0).max(80.0);
            for s in &pe.sections {
                ui.horizontal(|ui| {
                    let color = entropy_color(s.entropy);
                    let bw    = (s.entropy / 8.0 * bar_max).max(0.0);
                    ui.label(RichText::new(format!("{:<10}", s.name)).monospace().size(14.0));
                    let (rect, _) = ui.allocate_exact_size(Vec2::new(bar_max, 18.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 0.0, Color32::from_rgb(35, 35, 40));
                    let fill_rect = Rect::from_min_size(rect.min, Vec2::new(bw, 18.0));
                    if fill_rect.is_positive() {
                        let dim = Color32::from_rgb(color.r()/3, color.g()/3, color.b()/3);
                        paint_h_gradient(ui.painter(), fill_rect, dim, color);
                    }
                    ui.painter().rect_stroke(rect, 0.0, Stroke::new(1.0, Color32::from_rgb(50,52,60)));
                    ui.label(RichText::new(format!("{:.4}  {}", s.entropy, entropy_label(s.entropy))).color(color).size(13.0));
                    if s.is_ep { ui.label(RichText::new("◀ EP").color(Color32::YELLOW).size(13.0)); }
                });
                ui.add_space(2.0);
            }
            ui.add_space(6.0);
            egui::Grid::new("ov_sec_detail").num_columns(7).spacing([14.0,5.0]).striped(true).min_col_width(60.0).show(ui, |ui| {
                for h in &["Name","Virtual Address","Virtual Size","Raw Size","Entropy","Status","Characteristics"] {
                    ui.label(RichText::new(*h).strong().size(13.0));
                }
                ui.end_row();
                for s in &pe.sections {
                    let name_rt = if s.is_ep {
                        RichText::new(format!("{} ◀", s.name)).color(Color32::YELLOW).monospace()
                    } else { RichText::new(&s.name).monospace() };
                    ui.label(name_rt.size(12.0));
                    ui.label(RichText::new(format!("0x{:08X}", s.virtual_addr)).monospace().size(12.0));
                    ui.label(RichText::new(format!("0x{:08X}", s.virtual_size)).monospace().size(12.0));
                    ui.label(RichText::new(format!("0x{:08X}", s.raw_size)).monospace().size(12.0));
                    ui.label(RichText::new(format!("{:.4}", s.entropy)).color(entropy_color(s.entropy)).monospace().size(12.0));
                    ui.label(RichText::new(entropy_label(s.entropy)).color(entropy_color(s.entropy)).size(11.0));
                    ui.label(RichText::new(s.characteristics.join(" | ")).size(11.0).weak());
                    ui.end_row();
                }
            });
        });
        ui.add_space(16.0);

        // 4b. Entropy Heatmap
        if !pe.block_entropy.is_empty() {
            section_header(ui, "Entropy Heatmap");
            section_card(ui, |ui| {
                let avail_w = ui.available_width() - 20.0;
                let num_blocks = pe.block_entropy.len();
                let px_per_block = (avail_w / num_blocks as f32).max(1.0).min(4.0);
                let strip_w = (px_per_block * num_blocks as f32).min(avail_w);
                let strip_h = 24.0;
                let (rect, resp) = ui.allocate_exact_size(Vec2::new(strip_w, strip_h), egui::Sense::hover());

                for (i, &ent) in pe.block_entropy.iter().enumerate() {
                    let x = rect.min.x + i as f32 * px_per_block;
                    if x > rect.max.x { break; }
                    let w = px_per_block.min(rect.max.x - x);
                    let color = entropy_color(ent);
                    let block_rect = Rect::from_min_size(egui::pos2(x, rect.min.y), Vec2::new(w, strip_h));
                    ui.painter().rect_filled(block_rect, 0.0, color);
                }
                ui.painter().rect_stroke(rect, 0.0, Stroke::new(1.0, Color32::from_rgb(50,52,60)));

                // Hover tooltip
                if resp.hovered() {
                    if let Some(pos) = ui.input(|i| i.pointer.hover_pos()) {
                        if rect.contains(pos) {
                            let idx = ((pos.x - rect.min.x) / px_per_block) as usize;
                            if idx < pe.block_entropy.len() {
                                let file_offset = idx * 1024;
                                egui::show_tooltip_at_pointer(ui.ctx(), egui::Id::new("ent_tip"), |ui| {
                                    ui.label(format!("Offset: 0x{:X}\nEntropy: {:.4}", file_offset, pe.block_entropy[idx]));
                                });
                            }
                        }
                    }
                }

                ui.horizontal(|ui| {
                    ui.label(RichText::new("0.0").size(10.0).color(Color32::from_rgb(60,180,80)));
                    ui.label(RichText::new("low").size(10.0).weak());
                    ui.add_space(12.0);
                    ui.label(RichText::new("6.0").size(10.0).color(Color32::from_rgb(220,160,40)));
                    ui.label(RichText::new("suspicious").size(10.0).weak());
                    ui.add_space(12.0);
                    ui.label(RichText::new("7.0+").size(10.0).color(Color32::from_rgb(220,55,55)));
                    ui.label(RichText::new("packed/encrypted").size(10.0).weak());
                });
            });
            ui.add_space(16.0);
        }

        // 4c. Exports
        if let Some(ref exp) = pe.exports {
            if !exp.exports.is_empty() {
                section_header(ui, "Exports");
                section_card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&exp.dll_name).monospace().strong().size(13.0));
                        ui.label(RichText::new(format!("  {} functions ({} named)", exp.exports.len(), exp.num_names)).weak().size(12.0));
                        let fwd = exp.exports.iter().filter(|e| e.forwarded.is_some()).count();
                        if fwd > 0 {
                            ui.label(RichText::new(format!("  {fwd} forwarded")).color(Color32::YELLOW).size(12.0));
                        }
                    });
                    ui.add_space(4.0);
                    let show_count = exp.exports.len().min(500);
                    ui.collapsing(RichText::new(format!("Export Table  ({show_count} shown)")).size(13.0), |ui| {
                        egui::Grid::new("ov_exports").num_columns(4).spacing([14.0,3.0]).striped(true).min_col_width(60.0).show(ui, |ui| {
                            for h in &["Ordinal", "Name", "RVA", "Forward"] {
                                ui.label(RichText::new(*h).strong().size(12.0));
                            }
                            ui.end_row();
                            for e in exp.exports.iter().take(500) {
                                ui.label(RichText::new(format!("{}", e.ordinal)).monospace().size(11.0));
                                ui.label(RichText::new(e.name.as_deref().unwrap_or("-")).monospace().size(11.0));
                                ui.label(RichText::new(format!("0x{:08X}", e.rva)).monospace().size(11.0));
                                let fwd_text = e.forwarded.as_deref().unwrap_or("");
                                let fwd_color = if fwd_text.is_empty() { Color32::GRAY } else { Color32::YELLOW };
                                ui.label(RichText::new(if fwd_text.is_empty() { "-" } else { fwd_text }).monospace().size(11.0).color(fwd_color));
                                ui.end_row();
                            }
                        });
                    });
                });
                ui.add_space(16.0);
            }
        }

        // 4d. Resources
        if let Some(ref res) = pe.resources {
            section_header(ui, "Resources");
            section_card(ui, |ui| {
                grid(ui, "ov_res", |ui| {
                    if !res.resource_types.is_empty() {
                        kv(ui, "Resource Types", &res.resource_types.join(", "));
                    }
                    kv(ui, "Manifest",     if res.has_manifest { "Present" } else { "None" });
                    kv(ui, "Version Info", if res.has_version  { "Present" } else { "None" });
                    kv(ui, "Icon",         if res.has_icon     { "Present" } else { "None" });
                    if let Some(ref vi) = res.version_info {
                        kv(ui, "File Version",    &vi.file_version);
                        kv(ui, "Product Version", &vi.product_version);
                        if let Some(ref c) = vi.company_name      { kv(ui, "Company", c); }
                        if let Some(ref d) = vi.file_description   { kv(ui, "Description", d); }
                        if let Some(ref o) = vi.original_filename  { kv(ui, "Original Name", o); }
                    }
                });
                if let Some(ref xml) = res.manifest_xml {
                    ui.add_space(6.0);
                    ui.collapsing(RichText::new("Manifest XML").strong().size(13.0), |ui| {
                        ui.label(RichText::new(xml).monospace().size(11.0));
                    });
                }
            });
            ui.add_space(16.0);
        }

        // 5. Integrity & Stats
        section_header(ui, "Integrity & Stats");
        section_card(ui, |ui| {
            grid(ui, "ov_int", |ui| {
                let cs_col = if pe.checksum_ok { Color32::GREEN } else { Color32::RED };
                ui.label(RichText::new("Checksum").strong().size(14.0));
                ui.label(RichText::new(format!(
                    "Stored: 0x{:08X}   Calculated: 0x{:08X}   {}",
                    pe.stored_cs, pe.calc_cs,
                    if pe.checksum_ok { "OK" } else { "MISMATCH" }
                )).color(cs_col).size(13.0));
                ui.end_row();

                if let Some(ov) = &pe.overlay {
                    ui.label(RichText::new("Overlay").strong().size(14.0));
                    ui.label(RichText::new(format!(
                        "{} bytes at offset 0x{:X}  ({:.2} KB)",
                        ov.size, ov.offset, ov.size as f64/1024.0
                    )).color(Color32::YELLOW).size(13.0));
                    ui.end_row();
                }

                if pe.certificate.is_none() {
                    kv(ui, "Certificate", "Not signed");
                }

                kv(ui, "Sections",       &pe.sections.len().to_string());
                kv(ui, "Imports (DLLs)", &pe.imports.len().to_string());
                kv(ui, "Total imports",  &pe.imports.iter().map(|i| i.functions.len()).sum::<usize>().to_string());
                if let Some(ref exp) = pe.exports {
                    kv(ui, "Exports", &format!("{} functions ({} named)", exp.exports.len(), exp.num_names));
                }
                kv(ui, "Strings",        &pe.strings.len().to_string());

                let obf = pe.strings.iter().filter(|s| s.kind == StringKind::Obfuscated).count();
                if obf > 0 {
                    ui.label(RichText::new("Obfuscated strings").strong().size(14.0));
                    ui.label(RichText::new(format!("{obf} flagged")).color(Color32::from_rgb(230,120,50)).size(13.0));
                    ui.end_row();
                }
            });
        });
        ui.add_space(16.0);

        // 6. File & Hashes
        section_header(ui, "File");
        section_card(ui, |ui| {
            grid(ui, "ov_file", |ui| {
                kv(ui, "Path",    &pe.path);
                kv(ui, "Size",    &format!("{} bytes  ({:.2} KB)", pe.file_size, pe.file_size as f64/1024.0));
                kv(ui, "MD5",     &pe.md5);
                kv(ui, "SHA-256", &pe.sha256);
                if !pe.imphash.is_empty() { kv(ui, "ImpHash", &pe.imphash); }
                if let Some(ref rh) = pe.rich_hash { kv(ui, "RichHash", rh); }
            });
        });

        }); // end inner Frame
    });
}
