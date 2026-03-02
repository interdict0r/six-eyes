use eframe::egui::{self, Color32, RichText, Ui, Vec2, Rect, Stroke};
use crate::heuristics::{HeuristicFlag, Severity};
use super::*;

pub fn render_heuristics(ui: &mut Ui, flags: &[HeuristicFlag]) {
    egui::ScrollArea::vertical()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
        .show(ui, |ui| {
        let margin = egui::Margin::symmetric(14.0, 10.0);
        egui::Frame::none().inner_margin(margin).show(ui, |ui| {

        if flags.is_empty() {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("OK").color(Color32::GREEN).size(36.0));
                ui.label(RichText::new("No suspicious indicators detected.").color(Color32::GREEN).size(16.0));
            });
            return;
        }

        let crits = flags.iter().filter(|f| f.severity == Severity::Critical).count();
        let warns = flags.iter().filter(|f| f.severity == Severity::Warn).count();
        let infos = flags.iter().filter(|f| f.severity == Severity::Info).count();
        let score = ((crits * 25 + warns * 10 + infos * 2) as u8).min(100);
        let sc = score_color(score);

        // Threat Score Gauge
        section_card(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(format!("{score}")).size(52.0).color(sc).strong());
                ui.label(RichText::new("THREAT SCORE").size(11.0).color(Color32::from_rgb(120,120,130)));
                ui.add_space(8.0);

                let bar_w = ui.available_width().min(420.0);
                let (rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, 10.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 0.0, Color32::from_rgb(35, 36, 42));
                let fill_w = rect.width() * score as f32 / 100.0;
                if fill_w > 1.0 {
                    let fill_rect = Rect::from_min_size(rect.min, Vec2::new(fill_w, 10.0));
                    paint_h_gradient(ui.painter(), fill_rect,
                        Color32::from_rgb(60, 180, 80), sc);
                }
                ui.painter().rect_stroke(rect, 0.0, Stroke::new(1.0, Color32::from_rgb(50,52,60)));

                ui.add_space(10.0);
                ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                    ui.horizontal(|ui| {
                        badge(ui, &format!("{crits} CRITICAL"), Severity::Critical.color());
                        badge(ui, &format!("{warns} WARNINGS"), Severity::Warn.color());
                        badge(ui, &format!("{infos} INFO"),     Severity::Info.color());
                    });
                });
            });
        });
        ui.add_space(16.0);

        // Category Cards (collapsible)
        for cat in &["Packing/Obfuscation", "Imports", "Exports", "Structure", "Security", "Metadata"] {
            let cat_flags: Vec<&crate::heuristics::HeuristicFlag> = flags.iter().filter(|f| &f.category == cat).collect();
            if cat_flags.is_empty() { continue; }

            let max_sev = cat_flags.iter().map(|f| f.severity).max().unwrap_or(Severity::Info);
            let cat_color = max_sev.color();
            let border_c = Color32::from_rgba_premultiplied(cat_color.r()/3, cat_color.g()/3, cat_color.b()/3, 255);

            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                .rounding(0.0)
                .fill(Color32::from_rgb(25, 27, 35))
                .stroke(Stroke::new(1.0, border_c))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    let id = ui.make_persistent_id(format!("heur_{cat}"));
                    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
                        .show_header(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(max_sev.icon()).color(cat_color).size(16.0));
                                ui.label(RichText::new(*cat).strong().size(15.0).color(Color32::from_rgb(180,210,255)));
                                ui.label(RichText::new(format!("({})", cat_flags.len())).weak().size(12.0));
                            });
                        })
                        .body(|ui| {
                            for flag in &cat_flags {
                                let c = flag.severity.color();
                                ui.horizontal(|ui| {
                                    egui::Frame::none().rounding(0.0)
                                        .inner_margin(egui::Margin::symmetric(4.0, 1.0))
                                        .fill(c).show(ui, |ui| {
                                            ui.label(RichText::new(flag.severity.label()).color(Color32::BLACK).size(10.0).strong());
                                        });
                                    ui.label(RichText::new(&flag.message).size(13.0));
                                });
                                ui.add_space(3.0);
                            }
                        });
                });
            ui.add_space(8.0);
        }

        }); // margin
    }); // scroll
}
