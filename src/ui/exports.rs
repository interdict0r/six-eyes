use eframe::egui::{self, Color32, RichText, Ui};
use crate::model::*;
use super::*;

pub fn render_exports(ui: &mut Ui, pe: &PeInfo) {
    let Some(exp) = &pe.exports else {
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("No exports found — this binary does not export any symbols.").weak().size(14.0));
        });
        return;
    };

    egui::ScrollArea::vertical()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
        .show(ui, |ui| {
        let margin = egui::Margin::symmetric(12.0, 8.0);
        egui::Frame::none().inner_margin(margin).show(ui, |ui| {

        // Summary row
        ui.label(RichText::new(format!(
            "{}  ·  {} functions  ·  {} named  ·  ordinal base {}",
            exp.dll_name, exp.num_funcs, exp.num_names, exp.base
        )).weak().size(13.0));
        ui.add_space(8.0);

        let show_count = exp.exports.len().min(1000);
        if exp.exports.len() > 1000 {
            ui.label(RichText::new(format!(
                "Showing first 1000 of {} exports", exp.exports.len()
            )).color(Color32::from_rgb(220, 160, 40)).size(12.0));
            ui.add_space(4.0);
        }

        section_header(ui, "Export Table");

        egui::Grid::new("exports_grid")
            .num_columns(4)
            .spacing([16.0, 3.0])
            .striped(true)
            .min_col_width(60.0)
            .show(ui, |ui| {
                // Header row
                ui.label(RichText::new("Ordinal").strong().size(13.0).color(Color32::from_rgb(140, 160, 200)));
                ui.label(RichText::new("Name").strong().size(13.0).color(Color32::from_rgb(140, 160, 200)));
                ui.label(RichText::new("RVA").strong().size(13.0).color(Color32::from_rgb(140, 160, 200)));
                ui.label(RichText::new("Forwarded To").strong().size(13.0).color(Color32::from_rgb(140, 160, 200)));
                ui.end_row();

                for entry in exp.exports.iter().take(show_count) {
                    // Ordinal
                    ui.label(RichText::new(format!("{}", entry.ordinal))
                        .monospace().size(13.0).color(Color32::from_rgb(160, 180, 220)));

                    // Name
                    match &entry.name {
                        Some(name) => ui.label(RichText::new(name).monospace().size(13.0).color(Color32::from_rgb(100, 200, 255))),
                        None       => ui.label(RichText::new("(no name)").monospace().size(13.0).weak()),
                    };

                    // RVA
                    if entry.rva == 0 {
                        ui.label(RichText::new("(forwarded)").monospace().size(12.0).weak());
                    } else {
                        ui.label(RichText::new(format!("{:#010X}", entry.rva)).monospace().size(13.0).color(Color32::from_rgb(180, 220, 140)));
                    }

                    // Forwarded
                    match &entry.forwarded {
                        Some(fwd) => ui.label(RichText::new(fwd).monospace().size(12.0).color(Color32::from_rgb(220, 170, 80))),
                        None      => ui.label(RichText::new("—").weak().size(13.0)),
                    };

                    ui.end_row();
                }
            });

        }); // margin frame
    });
}
