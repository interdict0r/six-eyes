use eframe::egui::{self, Color32, RichText, Ui};
use crate::model::*;
use crate::hashing::HEX_LUT;

const BYTES_PER_ROW: usize = 16;

pub fn render_hexview(ui: &mut Ui, pe: &PeInfo) {
    if pe.buffer.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("No file data available.").weak().size(14.0));
        });
        return;
    }

    let total_rows = pe.buffer.len().div_ceil(BYTES_PER_ROW);
    let row_height = 18.0;

    egui::Frame::none().inner_margin(egui::Margin::symmetric(12.0, 6.0)).show(ui, |ui| {
        ui.label(RichText::new(format!("{} bytes  ·  {} rows", pe.buffer.len(), total_rows)).weak().size(12.0));
    });

    egui::ScrollArea::vertical()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
        .auto_shrink([false, false])
        .show_rows(ui, row_height, total_rows, |ui, row_range| {
            let buf = &pe.buffer;
            let len = buf.len();
            let lut = HEX_LUT;

            let mut hex_buf: Vec<u8> = Vec::with_capacity(BYTES_PER_ROW * 3);
            let mut ascii_buf: Vec<u8> = Vec::with_capacity(BYTES_PER_ROW);
            let mut off_buf: Vec<u8> = Vec::with_capacity(8);

            for row_idx in row_range {
                let offset = row_idx * BYTES_PER_ROW;
                let end = (offset + BYTES_PER_ROW).min(len);
                let count = end - offset;

                hex_buf.clear();
                for i in 0..BYTES_PER_ROW {
                    if i < count {
                        let b = buf[offset + i] as usize;
                        let idx = b * 2;
                        hex_buf.push(lut[idx]);
                        hex_buf.push(lut[idx + 1]);
                        hex_buf.push(b' ');
                    } else {
                        hex_buf.extend_from_slice(b"   ");
                    }
                }
                // hex_buf contains only ASCII hex digits and spaces
                let hex_str = unsafe { std::str::from_utf8_unchecked(&hex_buf) };

                ascii_buf.clear();
                for &b in &buf[offset..end] {
                    ascii_buf.push(if (0x20..=0x7E).contains(&b) { b } else { b'.' });
                }
                // ascii_buf contains only printable ASCII or '.'
                let ascii_str = unsafe { std::str::from_utf8_unchecked(&ascii_buf) };

                off_buf.clear();
                let off_bytes = (offset as u32).to_be_bytes();
                for &b in &off_bytes {
                    let idx = (b as usize) * 2;
                    off_buf.push(lut[idx]);
                    off_buf.push(lut[idx + 1]);
                }
                // off_buf contains only ASCII hex digits
                let off_str = unsafe { std::str::from_utf8_unchecked(&off_buf) };

                ui.horizontal(|ui| {
                    ui.label(RichText::new(off_str).monospace().size(12.0).color(Color32::from_rgb(100, 170, 255)));
                    ui.label(RichText::new(hex_str).monospace().size(12.0));
                    ui.label(RichText::new(ascii_str).monospace().size(12.0).color(Color32::from_rgb(160, 160, 170)));
                });
            }
        });
}
