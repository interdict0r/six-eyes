pub mod overview;
pub mod imports;
pub mod strings;
pub mod heuristics;
pub mod titlebar;
pub mod hexview;
pub mod disasm;

use eframe::egui::{self, Color32, RichText, Ui, Vec2, Rect, Stroke};
use crate::model::*;

pub fn kv(ui: &mut Ui, key: &str, val: &str) {
    ui.label(RichText::new(key).strong().size(14.0));
    ui.label(RichText::new(val).size(13.0));
    ui.end_row();
}

pub fn section_header(ui: &mut Ui, title: &str) {
    ui.add_space(2.0);
    ui.label(RichText::new(title).strong().size(16.0).color(Color32::from_rgb(140, 190, 255)));
    let w = ui.available_width().min(300.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 2.0), egui::Sense::hover());
    paint_h_gradient(ui.painter(), rect,
        Color32::from_rgb(60, 100, 160), Color32::from_rgb(30, 32, 40));
    ui.add_space(6.0);
}

pub fn grid<F: FnOnce(&mut Ui)>(ui: &mut Ui, id: &str, add_contents: F) {
    egui::Grid::new(id).num_columns(2).spacing([32.0,5.0]).striped(true).min_col_width(140.0).show(ui, add_contents);
}

pub fn tab_btn(ui: &mut Ui, current: &mut Tab, target: Tab, label: &str) -> egui::Response {
    let sel = *current == target;
    let rt = if sel {
        RichText::new(label).color(Color32::from_rgb(100,200,255)).strong().size(14.0)
    } else {
        RichText::new(label).color(Color32::from_rgb(160,160,170)).size(14.0)
    };
    let resp = ui.selectable_label(sel, rt);
    if resp.clicked() { *current = target; }
    resp
}

pub fn badge(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::none()
        .rounding(0.0).inner_margin(egui::Margin::symmetric(8.0,3.0))
        .fill(Color32::from_rgba_premultiplied(color.r()/5, color.g()/5, color.b()/5, 255))
        .stroke(Stroke::new(1.0, color))
        .show(ui, |ui| { ui.label(RichText::new(text).color(color).strong().size(12.0)); });
}

#[inline] pub fn entropy_color(e: f32) -> Color32 {
    if e > 7.0 { Color32::from_rgb(220,55,55) } else if e > 6.0 { Color32::from_rgb(220,160,40) } else { Color32::from_rgb(60,180,80) }
}
#[inline] pub fn entropy_label(e: f32) -> &'static str {
    if e > 7.0 { "PACKED/CRYPTED" } else if e > 6.0 { "SUSPICIOUS" } else { "NORMAL" }
}
#[inline] pub fn dll_char_color(flag: &str) -> Color32 {
    if flag.contains("ASLR") || flag.contains("DEP") || flag.contains("GUARD") || flag.contains("ENTROPY") {
        Color32::from_rgb(80,200,120)
    } else if flag.contains("NO_SEH") || flag.contains("NO_ISOLATION") {
        Color32::from_rgb(220,160,40)
    } else {
        Color32::from_rgb(140,160,200)
    }
}

#[inline] pub fn ease_out_cubic(t: f32) -> f32 {
    let inv = 1.0 - t;
    1.0 - inv * inv * inv
}

pub fn truncate_path(path: &str, max_chars: usize) -> String {
    if path.len() <= max_chars { return path.to_string(); }
    let sep = if path.contains('\\') { '\\' } else { '/' };
    if let Some(f) = path.split(sep).next_back() {
        if f.len() + 6 <= max_chars { return format!("...\\{f}"); }
    }
    format!("...{}", &path[path.len()-max_chars+1..])
}

pub fn paint_h_gradient(painter: &egui::Painter, rect: Rect, left: Color32, right: Color32) {
    if !rect.is_positive() { return; }
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(rect.left_top(), left);
    mesh.colored_vertex(rect.right_top(), right);
    mesh.colored_vertex(rect.left_bottom(), left);
    mesh.colored_vertex(rect.right_bottom(), right);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(1, 2, 3);
    painter.add(egui::Shape::mesh(mesh));
}

pub fn section_card(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    egui::Frame::none()
        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
        .rounding(0.0)
        .fill(Color32::from_rgb(28, 30, 38))
        .stroke(Stroke::new(1.0, Color32::from_rgb(45, 48, 58)))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            add_contents(ui);
        });
}

pub fn score_color(score: u8) -> Color32 {
    if score >= 70 { Color32::from_rgb(220,55,55) }
    else if score >= 30 { Color32::from_rgb(220,160,40) }
    else { Color32::from_rgb(60,180,80) }
}
