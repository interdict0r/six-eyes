use eframe::egui::{self, Color32, RichText, Vec2, Stroke, Rect};

pub fn render_titlebar(ctx: &egui::Context, file_path: Option<&str>, open_clicked: &mut bool) {
    let titlebar_bg = Color32::from_rgb(18, 20, 28);
    let is_maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));

    egui::TopBottomPanel::top("titlebar").exact_height(40.0)
        .frame(egui::Frame::none().fill(titlebar_bg).inner_margin(egui::Margin::symmetric(14.0, 0.0)))
        .show(ctx, |ui| {
            let any_hovered = ui.horizontal_centered(|ui| {
                let (icon_rect, _) = ui.allocate_exact_size(Vec2::new(20.0, 16.0), egui::Sense::hover());
                draw_eye_icon(ui, icon_rect);
                ui.add_space(6.0);
                ui.label(RichText::new("six eyes").color(Color32::from_rgb(200, 210, 230)).strong().size(15.0));
                ui.add_space(16.0);

                let sep = ui.allocate_exact_size(Vec2::new(1.0, 22.0), egui::Sense::hover()).0;
                ui.painter().rect_filled(sep, 0.0, Color32::from_rgb(45, 48, 58));
                ui.add_space(12.0);

                let open_resp = ui.add(
                    egui::Button::new(RichText::new("Open PE...").size(12.0).color(Color32::from_rgb(180, 190, 210)))
                        .fill(Color32::from_rgb(30, 34, 44))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(50, 55, 68)))
                        .rounding(3.0),
                );
                if open_resp.clicked() { *open_clicked = true; }

                if let Some(path) = file_path {
                    ui.add_space(10.0);
                    ui.label(RichText::new(super::truncate_path(path, 80))
                        .color(Color32::from_rgb(90, 95, 110)).italics().size(12.0));
                }

                let remaining = ui.available_width() - 110.0;
                if remaining > 0.0 { ui.add_space(remaining); }

                let btn_size = Vec2::new(36.0, 30.0);
                let idle = Color32::from_rgb(130, 135, 150);
                let hover_col = Color32::from_rgb(220, 225, 235);

                let min_r = window_btn(ui, btn_size);
                draw_minimize(ui, &min_r, idle, hover_col);
                if min_r.clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)); }

                let max_r = window_btn(ui, btn_size);
                draw_maximize(ui, &max_r, idle, hover_col, is_maximized, titlebar_bg);
                if max_r.clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!is_maximized)); }

                let close_r = window_btn(ui, btn_size);
                draw_close(ui, &close_r, idle);
                if close_r.clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }

                open_resp.hovered() || min_r.hovered() || max_r.hovered() || close_r.hovered()
            }).inner;

            let titlebar_rect = ui.min_rect();
            if !any_hovered {
                if let Some(pos) = ctx.input(|i| i.pointer.interact_pos()) {
                    if titlebar_rect.contains(pos) {
                        if ctx.input(|i| i.pointer.button_pressed(egui::PointerButton::Primary)) {
                            ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                        }
                        if ctx.input(|i| i.pointer.button_double_clicked(egui::PointerButton::Primary)) {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!is_maximized));
                        }
                    }
                }
            }
        });
}

fn window_btn(ui: &mut egui::Ui, size: Vec2) -> egui::Response {
    ui.add_sized(size, egui::Button::new(RichText::new("").size(1.0))
        .fill(Color32::TRANSPARENT).stroke(Stroke::NONE).rounding(0.0))
}

fn draw_minimize(ui: &egui::Ui, r: &egui::Response, idle: Color32, hover: Color32) {
    let c = r.rect.center();
    let col = if r.hovered() { hover } else { idle };
    if r.hovered() { ui.painter().rect_filled(r.rect, 0.0, Color32::from_rgba_premultiplied(255, 255, 255, 15)); }
    ui.painter().line_segment([egui::pos2(c.x - 5.0, c.y), egui::pos2(c.x + 5.0, c.y)], Stroke::new(1.4, col));
}

fn draw_maximize(ui: &egui::Ui, r: &egui::Response, idle: Color32, hover: Color32, maximized: bool, bg: Color32) {
    let c = r.rect.center();
    let col = if r.hovered() { hover } else { idle };
    if r.hovered() { ui.painter().rect_filled(r.rect, 0.0, Color32::from_rgba_premultiplied(255, 255, 255, 15)); }
    if maximized {
        let (s, off) = (4.0, 1.5);
        ui.painter().rect_stroke(Rect::from_min_size(egui::pos2(c.x - s + off, c.y - s - off), Vec2::splat(s * 2.0)), 0.0, Stroke::new(1.2, col));
        let front = Rect::from_min_size(egui::pos2(c.x - s - off + 1.0, c.y - s + off + 1.0), Vec2::splat(s * 2.0));
        ui.painter().rect_filled(front, 0.0, bg);
        ui.painter().rect_stroke(front, 0.0, Stroke::new(1.2, col));
    } else {
        ui.painter().rect_stroke(Rect::from_center_size(c, Vec2::splat(9.0)), 0.0, Stroke::new(1.2, col));
    }
}

fn draw_close(ui: &egui::Ui, r: &egui::Response, idle: Color32) {
    let c = r.rect.center();
    let col = if r.hovered() { Color32::WHITE } else { idle };
    if r.hovered() { ui.painter().rect_filled(r.rect, 0.0, Color32::from_rgb(190, 45, 45)); }
    let s = 4.5;
    ui.painter().line_segment([egui::pos2(c.x - s, c.y - s), egui::pos2(c.x + s, c.y + s)], Stroke::new(1.4, col));
    ui.painter().line_segment([egui::pos2(c.x + s, c.y - s), egui::pos2(c.x - s, c.y + s)], Stroke::new(1.4, col));
}

fn draw_eye_icon(ui: &egui::Ui, rect: Rect) {
    let c = rect.center();
    let accent = Color32::from_rgb(60, 140, 220);
    let (hw, hh) = (9.0, 5.0);
    let steps = 12;

    let glow_layers: &[(f32, u8)] = &[
        (10.0, 8), (8.0, 12), (6.0, 18), (4.5, 25),
    ];
    for &(radius, alpha) in glow_layers {
        ui.painter().circle_filled(c, radius,
            Color32::from_rgba_premultiplied(
                (accent.r() as u16 * alpha as u16 / 255) as u8,
                (accent.g() as u16 * alpha as u16 / 255) as u8,
                (accent.b() as u16 * alpha as u16 / 255) as u8,
                alpha,
            ),
        );
    }

    for i in 0..steps {
        let t0 = i as f32 / steps as f32;
        let t1 = (i + 1) as f32 / steps as f32;
        let (x0, x1) = (c.x - hw + t0 * hw * 2.0, c.x - hw + t1 * hw * 2.0);
        let (c0, c1) = (1.0 - (2.0 * t0 - 1.0).powi(2), 1.0 - (2.0 * t1 - 1.0).powi(2));
        ui.painter().line_segment([egui::pos2(x0, c.y - hh * c0), egui::pos2(x1, c.y - hh * c1)], Stroke::new(1.4, accent));
        ui.painter().line_segment([egui::pos2(x0, c.y + hh * c0), egui::pos2(x1, c.y + hh * c1)], Stroke::new(1.4, accent));
    }

    ui.painter().circle_filled(c, 3.0, accent);
    ui.painter().circle_filled(c, 1.4, Color32::from_rgb(180, 220, 255));
}
