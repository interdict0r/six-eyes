use eframe::egui::{self, Color32, RichText, Vec2, Rect, Stroke};
use crate::model::*;
use crate::parser::parse_pe;
use crate::heuristics::build_heuristic_flags;
use crate::ui::*;

pub struct SixEyesApp {
    pub pe:                       Option<PeInfo>,
    pub active_tab:               Tab,
    pub last_tab:                 Tab,
    pub string_filter:            String,
    pub string_kind_filter:       StringKindFilter,
    pub heuristic_flags:          Vec<crate::heuristics::HeuristicFlag>,
    pub threat_score:             u8,
    pub disasm_goto:              String,
    pub disasm_search:            String,
    pub disasm_scroll_to:         Option<usize>,
    pub disasm_scroll_target_px:  Option<f32>,
    pub disasm_scroll_current_px: f32,
    pub disasm_settings:          DisasmSettings,
    pub tab_anim:                 f32,
    pub tab_underline_x:          f32,
    pub tab_underline_w:          f32,
}

impl Default for SixEyesApp {
    fn default() -> Self {
        Self {
            pe: None,
            active_tab: Tab::Overview,
            last_tab: Tab::Overview,
            string_filter: String::new(),
            string_kind_filter: StringKindFilter::All,
            heuristic_flags: Vec::new(),
            threat_score: 0,
            disasm_goto: String::new(),
            disasm_search: String::new(),
            disasm_scroll_to: None,
            disasm_scroll_target_px: None,
            disasm_scroll_current_px: 0.0,
            disasm_settings: DisasmSettings::default(),
            tab_anim: 1.0,
            tab_underline_x: 0.0,
            tab_underline_w: 0.0,
        }
    }
}

impl SixEyesApp {
    fn load(&mut self, pe: PeInfo) {
        drop(self.pe.take());
        self.heuristic_flags = build_heuristic_flags(&pe);
        self.threat_score    = compute_threat_score(&self.heuristic_flags);
        self.pe                 = Some(pe);
        self.active_tab         = Tab::Overview;
        self.last_tab           = Tab::Overview;
        self.tab_anim           = 0.0;
        self.tab_underline_x    = 0.0;
        self.tab_underline_w    = 0.0;
        self.string_filter.clear();
        self.string_kind_filter = StringKindFilter::All;
        self.disasm_goto.clear();
        self.disasm_search.clear();
        self.disasm_scroll_to = None;
        self.disasm_scroll_target_px = None;
        self.disasm_scroll_current_px = 0.0;
    }
}

fn compute_threat_score(flags: &[crate::heuristics::HeuristicFlag]) -> u8 {
    use crate::heuristics::Severity;
    let (crits, warns, infos) = flags.iter().fold((0usize, 0usize, 0usize), |(c, w, i), f| {
        match f.severity {
            Severity::Critical => (c + 1, w, i),
            Severity::Warn     => (c, w + 1, i),
            Severity::Info     => (c, w, i + 1),
        }
    });
    (crits * 25 + warns * 10 + infos * 2).min(100) as u8
}

impl eframe::App for SixEyesApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());

        let mut style = (*ctx.style()).clone();
        style.interaction.selectable_labels = false;
        style.spacing.scroll = egui::style::ScrollStyle::solid();
        style.spacing.scroll.bar_outer_margin = 0.0;
        style.spacing.scroll.bar_inner_margin = 2.0;
        style.spacing.scroll.bar_width = 8.0;
        style.visuals.widgets.noninteractive.rounding = egui::Rounding::ZERO;
        style.visuals.widgets.inactive.rounding = egui::Rounding::ZERO;
        style.visuals.widgets.hovered.rounding = egui::Rounding::ZERO;
        style.visuals.widgets.active.rounding = egui::Rounding::ZERO;
        style.visuals.widgets.open.rounding = egui::Rounding::ZERO;
        style.visuals.window_rounding = egui::Rounding::ZERO;
        style.visuals.menu_rounding = egui::Rounding::ZERO;
        ctx.set_style(style);

        if self.last_tab != self.active_tab {
            self.tab_anim = 0.0;
            self.last_tab = self.active_tab;
        }

        let dt = ctx.input(|i| i.stable_dt);
        if self.tab_anim < 1.0 {
            self.tab_anim = (self.tab_anim + dt / 0.3).min(1.0);
            ctx.request_repaint();
        }

        let mut open_clicked = false;
        titlebar::render_titlebar(ctx, self.pe.as_ref().map(|p| p.path.as_str()), &mut open_clicked);
        if open_clicked {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Executables", &["exe","dll","sys","ocx","scr"])
                .add_filter("All files", &["*"])
                .pick_file()
            {
                self.load(parse_pe(path.to_str().unwrap_or("")));
            }
        }

        egui::TopBottomPanel::top("title_sep").exact_height(1.0)
            .frame(egui::Frame::none().fill(Color32::from_rgb(45, 50, 65)))
            .show(ctx, |_ui| {});

        if let Some(err) = self.pe.as_ref().and_then(|p| p.error.as_ref()) {
            let msg = format!("  {err}");
            egui::TopBottomPanel::bottom("errorbar").exact_height(26.0).show(ctx, |ui| {
                ui.label(RichText::new(msg).color(Color32::RED).size(13.0));
            });
        }

        egui::TopBottomPanel::top("tabs").exact_height(34.0)
            .frame(egui::Frame::none().fill(Color32::from_rgb(22, 24, 32)).inner_margin(egui::Margin::symmetric(8.0, 0.0)))
            .show(ctx, |ui| {
                let tab_bar_rect = ui.clip_rect();
                let mut target_x = 0.0f32;
                let mut target_w = 0.0f32;

                ui.horizontal_centered(|ui| {
                    let tabs = [
                        (Tab::Overview,   "Overview"),
                        (Tab::Imports,    "Imports"),
                        (Tab::Strings,    "Strings"),
                        (Tab::Heuristics, "Heuristics"),
                        (Tab::HexView,    "Hex"),
                        (Tab::Disasm,     "Disasm"),
                    ];
                    for (tab, label) in &tabs {
                        let resp = tab_btn(ui, &mut self.active_tab, *tab, label);
                        if *tab == self.active_tab {
                            target_x = resp.rect.min.x;
                            target_w = resp.rect.width();
                        }
                    }
                });

                if self.tab_underline_w == 0.0 {
                    self.tab_underline_x = target_x;
                    self.tab_underline_w = target_w;
                }

                let lerp_speed = 12.0 * dt;
                self.tab_underline_x += (target_x - self.tab_underline_x) * lerp_speed.min(1.0);
                self.tab_underline_w += (target_w - self.tab_underline_w) * lerp_speed.min(1.0);

                if (self.tab_underline_x - target_x).abs() > 0.5
                    || (self.tab_underline_w - target_w).abs() > 0.5 {
                    ctx.request_repaint();
                }

                let line_y = tab_bar_rect.max.y - 2.0;
                let line_rect = Rect::from_min_size(
                    egui::pos2(self.tab_underline_x, line_y),
                    Vec2::new(self.tab_underline_w, 2.0),
                );
                if line_rect.is_positive() {
                    paint_h_gradient(ui.painter(), line_rect,
                        Color32::from_rgb(60, 140, 220),
                        Color32::from_rgb(100, 200, 255));
                }
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(ctx.style().visuals.panel_fill))
            .show(ctx, |ui| {
                let t = ease_out_cubic(self.tab_anim);
                let offset = (1.0 - t) * 16.0;

                if offset > 0.1 {
                    ui.add_space(offset);
                }

                match &self.pe {
                    None => {
                        ui.centered_and_justified(|ui| {
                            ui.label(RichText::new("Drop a PE file or click Open PE...").size(22.0).weak());
                        });
                    }
                    Some(pe) => match self.active_tab {
                        Tab::Overview   => overview::render_overview(ui, pe, self.threat_score),
                        Tab::Imports    => imports::render_imports(ui, pe),
                        Tab::Strings    => strings::render_strings(ui, pe, &mut self.string_filter, &mut self.string_kind_filter),
                        Tab::Heuristics => heuristics::render_heuristics(ui, &self.heuristic_flags),
                        Tab::HexView    => hexview::render_hexview(ui, pe),
                        Tab::Disasm     => disasm::render_disasm(ui, pe, &mut self.disasm_goto, &mut self.disasm_search, &mut self.disasm_scroll_to, &mut self.disasm_scroll_target_px, &mut self.disasm_scroll_current_px, &mut self.disasm_settings),
                    },
                }
            });

        let is_maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
        if !is_maximized {
            let screen = ctx.screen_rect();
            let accent = Color32::from_rgb(60, 140, 220);
            let border_color = Color32::from_rgb(55, 65, 85);
            let fg_painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("window_border")));
            fg_painter.rect_stroke(screen.expand(0.5), 0.0, Stroke::new(1.0,
                Color32::from_rgba_premultiplied(
                    (accent.r() as u16 * 40 / 255) as u8,
                    (accent.g() as u16 * 40 / 255) as u8,
                    (accent.b() as u16 * 40 / 255) as u8,
                    40,
                ),
            ));
            fg_painter.rect_stroke(screen, 0.0, Stroke::new(1.0, border_color));
        }
    }
}
