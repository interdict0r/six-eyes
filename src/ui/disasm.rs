use eframe::egui::{self, Color32, Pos2, Rect, RichText, Stroke, Ui};
use crate::model::*;

const ARC_COL_W: f32 = 60.0;
const ARC_STEP: f32 = 7.0;

const COL_REGISTER:   Color32 = Color32::from_rgb(220, 120, 150);
const COL_NUMBER:     Color32 = Color32::from_rgb(100, 200, 170);
const COL_MEMORY:     Color32 = Color32::from_rgb(160, 140, 200);
const COL_SIZE_KW:    Color32 = Color32::from_rgb(110, 120, 140);
const COL_COMMA:      Color32 = Color32::from_rgb(110, 115, 130);
const COL_COMMENT:    Color32 = Color32::from_rgb(100, 160, 80);
const COL_ADDR_RVA:   Color32 = Color32::from_rgb(100, 170, 255);
const COL_ADDR_FUNC:  Color32 = Color32::from_rgb(180, 140, 255);
const COL_HEX:        Color32 = Color32::from_rgb(100, 100, 120);
const COL_SYMBOL:     Color32 = Color32::from_rgb(220, 180, 100);
const COL_LINK:       Color32 = Color32::from_rgb(80, 180, 255);


pub fn render_disasm(
    ui: &mut Ui,
    pe: &PeInfo,
    goto_buf: &mut String,
    search_buf: &mut String,
    scroll_to: &mut Option<usize>,
    scroll_target_px: &mut Option<f32>,
    scroll_current_px: &mut f32,
    settings: &mut DisasmSettings,
) {
    if pe.buffer.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("No file data available.").weak().size(14.0));
        });
        return;
    }

    if pe.disasm_lines.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("Cannot resolve entry point to file offset.").weak().size(14.0));
        });
        return;
    }

    let meta = pe.disasm_meta.as_ref();
    let lines = &pe.disasm_lines;

    egui::Frame::none()
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .fill(Color32::from_rgb(25, 27, 35))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                let btn = |ui: &mut Ui, label: &str, color: Color32| -> bool {
                    let rt = RichText::new(label).size(11.0).color(color);
                    ui.add(egui::Button::new(rt).fill(Color32::TRANSPARENT)).clicked()
                };

                if let Some(m) = meta {
                    if let Some(uc_idx) = m.user_code {
                        if btn(ui, "[ User Code ]", Color32::from_rgb(100, 220, 160)) {
                            *scroll_to = Some(uc_idx);
                        }
                    }
                }

                if btn(ui, "[ EP ]", Color32::from_rgb(100, 170, 255)) {
                    *scroll_to = Some(0);
                }

                if let Some(m) = meta {
                    if !m.func_starts.is_empty() {
                        ui.separator();
                        let func_label = format!("Functions ({})", m.func_starts.len());
                        let menu_rt = RichText::new(func_label).size(11.0).color(Color32::from_rgb(180, 160, 220));
                        let use_rva = settings.use_rva;
                        let image_base = pe.image_base;
                        ui.menu_button(menu_rt, |ui| {
                            ui.set_max_height(300.0);
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                for (i, &fi) in m.func_starts.iter().enumerate() {
                                    let addr_str = format_addr(&lines[fi], use_rva, image_base);
                                    let sym = if !lines[fi].comment.is_empty() {
                                        format!("  {}", &lines[fi].comment)
                                    } else {
                                        String::new()
                                    };
                                    let label = format!("#{:<3} {}{}", i + 1, addr_str, sym);
                                    let rt = RichText::new(label).monospace().size(11.0).color(Color32::from_rgb(180, 160, 220));
                                    if ui.add(egui::Button::new(rt).fill(Color32::TRANSPARENT)).clicked() {
                                        *scroll_to = Some(fi);
                                        ui.close_menu();
                                    }
                                }
                            });
                        });
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let dim = Color32::from_rgb(120, 125, 140);
                    let tog = |ui: &mut Ui, val: &mut bool, label: &str| {
                        let rt = RichText::new(label).size(10.0).color(if *val { Color32::from_rgb(170, 180, 200) } else { dim });
                        ui.add(egui::Checkbox::without_text(val));
                        ui.label(rt);
                    };
                    tog(ui, &mut settings.show_arcs,     "Arcs");
                    tog(ui, &mut settings.show_comments, "Comments");
                    tog(ui, &mut settings.show_hex,      "Hex");
                    tog(ui, &mut settings.rel_addr,      "Rel");
                    tog(ui, &mut settings.use_rva,       "RVA");
                });
            });

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(RichText::new("Go to:").weak().size(11.0));
                let goto_resp = ui.add(
                    egui::TextEdit::singleline(goto_buf)
                        .desired_width(100.0)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("address (hex)")
                );
                if goto_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if let Some(idx) = resolve_goto(lines, goto_buf.trim()) {
                        *scroll_to = Some(idx);
                    }
                }

                ui.label(RichText::new("Search:").weak().size(11.0));
                ui.add(
                    egui::TextEdit::singleline(search_buf)
                        .desired_width(150.0)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("mnemonic / symbol")
                );

                if !search_buf.is_empty() {
                    let needle = search_buf.to_ascii_lowercase();
                    let matches: usize = lines.iter()
                        .filter(|l| l.mnemonic.to_ascii_lowercase().contains(&needle) || l.comment.to_ascii_lowercase().contains(&needle))
                        .count();
                    ui.label(RichText::new(format!("{matches} hits")).weak().size(11.0));
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(m) = meta {
                        let stats = format!(
                            "{} insns | {} calls  {} jmps  {} rets  {} nops",
                            lines.len(), m.calls, m.jumps, m.rets, m.nops
                        );
                        ui.label(RichText::new(stats).weak().size(10.0));
                    }
                });
            });
        });

    ui.add(egui::Separator::default().spacing(0.0));

    let row_height = 15.0;
    let search_active = !search_buf.is_empty();
    let needle = search_buf.to_ascii_lowercase();

    let filtered: Vec<usize> = if search_active {
        lines.iter().enumerate()
            .filter(|(_, l)| l.mnemonic.to_ascii_lowercase().contains(&needle) || l.comment.to_ascii_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect()
    } else {
        Vec::new()
    };

    let display_count = if search_active { filtered.len() } else { lines.len() };

    let dt = ui.ctx().input(|i| i.stable_dt);

    if let Some(target_idx) = scroll_to.take() {
        let row = if search_active {
            filtered.iter().position(|&i| i >= target_idx).unwrap_or(0)
        } else {
            target_idx.min(display_count.saturating_sub(1))
        };
        *scroll_target_px = Some(row as f32 * row_height);
    }

    let mut scroll_area = egui::ScrollArea::vertical()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
        .auto_shrink([false, false]);

    if let Some(target) = *scroll_target_px {
        let speed = 12.0 * dt;
        *scroll_current_px += (target - *scroll_current_px) * speed.min(1.0);
        if (*scroll_current_px - target).abs() < 0.5 {
            *scroll_current_px = target;
            *scroll_target_px = None;
        } else {
            ui.ctx().request_repaint();
        }
        scroll_area = scroll_area.vertical_scroll_offset(*scroll_current_px);
    }

    let s_show_hex      = settings.show_hex;
    let s_show_arcs     = settings.show_arcs;
    let s_show_comments = settings.show_comments;
    let s_use_rva       = settings.use_rva;
    let s_max_span      = settings.max_arc_span;
    let s_rel_addr      = settings.rel_addr;
    let image_base      = pe.image_base;
    let user_code_idx   = meta.and_then(|m| m.user_code);

    let output = scroll_area.show_rows(ui, row_height, display_count, |ui, row_range| {
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
        let first_ip = lines.first().map(|l| l.ip).unwrap_or(0);
        let last_ip  = lines.last().map(|l| l.ip).unwrap_or(0);

        let mut row_ys: Vec<(usize, f32)> = Vec::with_capacity(row_range.len());
        let painter = ui.painter().clone();

        let mut arc_gutter_left_x: f32 = 0.0;
        let mut arc_gutter_right_x: f32 = 0.0;

        let mut arc_endpoints: std::collections::HashMap<usize, (bool, bool, Color32)> =
            std::collections::HashMap::new();
        if let Some(m) = meta {
            if !search_active && s_show_arcs {
                for arc in &m.arcs {
                    let lo = arc.from.min(arc.to);
                    let hi = arc.from.max(arc.to);
                    if hi - lo > s_max_span { continue; }
                    let color = arc_color(arc.kind);
                    if arc.from >= row_range.start && arc.from < row_range.end {
                        let e = arc_endpoints.entry(arc.from).or_insert((false, false, color));
                        e.0 = true;
                    }
                    if arc.to >= row_range.start && arc.to < row_range.end {
                        let e = arc_endpoints.entry(arc.to).or_insert((false, false, color));
                        e.1 = true;
                    }
                }
            }
        }

        for row in row_range.clone() {
            let line_idx = if search_active { filtered[row] } else { row };
            let line = &lines[line_idx];

            if !search_active {
                let is_ep = line_idx == 0;
                let is_uc = user_code_idx == Some(line_idx);
                if is_ep || is_uc {
                    if is_ep {
                        let rect = ui.available_rect_before_wrap();
                        let banner_rect = Rect::from_min_size(rect.min, egui::vec2(rect.width(), row_height));
                        painter.rect_filled(banner_rect, 0.0, Color32::from_rgba_premultiplied(30, 50, 80, 80));
                        let text_pos = Pos2::new(rect.min.x + 4.0, rect.min.y + 1.0);
                        painter.text(text_pos, egui::Align2::LEFT_TOP,
                            "\u{25B6} Entry Point",
                            egui::FontId::monospace(10.0),
                            COL_ADDR_RVA);
                        ui.allocate_space(egui::vec2(0.0, row_height));
                    }
                    if is_uc {
                        let rect = ui.available_rect_before_wrap();
                        let banner_rect = Rect::from_min_size(rect.min, egui::vec2(rect.width(), row_height));
                        painter.rect_filled(banner_rect, 0.0, Color32::from_rgba_premultiplied(30, 70, 50, 80));
                        let text_pos = Pos2::new(rect.min.x + 4.0, rect.min.y + 1.0);
                        painter.text(text_pos, egui::Align2::LEFT_TOP,
                            "\u{25B6} User Code",
                            egui::FontId::monospace(10.0),
                            Color32::from_rgb(100, 220, 160));
                        ui.allocate_space(egui::vec2(0.0, row_height));
                    }
                }
            }

            if line.is_prologue && row > 0 {
                let rect = ui.available_rect_before_wrap();
                let y = rect.min.y;
                draw_dashed_hline(&painter, y, rect.min.x, rect.max.x,
                    Stroke::new(1.0, Color32::from_rgb(70, 75, 100)), 4.0, 3.0);
            }

            let row_top = ui.cursor().min.y;
            let row_cy = row_top + row_height * 0.5;
            row_ys.push((line_idx, row_cy));

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;

                let addr_str = format_addr(line, s_use_rva, image_base);
                let addr_color = if line.is_prologue { COL_ADDR_FUNC } else { COL_ADDR_RVA };
                ui.label(RichText::new(&addr_str).monospace().size(11.0).color(addr_color));
                ui.add_space(4.0);

                let gutter_left = ui.cursor().min.x;
                if s_show_arcs && !search_active {
                    ui.add_space(ARC_COL_W);
                    ui.add_space(6.0); // gap so arc endings don't overlap hex data
                }
                let gutter_right = if s_show_arcs && !search_active {
                    ui.cursor().min.x - 6.0 // right edge excludes the gap
                } else {
                    ui.cursor().min.x
                };
                arc_gutter_left_x = gutter_left;
                arc_gutter_right_x = gutter_right;

                if s_show_hex {
                    let hex_display = if line.hex_bytes.len() > 24 {
                        format!("{:<24}", &line.hex_bytes[..24])
                    } else {
                        format!("{:<24}", line.hex_bytes)
                    };
                    ui.label(RichText::new(hex_display).monospace().size(11.0).color(COL_HEX));
                    ui.add_space(4.0);
                }

                let opcode_display = format!("{:<7}", line.opcode);
                let opcode_color = line.kind.color();
                ui.label(RichText::new(&opcode_display).monospace().size(11.0).color(opcode_color));
                ui.add_space(2.0);

                if !line.operands.is_empty() {
                    render_operands(ui, &line.operands, line, first_ip, last_ip, lines, scroll_to, s_rel_addr);
                }

                if s_show_comments && !line.comment.is_empty() {
                    ui.add_space(8.0);
                    let (prefix, color) = if line.comment.starts_with('"') {
                        ("; ", COL_COMMENT)
                    } else {
                        ("; ", COL_SYMBOL)
                    };
                    let comment_text = format!("{}{}", prefix, line.comment);
                    ui.label(RichText::new(comment_text).monospace().size(11.0).color(color));
                }
            });
        }

        if let Some(m) = meta {
            if !search_active && s_show_arcs {
                let vis_lo = row_range.start;
                let vis_hi = row_range.end.saturating_sub(1);
                let mut idx_to_y: std::collections::HashMap<usize, f32> = std::collections::HashMap::with_capacity(row_ys.len());
                for &(idx, cy) in &row_ys {
                    idx_to_y.insert(idx, cy);
                }

                let right_edge = arc_gutter_right_x;
                let gutter_left = arc_gutter_left_x;

                for (&line_idx, &(is_src, is_dst, color)) in &arc_endpoints {
                    if let Some(&cy) = idx_to_y.get(&line_idx) {
                        let marker_x = right_edge - 6.0;
                        let marker_top = cy - row_height * 0.5;
                        if is_dst {
                            painter.rect_filled(
                                Rect::from_min_size(Pos2::new(marker_x, marker_top), egui::vec2(3.0, row_height)),
                                0.0, color,
                            );
                        } else if is_src {
                            let dim = Color32::from_rgba_premultiplied(
                                color.r() / 2, color.g() / 2, color.b() / 2, 160,
                            );
                            painter.rect_filled(
                                Rect::from_min_size(Pos2::new(marker_x, marker_top), egui::vec2(2.0, row_height)),
                                0.0, dim,
                            );
                        }
                    }
                }

                let mut arc_order: Vec<usize> = (0..m.arcs.len()).collect();
                arc_order.sort_by(|&a, &b| m.arcs[b].col.cmp(&m.arcs[a].col));

                for &arc_i in &arc_order {
                    let arc = &m.arcs[arc_i];
                    let lo = arc.from.min(arc.to);
                    let hi = arc.from.max(arc.to);
                    if hi < vis_lo || lo > vis_hi { continue; }
                    if hi - lo > s_max_span { continue; }

                    let col_x = gutter_left + (arc.col as f32 + 1.0) * ARC_STEP;
                    let color = arc_color(arc.kind);
                    let is_dashed = arc.kind == InstrKind::CondJump;

                    let first_vis_y = row_ys.first().map(|&(_, y)| y).unwrap_or(0.0);
                    let last_vis_y  = row_ys.last().map(|&(_, y)| y).unwrap_or(0.0);

                    let from_y = idx_to_y.get(&arc.from).copied()
                        .unwrap_or(if arc.from < vis_lo { first_vis_y - 8.0 } else { last_vis_y + 8.0 });
                    let to_y = idx_to_y.get(&arc.to).copied()
                        .unwrap_or(if arc.to < vis_lo { first_vis_y - 8.0 } else { last_vis_y + 8.0 });

                    let (top_y, bot_y) = if from_y < to_y { (from_y, to_y) } else { (to_y, from_y) };

                    // Hit rects: vertical column strip + horizontal ticks at endpoints
                    let vert_hit = Rect::from_min_max(
                        Pos2::new(col_x - 3.0, top_y),
                        Pos2::new(col_x + 3.0, bot_y),
                    );
                    let arc_id = egui::Id::new("arc").with(arc_i);
                    let vert_resp = ui.interact(vert_hit, arc_id, egui::Sense::click());
                    let hovered = vert_resp.hovered();

                    let arc_end = right_edge - 3.0;

                    let from_hovered = if idx_to_y.contains_key(&arc.from) {
                        let tick_hit = Rect::from_min_max(
                            Pos2::new(col_x, from_y - 2.0),
                            Pos2::new(arc_end, from_y + 2.0),
                        );
                        let r = ui.interact(tick_hit, arc_id.with("from"), egui::Sense::click());
                        if r.clicked() { *scroll_to = Some(arc.to); }
                        r.hovered()
                    } else { false };

                    let to_hovered = if idx_to_y.contains_key(&arc.to) {
                        let tick_hit = Rect::from_min_max(
                            Pos2::new(col_x, to_y - 2.0),
                            Pos2::new(arc_end, to_y + 2.0),
                        );
                        let r = ui.interact(tick_hit, arc_id.with("to"), egui::Sense::click());
                        if r.clicked() { *scroll_to = Some(arc.from); }
                        r.hovered()
                    } else { false };

                    let any_hover = hovered || from_hovered || to_hovered;
                    let draw_color = if any_hover { brighten(color, 80) } else { color };
                    let stroke = Stroke::new(if any_hover { 1.5 } else { 1.0 }, draw_color);

                    if idx_to_y.contains_key(&arc.from) {
                        if is_dashed {
                            draw_dashed_hline(&painter, from_y, col_x, arc_end, stroke, 3.0, 2.0);
                        } else {
                            painter.line_segment([Pos2::new(col_x, from_y), Pos2::new(arc_end, from_y)], stroke);
                        }
                        painter.circle_filled(Pos2::new(arc_end, from_y), 2.0, draw_color);
                    }

                    if is_dashed {
                        draw_dashed_vline(&painter, col_x, top_y, bot_y, stroke, 3.0, 2.0);
                    } else {
                        painter.line_segment([Pos2::new(col_x, top_y), Pos2::new(col_x, bot_y)], stroke);
                    }

                    if idx_to_y.contains_key(&arc.to) {
                        if is_dashed {
                            draw_dashed_hline(&painter, to_y, col_x, arc_end, stroke, 3.0, 2.0);
                        } else {
                            painter.line_segment([Pos2::new(col_x, to_y), Pos2::new(arc_end, to_y)], stroke);
                        }
                        let ax = arc_end;
                        let ay = to_y;
                        painter.line_segment([Pos2::new(ax - 4.0, ay - 3.0), Pos2::new(ax, ay)], stroke);
                        painter.line_segment([Pos2::new(ax - 4.0, ay + 3.0), Pos2::new(ax, ay)], stroke);
                    }

                    if vert_resp.clicked() {
                        *scroll_to = Some(arc.to);
                    }

                    if any_hover {
                        let kind_label = match arc.kind {
                            InstrKind::Call     => "Call",
                            InstrKind::Jump     => "Jump",
                            InstrKind::CondJump => "Cond. jump",
                            _                   => "Branch",
                        };
                        let src_addr = format_addr(&lines[arc.from], s_use_rva, image_base);
                        let dst_addr = format_addr(&lines[arc.to], s_use_rva, image_base);
                        let tip = format!("{kind_label}: {src_addr} -> {dst_addr}\nClick to follow");
                        vert_resp.on_hover_text(tip);
                    }
                }
            }
        }
    });

    if scroll_target_px.is_none() {
        *scroll_current_px = output.state.offset.y;
    }
}

fn render_operands(
    ui: &mut Ui,
    operands: &str,
    line: &DisasmLine,
    first_ip: u64,
    last_ip: u64,
    all_lines: &[DisasmLine],
    scroll_to: &mut Option<usize>,
    rel_addr: bool,
) {
    let tokens = tokenize_operands(operands);

    let clickable_target = if matches!(line.kind, InstrKind::Call | InstrKind::Jump | InstrKind::CondJump) {
        line.target.filter(|&t| t >= first_ip && t <= last_ip)
    } else {
        None
    };

    for tok in &tokens {
        let (text, color) = match tok {
            OpToken::Register(s)  => (*s, COL_REGISTER),
            OpToken::Number(s)    => (*s, COL_NUMBER),
            OpToken::Bracket(s)   => (*s, COL_MEMORY),
            OpToken::SizeKw(s)    => (*s, COL_SIZE_KW),
            OpToken::Comma        => (",", COL_COMMA),
            OpToken::Plus         => ("+", COL_COMMA),
            OpToken::Minus        => ("-", COL_COMMA),
            OpToken::Star         => ("*", COL_COMMA),
            OpToken::Other(s)     => (*s, Color32::from_rgb(210, 210, 220)),
            OpToken::Space(s)     => {
                ui.add_space(s.len() as f32 * 3.0);
                continue;
            }
        };

        if let OpToken::Number(_) = tok {
            if let Some(target) = clickable_target {
                let tgt_idx = all_lines.iter().position(|l| l.ip == target);
                let display_text = if rel_addr {
                    let offset = target as i64 - line.ip as i64;
                    if offset >= 0 {
                        format!("+{:X}h", offset)
                    } else {
                        format!("-{:X}h", -offset)
                    }
                } else {
                    text.to_string()
                };
                let rt = RichText::new(&display_text).monospace().size(11.0).color(COL_LINK).underline();
                let resp = ui.add(egui::Label::new(rt).sense(egui::Sense::click()));
                let is_hovered = resp.hovered();
                let is_dbl = resp.double_clicked();

                if is_hovered {
                    let rect = resp.rect;
                    ui.painter().rect_filled(
                        rect.expand2(egui::vec2(2.0, 1.0)),
                        2.0,
                        Color32::from_rgba_premultiplied(30, 60, 90, 120),
                    );

                    let mut tip = format!("Double-click to jump to {:X}h", target);
                    if let Some(idx) = tgt_idx {
                        let dst = &all_lines[idx];
                        if dst.is_prologue {
                            tip.push_str("\n  Function prologue");
                        }
                        if !dst.comment.is_empty() {
                            tip.push_str(&format!("\n  {}", dst.comment));
                        }
                        tip.push_str(&format!("\n  {} {}", dst.opcode, dst.operands));
                    }
                    resp.on_hover_text(tip);
                }

                if is_dbl {
                    if let Some(idx) = tgt_idx {
                        *scroll_to = Some(idx);
                    }
                }
                continue;
            }
        }

        ui.add(egui::Label::new(RichText::new(text).monospace().size(11.0).color(color)));
    }
}

#[derive(Debug)]
enum OpToken<'a> {
    Register(&'a str),
    Number(&'a str),
    Bracket(&'a str),
    SizeKw(&'a str),
    Comma,
    Plus,
    Minus,
    Star,
    Space(&'a str),
    Other(&'a str),
}

fn tokenize_operands(text: &str) -> Vec<OpToken<'_>> {
    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let b = bytes[i];
        match b {
            b'[' => { tokens.push(OpToken::Bracket(&text[i..i+1])); i += 1; }
            b']' => { tokens.push(OpToken::Bracket(&text[i..i+1])); i += 1; }
            b',' => { tokens.push(OpToken::Comma); i += 1; }
            b'+' => { tokens.push(OpToken::Plus); i += 1; }
            b'-' => { tokens.push(OpToken::Minus); i += 1; }
            b'*' => { tokens.push(OpToken::Star); i += 1; }
            b' ' | b'\t' => {
                let start = i;
                while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') { i += 1; }
                tokens.push(OpToken::Space(&text[start..i]));
            }
            _ => {
                let start = i;
                while i < len && bytes[i] != b' ' && bytes[i] != b'\t'
                    && bytes[i] != b',' && bytes[i] != b'[' && bytes[i] != b']'
                    && bytes[i] != b'+' && bytes[i] != b'-' && bytes[i] != b'*'
                {
                    i += 1;
                }
                let word = &text[start..i];
                tokens.push(classify_word(word));
            }
        }
    }
    tokens
}

fn classify_word(word: &str) -> OpToken<'_> {
    let lower = word.to_ascii_lowercase();

    match lower.as_str() {
        "byte" | "word" | "dword" | "qword" | "ptr" | "tbyte" | "fword"
        | "xmmword" | "ymmword" | "zmmword" | "oword" | "short" | "near" | "far" => {
            return OpToken::SizeKw(word);
        }
        _ => {}
    }

    if is_register(&lower) {
        return OpToken::Register(word);
    }

    if is_number(word) {
        return OpToken::Number(word);
    }

    OpToken::Other(word)
}

fn is_register(lower: &str) -> bool {
    matches!(lower,
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp"
        | "r8" | "r9" | "r10" | "r11" | "r12" | "r13" | "r14" | "r15"
        | "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp"
        | "r8d" | "r9d" | "r10d" | "r11d" | "r12d" | "r13d" | "r14d" | "r15d"
        | "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp"
        | "r8w" | "r9w" | "r10w" | "r11w" | "r12w" | "r13w" | "r14w" | "r15w"
        | "al" | "ah" | "bl" | "bh" | "cl" | "ch" | "dl" | "dh"
        | "sil" | "dil" | "bpl" | "spl"
        | "r8b" | "r9b" | "r10b" | "r11b" | "r12b" | "r13b" | "r14b" | "r15b"
        | "cs" | "ds" | "es" | "fs" | "gs" | "ss"
        | "cr0" | "cr2" | "cr3" | "cr4" | "cr8"
        | "dr0" | "dr1" | "dr2" | "dr3" | "dr6" | "dr7"
        | "rip" | "eip" | "ip" | "rflags" | "eflags" | "flags"
        | "xmm0" | "xmm1" | "xmm2" | "xmm3" | "xmm4" | "xmm5" | "xmm6" | "xmm7"
        | "xmm8" | "xmm9" | "xmm10" | "xmm11" | "xmm12" | "xmm13" | "xmm14" | "xmm15"
        | "ymm0" | "ymm1" | "ymm2" | "ymm3" | "ymm4" | "ymm5" | "ymm6" | "ymm7"
        | "ymm8" | "ymm9" | "ymm10" | "ymm11" | "ymm12" | "ymm13" | "ymm14" | "ymm15"
        | "st0" | "st1" | "st2" | "st3" | "st4" | "st5" | "st6" | "st7"
        | "st(0)" | "st(1)" | "st(2)" | "st(3)" | "st(4)" | "st(5)" | "st(6)" | "st(7)"
    )
}

fn is_number(word: &str) -> bool {
    if word.is_empty() { return false; }
    if word.ends_with('h') || word.ends_with('H') {
        let core = &word[..word.len() - 1];
        return !core.is_empty() && core.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if word.starts_with("0x") || word.starts_with("0X") {
        return word[2..].bytes().all(|b| b.is_ascii_hexdigit());
    }
    word.bytes().all(|b| b.is_ascii_digit())
}

fn format_addr(line: &DisasmLine, use_rva: bool, _image_base: u64) -> String {
    if use_rva {
        format!("{:08X}", line.rva)
    } else {
        format!("{:016X}", line.ip)
    }
}

fn arc_color(kind: InstrKind) -> Color32 {
    match kind {
        InstrKind::Call     => Color32::from_rgb(200, 140, 60),
        InstrKind::Jump     => Color32::from_rgb(80, 180, 80),
        InstrKind::CondJump => Color32::from_rgb(160, 180, 60),
        _                   => Color32::from_rgb(120, 120, 140),
    }
}

#[inline]
fn brighten(c: Color32, amount: u8) -> Color32 {
    Color32::from_rgb(
        c.r().saturating_add(amount),
        c.g().saturating_add(amount),
        c.b().saturating_add(amount),
    )
}

fn draw_dashed_hline(painter: &egui::Painter, y: f32, x0: f32, x1: f32, stroke: Stroke, dash: f32, gap: f32) {
    let mut x = x0;
    while x < x1 {
        let end = (x + dash).min(x1);
        painter.line_segment([Pos2::new(x, y), Pos2::new(end, y)], stroke);
        x = end + gap;
    }
}

fn draw_dashed_vline(painter: &egui::Painter, x: f32, y0: f32, y1: f32, stroke: Stroke, dash: f32, gap: f32) {
    let mut y = y0;
    while y < y1 {
        let end = (y + dash).min(y1);
        painter.line_segment([Pos2::new(x, y), Pos2::new(x, end)], stroke);
        y = end + gap;
    }
}

fn resolve_goto(lines: &[DisasmLine], input: &str) -> Option<usize> {
    let clean = input.trim_start_matches("0x").trim_start_matches("0X");
    let addr = u64::from_str_radix(clean, 16).ok()?;
    if let Some(idx) = lines.iter().position(|l| l.ip == addr) {
        return Some(idx);
    }
    if let Some(idx) = lines.iter().position(|l| l.rva as u64 == addr) {
        return Some(idx);
    }
    lines.iter().position(|l| l.ip >= addr)
}
