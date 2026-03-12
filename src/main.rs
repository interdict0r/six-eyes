#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(clippy::collapsible_if, clippy::too_many_arguments)]

mod model;
mod hashing;
mod detection;
mod parser;
mod heuristics;
mod app;
mod ui;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("six eyes")
            .with_inner_size([1100.0, 700.0])
            .with_min_inner_size([800.0, 500.0])
            .with_decorations(false)
            .with_resizable(true)
            .with_transparent(true),
        ..Default::default()
    };
    eframe::run_native(
        "six-eyes",
        options,
        Box::new(|_cc| Box::new(app::SixEyesApp::default()) as Box<dyn eframe::App>),
    )
}
