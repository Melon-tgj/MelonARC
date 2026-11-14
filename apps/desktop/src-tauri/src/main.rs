//! The desktop shell.
//!
//! Its whole job is to open one window and let the page ask two questions:
//! "call this path on the core" and "where do you look for the core". Both are
//! answered by `api`, which is the only module that reads the token. No shell
//! plugin, no filesystem plugin, no network permission for the webview: the page
//! cannot reach anything but these two commands.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod settings;

fn main() {
    let settings = match settings::load() {
        Ok(settings) => settings,
        Err(error) => {
            // Without a data directory there is nothing to read and no useful
            // window to show, so say why on stderr and stop.
            eprintln!("melonarc-desktop: {error}");
            std::process::exit(1);
        }
    };

    tauri::Builder::default()
        .manage(settings)
        .invoke_handler(tauri::generate_handler![
            api::api_request,
            api::runtime_info
        ])
        .run(tauri::generate_context!())
        .expect("the window could not start");
}
