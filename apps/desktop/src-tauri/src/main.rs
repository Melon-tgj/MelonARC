//! The desktop shell.
//!
//! It opens one window, hosts one core process and answers four kinds of
//! question: "call this path on the core", "where do you look for the core",
//! "what is the process doing" and "what are the shell settings". `api` is the
//! only module that reads the token; `settings` is the only module that writes
//! the settings file; `core` owns the child. No shell plugin, no filesystem
//! plugin, no network permission for the webview: the page cannot reach anything
//! but these commands.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod core;
mod settings;
mod single;

use tauri::Manager;

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

    // Held until the process ends; dropping it would release the lock.
    let _instance = single::acquire(&settings.data_dir);

    // Starts the first attempt before the window exists, so the page's first
    // status call already has something to report.
    let supervisor = core::CoreHandle::start(&settings);

    let app = tauri::Builder::default()
        .manage(settings)
        .manage(supervisor)
        .invoke_handler(tauri::generate_handler![
            api::api_request,
            api::runtime_info,
            core::core_status,
            core::core_restart,
            settings::get_shell_settings,
            settings::set_shell_settings
        ])
        .build(tauri::generate_context!())
        .expect("the window could not start");

    // Both events are handled because a window close asks first and a quit does
    // not; `shutdown` is idempotent, so either order is safe.
    app.run(|handle, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            handle.state::<core::CoreHandle>().shutdown();
        }
    });
}
