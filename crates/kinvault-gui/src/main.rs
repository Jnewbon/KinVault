//! KinVault desktop app. A window and tray icon on top of `kinvaultd`: all
//! backup work happens in the daemon, so closing the window (or quitting the
//! app) never stops backups.

// No console window on Windows release builds.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use kinvault_daemon::api::{Reply, Request};
use kinvault_daemon::ipc::{self, Client};
use kinvault_daemon::{recovery, service};
use serde_json::Value;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::oneshot;

struct AppState {
    state_dir: PathBuf,
    /// Set when the state directory isn't the default, so a started daemon uses it too.
    custom_state: bool,
}

impl AppState {
    fn daemon_state_arg(&self) -> Option<&Path> {
        self.custom_state.then_some(self.state_dir.as_path())
    }
}

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    format!("{e:#}")
}

/// Sends one control request to the daemon. `request` uses the daemon's JSON
/// format, e.g. `{"method": "backup_now", "params": {"set": "docs"}}`.
#[tauri::command]
async fn daemon_call(state: State<'_, AppState>, request: Value) -> CmdResult<Value> {
    let request: Request =
        serde_json::from_value(request).map_err(|e| format!("bad request: {e}"))?;
    let mut client = Client::connect(&state.state_dir).await.map_err(err)?;
    let reply = client.call(&request).await.map_err(err)?;
    serde_json::to_value(reply).map_err(err)
}

#[tauri::command]
fn daemon_running(state: State<'_, AppState>) -> bool {
    ipc::daemon_running(&state.state_dir)
}

#[tauri::command]
fn start_daemon(state: State<'_, AppState>) -> CmdResult<()> {
    let daemon = service::daemon_binary().map_err(err)?;
    service::start_detached(&daemon, state.daemon_state_arg()).map_err(err)
}

#[tauri::command]
fn autostart_enabled() -> bool {
    service::is_installed()
}

#[tauri::command]
fn set_autostart(state: State<'_, AppState>, enabled: bool) -> CmdResult<()> {
    if enabled {
        let daemon = service::daemon_binary().map_err(err)?;
        service::install(&daemon, state.daemon_state_arg()).map_err(err)
    } else {
        service::uninstall().map_err(err)
    }
}

fn path_strings(paths: Vec<tauri_plugin_dialog::FilePath>) -> Vec<String> {
    paths
        .into_iter()
        .filter_map(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
        .collect()
}

#[tauri::command]
async fn pick_folders(app: AppHandle, multiple: bool) -> CmdResult<Vec<String>> {
    let (tx, rx) = oneshot::channel();
    let dialog = app.dialog().file();
    if multiple {
        dialog.pick_folders(move |p| {
            let _ = tx.send(p.map(path_strings).unwrap_or_default());
        });
    } else {
        dialog.pick_folder(move |p| {
            let _ = tx.send(p.map(|p| path_strings(vec![p])).unwrap_or_default());
        });
    }
    rx.await.map_err(err)
}

/// Asks the daemon for a recovery kit and saves it where the user chooses.
/// Returns the saved path, or `None` if the user cancelled.
#[tauri::command]
async fn export_recovery_kit(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
) -> CmdResult<Option<String>> {
    let mut client = Client::connect(&state.state_dir).await.map_err(err)?;
    let Reply::RecoveryKit { json } = client
        .call(&Request::ExportRecoveryKit { passphrase })
        .await
        .map_err(err)?
    else {
        return Err("unexpected reply from kinvaultd".into());
    };
    let (tx, rx) = oneshot::channel();
    app.dialog()
        .file()
        .set_title("Save recovery kit")
        .set_file_name("kinvault-recovery-kit.json")
        .add_filter("Recovery kit", &["json"])
        .save_file(move |p| {
            let _ = tx.send(p.and_then(|p| p.into_path().ok()));
        });
    let Some(path) = rx.await.map_err(err)? else {
        return Ok(None);
    };
    write_private(&path, json.as_bytes()).map_err(err)?;
    Ok(Some(path.display().to_string()))
}

/// Imports a recovery kit (the daemon must not be running). Returns the
/// imported set names.
#[tauri::command]
async fn import_recovery_kit(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
) -> CmdResult<Option<Vec<String>>> {
    let (tx, rx) = oneshot::channel();
    app.dialog()
        .file()
        .set_title("Open recovery kit")
        .add_filter("Recovery kit", &["json"])
        .pick_file(move |p| {
            let _ = tx.send(p.and_then(|p| p.into_path().ok()));
        });
    let Some(path) = rx.await.map_err(err)? else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path).map_err(err)?;
    let state_dir = state.state_dir.clone();
    let summary = tauri::async_runtime::spawn_blocking(move || {
        recovery::import_offline(&state_dir, &json, &passphrase, false)
    })
    .await
    .map_err(err)?
    .map_err(err)?;
    Ok(Some(summary.sets))
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(data)
}

/// Relays daemon events to the window as `daemon-event`, and connection
/// changes as `daemon-connection`, reconnecting whenever the daemon restarts.
async fn forward_events(app: AppHandle, state_dir: PathBuf) {
    let mut connected = None;
    loop {
        let stream = match Client::connect(&state_dir).await {
            Ok(client) => client.subscribe().await.ok(),
            Err(_) => None,
        };
        let now_connected = stream.is_some();
        if connected != Some(now_connected) {
            connected = Some(now_connected);
            let _ = app.emit("daemon-connection", now_connected);
        }
        if let Some(mut events) = stream {
            while let Some(event) = events.next().await {
                let _ = app.emit("daemon-event", &event);
            }
            connected = Some(false);
            let _ = app.emit("daemon-connection", false);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Tray menu: back up every set that isn't paused.
async fn back_up_all(state_dir: PathBuf) {
    let Ok(mut client) = Client::connect(&state_dir).await else {
        return;
    };
    let Ok(Reply::Status(status)) = client.call(&Request::Status).await else {
        return;
    };
    for set in status.sets {
        let state_dir = state_dir.clone();
        tauri::async_runtime::spawn(async move {
            if let Ok(mut c) = Client::connect(&state_dir).await {
                let _ = c.call(&Request::BackupNow { set: set.id }).await;
            }
        });
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn main() {
    let default_dir = kinvault_daemon::default_state_dir();
    let state_dir = std::env::var_os("KINVAULT_STATE")
        .map(PathBuf::from)
        .or_else(|| default_dir.clone())
        .expect("could not determine the KinVault data directory");
    let custom_state = Some(&state_dir) != default_dir.as_ref();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            state_dir: state_dir.clone(),
            custom_state,
        })
        .invoke_handler(tauri::generate_handler![
            daemon_call,
            daemon_running,
            start_daemon,
            autostart_enabled,
            set_autostart,
            pick_folders,
            export_recovery_kit,
            import_recovery_kit,
        ])
        .setup(move |app| {
            let open = MenuItem::with_id(app, "open", "Open KinVault", true, None::<&str>)?;
            let backup = MenuItem::with_id(app, "backup", "Back up now", true, None::<&str>)?;
            let quit = MenuItem::with_id(
                app,
                "quit",
                "Quit (backups keep running)",
                true,
                None::<&str>,
            )?;
            let separator = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(app, &[&open, &backup, &separator, &quit])?;
            let tray_state_dir = state_dir.clone();
            let mut tray = TrayIconBuilder::with_id("main")
                .tooltip("KinVault")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "open" => show_main_window(app),
                    "backup" => {
                        tauri::async_runtime::spawn(back_up_all(tray_state_dir.clone()));
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;

            tauri::async_runtime::spawn(forward_events(app.handle().clone(), state_dir.clone()));
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the app in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running KinVault");
}
