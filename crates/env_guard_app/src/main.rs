#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod state;
mod commands;
mod config;

use state::VaultState;

fn main() {
    tracing_subscriber::fmt::init();
    tauri::Builder::default()
        .manage(VaultState::default())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            commands::unlock_vault,
            commands::lock_vault,
            commands::wipe_vault,
            commands::is_vault_initialized,
            commands::create_profile,
            commands::list_profiles,
            commands::update_profile,
            commands::update_profile_metadata,
            commands::duplicate_profile,
            commands::get_profile,
            commands::update_profile_rules,
            commands::delete_profile,
            commands::add_credential,
            commands::list_credentials,
            commands::decrypt_credential,
            commands::delete_credential,
            commands::update_credential,
            commands::start_session,
            commands::stop_session,
            commands::list_active_sessions,
            commands::scan_for_env_files,
            commands::get_vault_directory,
            commands::get_app_config,
            commands::save_app_config,
            commands::open_vault_directory,
            commands::generate_secure_token
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
