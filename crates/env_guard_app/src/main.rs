slint::include_modules!();

use std::sync::Arc;
use std::path::PathBuf;
use tokio::sync::Mutex;
use uuid::Uuid;
use env_guard_core::env_guard::envGuard;
use env_guard_core::env_guard::models::{SessionRules, ShellType};

fn main() {
    let ui = AppWindow::new().expect("Failed to create window");
    let ui_handle = ui.as_weak();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    let controller_state = Arc::new(Mutex::new(None));

    let u_state = Arc::clone(&controller_state);
    let u_handle = ui_handle.clone();
    ui.on_unlock(move |password| {
        let u_state = Arc::clone(&u_state);
        let u_handle = u_handle.clone();
        let password_str = password.to_string();
        tokio::spawn(async move {
            let base_dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
            let db_path = base_dir.join("EnvGuard").join("vault.db");
            if let Some(parent) = db_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match envGuard::unlock(&db_path, &password_str).await {
                Ok(controller) => {
                    let mut lock = u_state.lock().await;
                    *lock = Some(controller);
                    let ctrl_ref = lock.as_ref().unwrap();
                    let profiles_res = ctrl_ref.list_profiles().await;
                    
                    u_handle.upgrade_in_event_loop(move |ui| {
                        ui.set_vault_locked(false);
                        ui.set_error_message("".into());
                        if let Ok(profs) = profiles_res {
                            let slint_profs: Vec<ProfileUiData> = profs.into_iter().map(|p| {
                                ProfileUiData {
                                    id: p.id.to_string().into(),
                                    name: p.name.into(),
                                    description: p.description.unwrap_or_default().into(),
                                    credential_count: 0,
                                    is_active: p.is_active,
                                    session_count: 0,
                                }
                            }).collect();
                            ui.set_profiles(slint::ModelRc::new(slint::VecModel::from(slint_profs)));
                        }
                    }).expect("Event loop queue failed");
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    u_handle.upgrade_in_event_loop(move |ui| {
                        ui.set_error_message(err_msg.into());
                    }).expect("Event loop queue failed");
                }
            }
        });
    });

    let l_state = Arc::clone(&controller_state);
    let l_handle = ui_handle.clone();
    ui.on_lock_vault(move || {
        let l_state = Arc::clone(&l_state);
        let l_handle = l_handle.clone();
        tokio::spawn(async move {
            let mut lock = l_state.lock().await;
            if let Some(ctrl) = lock.take() {
                let _ = ctrl.lock().await;
            }
            l_handle.upgrade_in_event_loop(move |ui| {
                ui.set_vault_locked(true);
                ui.set_profiles(slint::ModelRc::new(slint::VecModel::from(Vec::new())));
                ui.set_credentials(slint::ModelRc::new(slint::VecModel::from(Vec::new())));
                ui.set_active_sessions(slint::ModelRc::new(slint::VecModel::from(Vec::new())));
            }).expect("Event loop queue failed");
        });
    });

    let cp_state = Arc::clone(&controller_state);
    let cp_handle = ui_handle.clone();
    ui.on_create_profile(move |name, desc| {
        let cp_state = Arc::clone(&cp_state);
        let cp_handle = cp_handle.clone();
        let name_str = name.to_string();
        let desc_str = desc.to_string();
        tokio::spawn(async move {
            let lock = cp_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                let rules = SessionRules {
                    expiration_seconds: None,
                    allowed_shells: Vec::new(),
                    require_auth_on_resume: false,
                };
                let _ = ctrl.create_profile(&name_str, Some(&desc_str), rules).await;
                if let Ok(profs) = ctrl.list_profiles().await {
                    cp_handle.upgrade_in_event_loop(move |ui| {
                        let slint_profs: Vec<ProfileUiData> = profs.into_iter().map(|p| {
                            ProfileUiData {
                                id: p.id.to_string().into(),
                                name: p.name.into(),
                                description: p.description.unwrap_or_default().into(),
                                credential_count: 0,
                                is_active: p.is_active,
                                session_count: 0,
                            }
                        }).collect();
                        ui.set_profiles(slint::ModelRc::new(slint::VecModel::from(slint_profs)));
                    }).expect("Event loop queue failed");
                }
            }
        });
    });

    let sp_state = Arc::clone(&controller_state);
    let sp_handle = ui_handle.clone();
    ui.on_select_profile(move |id| {
        let sp_state = Arc::clone(&sp_state);
        let sp_handle = sp_handle.clone();
        let id_uuid = Uuid::parse_str(&id.to_string()).unwrap_or_default();
        tokio::spawn(async move {
            let lock = sp_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                let profile_opt = ctrl.get_profile(id_uuid).await.unwrap_or(None);
                if let Ok(creds) = ctrl.get_credentials_metadata(id_uuid).await {
                    sp_handle.upgrade_in_event_loop(move |ui| {
                        if let Some(p) = profile_opt {
                            let timeout_str = p.session_rules.expiration_seconds.map(|s| s.to_string()).unwrap_or_default();
                            let shells_str = p.session_rules.allowed_shells.iter().map(|s| format!("{:?}", s)).collect::<Vec<_>>().join(", ");
                            ui.set_session_timeout(timeout_str.into());
                            ui.set_allowed_shells(shells_str.into());
                        }
                        let slint_creds: Vec<CredentialUiData> = creds.into_iter().map(|c| {
                            CredentialUiData {
                                id: c.id.to_string().into(),
                                key: c.key.into(),
                                value_revealed: false,
                                value_plaintext: "".into(),
                            }
                        }).collect();
                        ui.set_credentials(slint::ModelRc::new(slint::VecModel::from(slint_creds)));
                    }).expect("Event loop queue failed");
                }
            }
        });
    });

    let spr_state = Arc::clone(&controller_state);
    ui.on_save_profile_rules(move |profile_id, timeout_str, allowed_shells_str| {
        let spr_state = Arc::clone(&spr_state);
        let profile_uuid = Uuid::parse_str(&profile_id.to_string()).unwrap_or_default();
        let timeout_trimmed = timeout_str.to_string().trim().to_string();
        let shells_trimmed = allowed_shells_str.to_string();
        tokio::spawn(async move {
            let expiration_seconds = if timeout_trimmed.is_empty() {
                None
            } else {
                timeout_trimmed.parse::<u64>().ok()
            };
            let allowed_shells = shells_trimmed
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .map(|s| match s.as_str() {
                    "bash" => ShellType::Bash,
                    "zsh" => ShellType::Zsh,
                    "fish" => ShellType::Fish,
                    "powershell" => ShellType::PowerShell,
                    "cmd" => ShellType::Cmd,
                    other => ShellType::Custom(other.to_string()),
                })
                .collect();
            let rules = SessionRules {
                expiration_seconds,
                allowed_shells,
                require_auth_on_resume: false,
            };
            let lock = spr_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                let _ = ctrl.update_profile_rules(profile_uuid, rules).await;
            }
        });
    });

    let dp_state = Arc::clone(&controller_state);
    let dp_handle = ui_handle.clone();
    ui.on_delete_profile(move |id| {
        let dp_state = Arc::clone(&dp_state);
        let dp_handle = dp_handle.clone();
        let id_uuid = Uuid::parse_str(&id.to_string()).unwrap_or_default();
        tokio::spawn(async move {
            let lock = dp_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                let _ = ctrl.delete_profile(id_uuid).await;
                if let Ok(profs) = ctrl.list_profiles().await {
                    dp_handle.upgrade_in_event_loop(move |ui| {
                        let slint_profs: Vec<ProfileUiData> = profs.into_iter().map(|p| {
                            ProfileUiData {
                                id: p.id.to_string().into(),
                                name: p.name.into(),
                                description: p.description.unwrap_or_default().into(),
                                credential_count: 0,
                                is_active: p.is_active,
                                session_count: 0,
                            }
                        }).collect();
                        ui.set_profiles(slint::ModelRc::new(slint::VecModel::from(slint_profs)));
                    }).expect("Event loop queue failed");
                }
            }
        });
    });

    let ac_state = Arc::clone(&controller_state);
    let ac_handle = ui_handle.clone();
    ui.on_add_credential(move |profile_id, key, val| {
        let ac_state = Arc::clone(&ac_state);
        let ac_handle = ac_handle.clone();
        let profile_uuid = Uuid::parse_str(&profile_id.to_string()).unwrap_or_default();
        let key_str = key.to_string();
        let val_str = val.to_string();
        tokio::spawn(async move {
            let lock = ac_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                let _ = ctrl.add_credential(profile_uuid, &key_str, &val_str).await;
                if let Ok(creds) = ctrl.get_credentials_metadata(profile_uuid).await {
                    ac_handle.upgrade_in_event_loop(move |ui| {
                        let slint_creds: Vec<CredentialUiData> = creds.into_iter().map(|c| {
                            CredentialUiData {
                                id: c.id.to_string().into(),
                                key: c.key.into(),
                                value_revealed: false,
                                value_plaintext: "".into(),
                            }
                        }).collect();
                        ui.set_credentials(slint::ModelRc::new(slint::VecModel::from(slint_creds)));
                    }).expect("Event loop queue failed");
                }
            }
        });
    });

    let dc_state = Arc::clone(&controller_state);
    let dc_handle = ui_handle.clone();
    ui.on_delete_credential(move |id| {
        let dc_state = Arc::clone(&dc_state);
        let dc_handle = dc_handle.clone();
        let id_uuid = Uuid::parse_str(&id.to_string()).unwrap_or_default();
        tokio::spawn(async move {
            let profile_uuid = {
                if let Some(ui) = dc_handle.upgrade() {
                    let profile_id_str = ui.get_selected_profile_id().to_string();
                    Uuid::parse_str(&profile_id_str).unwrap_or_default()
                } else {
                    Uuid::nil()
                }
            };
            let lock = dc_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                let _ = ctrl.delete_credential(id_uuid).await;
                if !profile_uuid.is_nil() {
                    if let Ok(creds) = ctrl.get_credentials_metadata(profile_uuid).await {
                        let dc_handle_clone = dc_handle.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui_ref) = dc_handle_clone.upgrade() {
                                let slint_creds: Vec<CredentialUiData> = creds.into_iter().map(|c| {
                                    CredentialUiData {
                                        id: c.id.to_string().into(),
                                        key: c.key.into(),
                                        value_revealed: false,
                                        value_plaintext: "".into(),
                                    }
                                }).collect();
                                ui_ref.set_credentials(slint::ModelRc::new(slint::VecModel::from(slint_creds)));
                            }
                        });
                    }
                }
            }
        });
    });

    let ss_state = Arc::clone(&controller_state);
    let ss_handle = ui_handle.clone();
    ui.on_start_session(move |profile_id| {
        let ss_state = Arc::clone(&ss_state);
        let ss_handle = ss_handle.clone();
        let profile_uuid = Uuid::parse_str(&profile_id.to_string()).unwrap_or_default();
        tokio::spawn(async move {
            let lock = ss_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                let shell = if cfg!(target_os = "windows") { ShellType::Cmd } else { ShellType::Bash };
                let _ = ctrl.start_session(profile_uuid, shell).await;
                let active = ctrl.list_active_sessions().await;
                ss_handle.upgrade_in_event_loop(move |ui| {
                    ui.set_active_session_count(active.len() as i32);
                    let slint_sessions: Vec<SessionUiData> = active.into_iter().map(|s| {
                        SessionUiData {
                            id: s.id.to_string().into(),
                            profile_name: "Profile".into(),
                            shell: format!("{:?}", s.shell).into(),
                            started_at: s.started_at.to_rfc3339().into(),
                            expires_at: s.expires_at.map(|d| d.to_rfc3339()).unwrap_or_default().into(),
                            pid: s.pid.unwrap_or(0) as i32,
                            status: format!("{:?}", s.status).into(),
                        }
                    }).collect();
                    ui.set_active_sessions(slint::ModelRc::new(slint::VecModel::from(slint_sessions)));
                }).expect("Event loop queue failed");
            }
        });
    });

    let ts_state = Arc::clone(&controller_state);
    let ts_handle = ui_handle.clone();
    ui.on_stop_session(move |session_id| {
        let ts_state = Arc::clone(&ts_state);
        let ts_handle = ts_handle.clone();
        let session_uuid = Uuid::parse_str(&session_id.to_string()).unwrap_or_default();
        tokio::spawn(async move {
            let lock = ts_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                let _ = ctrl.stop_session(session_uuid).await;
                let active = ctrl.list_active_sessions().await;
                ts_handle.upgrade_in_event_loop(move |ui| {
                    ui.set_active_session_count(active.len() as i32);
                    let slint_sessions: Vec<SessionUiData> = active.into_iter().map(|s| {
                        SessionUiData {
                            id: s.id.to_string().into(),
                            profile_name: "Profile".into(),
                            shell: format!("{:?}", s.shell).into(),
                            started_at: s.started_at.to_rfc3339().into(),
                            expires_at: s.expires_at.map(|d| d.to_rfc3339()).unwrap_or_default().into(),
                            pid: s.pid.unwrap_or(0) as i32,
                            status: format!("{:?}", s.status).into(),
                        }
                    }).collect();
                    ui.set_active_sessions(slint::ModelRc::new(slint::VecModel::from(slint_sessions)));
                }).expect("Event loop queue failed");
            }
        });
    });

    let sc_state = Arc::clone(&controller_state);
    let sc_handle = ui_handle.clone();
    ui.on_scan_env_files(move |dir_path| {
        let sc_state = Arc::clone(&sc_state);
        let sc_handle = sc_handle.clone();
        let path = PathBuf::from(dir_path.to_string());
        tokio::spawn(async move {
            let lock = sc_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                if let Ok(files) = ctrl.scan_for_env_files(&path).await {
                    sc_handle.upgrade_in_event_loop(move |ui| {
                        let slint_files: Vec<slint::SharedString> = files.into_iter().map(|p| {
                            p.to_string_lossy().to_string().into()
                        }).collect();
                        ui.set_scanned_env_files(slint::ModelRc::new(slint::VecModel::from(slint_files)));
                    }).expect("Event loop queue failed");
                }
            }
        });
    });

    let cc_state = Arc::clone(&controller_state);
    ui.on_copy_to_clipboard(move |id_str| {
        let cc_state = Arc::clone(&cc_state);
        let id_uuid = Uuid::parse_str(&id_str.to_string()).unwrap_or_default();
        tokio::spawn(async move {
            let lock = cc_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                if let Ok(val) = ctrl.decrypt_credential(id_uuid).await {
                    if let Ok(mut clipboard) = arboard::Clipboard::new() {
                        let _ = clipboard.set_text(val);
                    }
                }
            }
        });
    });

    let handle_clone = runtime.handle().clone();
    let dc_clip_state = Arc::clone(&controller_state);
    ui.on_decrypt_credential(move |id_str| {
        let dc_clip_state = Arc::clone(&dc_clip_state);
        let id_uuid = Uuid::parse_str(&id_str.to_string()).unwrap_or_default();
        let val = handle_clone.block_on(async move {
            let lock = dc_clip_state.lock().await;
            if let Some(ctrl) = lock.as_ref() {
                ctrl.decrypt_credential(id_uuid).await.unwrap_or_default()
            } else {
                "".to_string()
            }
        });
        val.into()
    });

    let _timer_state = Arc::clone(&controller_state);
    let timer_handle = ui_handle.clone();
    runtime.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let is_locked = {
                if let Some(ui) = timer_handle.upgrade() {
                    ui.get_vault_locked()
                } else {
                    break;
                }
            };
            if !is_locked {
                let active = _timer_state.lock().await;
                if let Some(ctrl) = active.as_ref() {
                    let list = ctrl.list_active_sessions().await;
                    let count = list.len() as i32;
                    let timer_handle_clone = timer_handle.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui_ref) = timer_handle_clone.upgrade() {
                            ui_ref.set_active_session_count(count);
                        }
                    });
                }
            }
        }
    });

    ui.run().expect("UI event loop failed");

    let mut final_lock = runtime.block_on(async {
        controller_state.lock().await
    });
    if let Some(ctrl) = final_lock.take() {
        let _ = runtime.block_on(ctrl.lock());
    }
}
