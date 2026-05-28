slint::include_modules!();

fn main() {
    let ui = AppWindow::new().expect("Failed to create window");
    let ui_handle = ui.as_weak();
    let _runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");
    ui.on_unlock(move |password| {
        let handle_clone = ui_handle.clone();
        tokio::spawn(async move {
            let result = simulate_unlock(password).await;
            handle_clone.upgrade_in_event_loop(move |ui| {
                match result {
                    Ok(()) => {
                        ui.set_vault_locked(false);
                    }
                    Err(err) => {
                        ui.set_error_message(err.into());
                    }
                }
            }).expect("Event loop queue failed");
        });
    });
    ui.run().expect("UI loop failed");
}

async fn simulate_unlock(password: slint::SharedString) -> Result<(), &'static str> {
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    if password == "secret" {
        Ok(())
    } else {
        Err("Invalid password")
    }
}
