use crate::Store2PluginExt;

const SECURE_STORE_SUFFIX: &str = "secure-store";

fn secure_store_service(identifier: &str) -> String {
    let identifier = match identifier {
        "com.hyprnote.dev" => "com.anarlog.dev",
        "com.hyprnote.staging" => "com.anarlog.staging",
        "com.hyprnote.stable" | "com.hyprnote.Hyprnote" => "com.anarlog.stable",
        identifier => identifier,
    };

    format!("{identifier}.{SECURE_STORE_SUFFIX}")
}

fn secure_store_account(identifier: &str, scope: &str, key: &str) -> String {
    let account = format!("{scope}:{key}");
    if identifier == "com.hyprnote.dev" {
        // Rotate away from dev items whose ACLs captured unstable ad-hoc signatures.
        format!("v2:{account}")
    } else {
        account
    }
}

fn legacy_secret_locations(identifier: &str, scope: &str, key: &str) -> Vec<(String, String)> {
    let service = secure_store_service(identifier);
    let account = format!("{scope}:{key}");
    let current_account = secure_store_account(identifier, scope, key);
    let legacy_service = format!("{identifier}.{SECURE_STORE_SUFFIX}");
    let mut locations = Vec::new();

    if account != current_account {
        locations.push((service.clone(), account.clone()));
    }
    if legacy_service != service {
        locations.push((legacy_service, account));
    }

    locations
}

fn legacy_secret_entries<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    scope: &str,
    key: &str,
) -> Result<Vec<keyring::Entry>, String> {
    legacy_secret_locations(&app.config().identifier, scope, key)
        .into_iter()
        .map(|(service, account)| {
            keyring::Entry::new(&service, &account).map_err(|error| error.to_string())
        })
        .collect()
}

fn secret_entry<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    scope: &str,
    key: &str,
) -> Result<keyring::Entry, String> {
    if scope.trim().is_empty() || key.trim().is_empty() {
        return Err("secure-store scope and key must not be empty".to_string());
    }

    let identifier = &app.config().identifier;
    let service = secure_store_service(identifier);
    let account = secure_store_account(identifier, scope, key);
    keyring::Entry::new(&service, &account).map_err(|error| error.to_string())
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn save<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<(), String> {
    app.store2()
        .store()
        .map_err(|e| e.to_string())?
        .save()
        .map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn get_str<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
) -> Result<Option<String>, String> {
    let store = app
        .store2()
        .scoped_store::<String>(scope)
        .map_err(|e| e.to_string())?;

    store.get::<String>(key).map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn set_str<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
    value: String,
) -> Result<(), String> {
    let store = app
        .store2()
        .scoped_store::<String>(scope)
        .map_err(|e| e.to_string())?;

    store.set(key, value).map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn get_bool<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
) -> Result<Option<bool>, String> {
    let store = app
        .store2()
        .scoped_store::<String>(scope)
        .map_err(|e| e.to_string())?;

    store.get::<bool>(key).map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn set_bool<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
    value: bool,
) -> Result<(), String> {
    let store = app
        .store2()
        .scoped_store::<String>(scope)
        .map_err(|e| e.to_string())?;

    store.set(key, value).map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn get_number<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
) -> Result<Option<f64>, String> {
    let store = app
        .store2()
        .scoped_store::<String>(scope)
        .map_err(|e| e.to_string())?;

    store.get::<f64>(key).map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn set_number<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
    value: f64,
) -> Result<(), String> {
    let store = app
        .store2()
        .scoped_store::<String>(scope)
        .map_err(|e| e.to_string())?;

    store.set(key, value).map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn get_secret<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let entry = secret_entry(&app, &scope, &key)?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => {
                for legacy_entry in legacy_secret_entries(&app, &scope, &key)? {
                    match legacy_entry.get_password() {
                        Ok(secret) => {
                            if entry.set_password(&secret).is_ok() {
                                let _ = legacy_entry.delete_credential();
                            }
                            return Ok(Some(secret));
                        }
                        Err(keyring::Error::NoEntry | keyring::Error::PlatformFailure(_)) => {}
                        Err(error) => return Err(error.to_string()),
                    }
                }
                Ok(None)
            }
            Err(error) => Err(error.to_string()),
        }
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn set_secret<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
    value: String,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let entry = secret_entry(&app, &scope, &key)?;
        entry
            .set_password(&value)
            .map_err(|error| error.to_string())?;
        for legacy_entry in legacy_secret_entries(&app, &scope, &key)? {
            let _ = legacy_entry.delete_credential();
        }
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
#[specta::specta]
pub(crate) async fn delete_secret<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    scope: String,
    key: String,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        for legacy_entry in legacy_secret_entries(&app, &scope, &key)? {
            match legacy_entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry | keyring::Error::PlatformFailure(_)) => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        let entry = secret_entry(&app, &scope, &key)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(error) => return Err(error.to_string()),
        }
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_anarlog_service_names_for_legacy_bundle_identifiers() {
        assert_eq!(
            secure_store_service("com.hyprnote.dev"),
            "com.anarlog.dev.secure-store"
        );
        assert_eq!(
            secure_store_service("com.hyprnote.staging"),
            "com.anarlog.staging.secure-store"
        );
        assert_eq!(
            secure_store_service("com.hyprnote.stable"),
            "com.anarlog.stable.secure-store"
        );
        assert_eq!(
            secure_store_service("com.hyprnote.Hyprnote"),
            "com.anarlog.stable.secure-store"
        );
    }

    #[test]
    fn preserves_unknown_service_identifiers() {
        assert_eq!(
            secure_store_service("com.example.app"),
            "com.example.app.secure-store"
        );
    }

    #[test]
    fn versions_dev_accounts_across_signing_changes() {
        assert_eq!(
            secure_store_account("com.hyprnote.dev", "provider", "deepgram"),
            "v2:provider:deepgram"
        );
        assert_eq!(
            secure_store_account("com.hyprnote.stable", "provider", "deepgram"),
            "provider:deepgram"
        );
    }

    #[test]
    fn migrates_all_previous_dev_secret_locations() {
        assert_eq!(
            legacy_secret_locations("com.hyprnote.dev", "provider", "deepgram"),
            vec![
                (
                    "com.anarlog.dev.secure-store".to_string(),
                    "provider:deepgram".to_string(),
                ),
                (
                    "com.hyprnote.dev.secure-store".to_string(),
                    "provider:deepgram".to_string(),
                ),
            ]
        );
    }

    #[test]
    fn skips_duplicate_legacy_secret_locations() {
        assert!(legacy_secret_locations("com.example.app", "provider", "deepgram").is_empty());
    }
}
