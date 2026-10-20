use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_acme"));
    command
        .env("ACME_HOME", home)
        .env_remove("ACME_CONFIG")
        .env_remove("ACME_STORE_PATH")
        .env_remove("ACME_STORE_ENABLED");
    command
}
fn metadata(home: &Path, name: &str, change: impl FnOnce(&mut Value)) {
    let directory = home.join("certs").join(name);
    fs::create_dir_all(&directory).unwrap();
    let mut value = json!({"domains": [name], "ca_directory": "invalid-url",
        "challenge": "http-01", "not_after": "2099-01-01T00:00:00Z", "webroot": "/tmp",
        "email": "test@example.com", "key_type": "ec-256"});
    change(&mut value);
    fs::write(directory.join("metadata.json"), value.to_string()).unwrap();
}
fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn renewal_collects_directory_errors_and_continues() {
    let home = tempdir().unwrap();
    metadata(home.path(), "unsupported.example", |v| {
        v["challenge"] = json!("unknown")
    });
    metadata(home.path(), "expiry.example", |v| {
        v["not_after"] = json!("invalid")
    });
    metadata(home.path(), "primary.example", |v| {
        v["domains"] = json!(["*.example.com"])
    });
    metadata(home.path(), "valid.example", |_| {});
    fs::create_dir_all(home.path().join("certs/missing.example")).unwrap();
    let output = command(home.path())
        .args(["--no-store", "renew", "--all"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let errors = stderr(&output);
    for (name, cause) in [
        ("unsupported.example", "unsupported renewal challenge"),
        ("expiry.example", "invalid not_after"),
        ("primary.example", "no primary domain"),
        ("missing.example", "metadata"),
    ] {
        assert!(
            errors
                .lines()
                .any(|line| line.contains(name) && line.contains(cause)),
            "{errors}"
        );
    }
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("not due: valid.example")
    );
}

#[test]
fn corrupt_or_unavailable_store_cannot_report_not_due_for_all() {
    for unavailable in [false, true] {
        let home = tempdir().unwrap();
        metadata(home.path(), "one.example", |_| {});
        metadata(home.path(), "two.example", |_| {});
        let store = home.path().join("store.db");
        if unavailable {
            fs::create_dir(&store).unwrap();
        } else {
            fs::write(&store, "not a sqlite database").unwrap();
        }
        let output = command(home.path())
            .args(["renew", "--all"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let errors = stderr(&output);
        for name in ["one.example", "two.example"] {
            assert!(
                errors
                    .lines()
                    .any(|line| line.contains(name) && line.contains("cannot evaluate renewal")),
                "{errors}"
            );
        }
        // The existing single-lineage warning/expiry fallback remains available.
        let output = command(home.path())
            .args(["renew", "-d", "one.example"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    }
}

#[test]
fn explicit_missing_config_is_an_error() {
    let home = tempdir().unwrap();
    let missing = home.path().join("missing.toml");
    let output = command(home.path())
        .arg("--config")
        .arg(&missing)
        .args(["--no-store", "store", "path"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("reading config"));
    let output = command(home.path())
        .env("ACME_CONFIG", &missing)
        .args(["--no-store", "store", "path"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("reading config"));
    let output = command(home.path())
        .args(["--no-store", "store", "path"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
}
