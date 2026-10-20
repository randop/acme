use anyhow::{Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
pub fn validate_token(token: &str) -> Result<()> {
    anyhow::ensure!(
        !token.is_empty()
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "challenge token must use base64url characters"
    );
    Ok(())
}
/// Write a single http-01 response into the user's existing webroot.
pub fn write_http01(webroot: &Path, token: &str, key_authorization: &str) -> Result<PathBuf> {
    validate_token(token)?;
    let root = webroot
        .canonicalize()
        .with_context(|| format!("resolving webroot {}", webroot.display()))?;
    anyhow::ensure!(root.is_dir(), "webroot must be a directory");
    let mut dir = root;
    for part in [".well-known", "acme-challenge"] {
        dir.push(part);
        match fs::symlink_metadata(&dir) {
            Ok(m) => anyhow::ensure!(
                m.is_dir() && !m.file_type().is_symlink(),
                "refusing symlink or non-directory in challenge path: {}",
                dir.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&dir)?;
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let path = dir.join(token);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .with_context(|| {
            format!(
                "creating challenge file {} (existing files are not overwritten)",
                path.display()
            )
        })?;
    if let Err(error) = f
        .write_all(key_authorization.as_bytes())
        .and_then(|_| f.sync_all())
    {
        drop(f);
        let _ = fs::remove_file(&path);
        return Err(error)
            .with_context(|| format!("writing challenge response {}", path.display()));
    }
    Ok(path)
}
pub fn cleanup(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_validate_token() {
        assert!(validate_token("valid123").is_ok());
        assert!(validate_token("valid-token").is_ok());
        assert!(validate_token("valid_token").is_ok());
        assert!(validate_token("").is_err());
        assert!(validate_token("invalid@").is_err());
        assert!(validate_token("invalid ").is_err());
    }

    #[test]
    fn test_write_http01_basic() {
        let dir = tempdir().unwrap();
        let webroot = dir.path();
        let token = "test_token_123";
        let key_auth = "test.keyauth";

        let path = write_http01(webroot, token, key_auth).unwrap();
        assert!(path.exists());
        assert!(path.ends_with(".well-known/acme-challenge/test_token_123"));
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, key_auth);
    }

    #[test]
    fn test_write_http01_creates_directories() {
        let dir = tempdir().unwrap();
        let webroot = dir.path();
        let token = "test_token";
        let key_auth = "keyauth";

        let path = write_http01(webroot, token, key_auth).unwrap();
        let challenge_dir = path.parent().unwrap(); // acme-challenge dir
        let well_known_dir = challenge_dir.parent().unwrap(); // .well-known dir
        assert!(well_known_dir.exists());
        assert!(challenge_dir.exists());
        assert!(well_known_dir.join("acme-challenge").exists());
    }

    #[test]
    fn test_write_http01_rejects_symlink() {
        let dir = tempdir().unwrap();
        let webroot = dir.path();
        let well_known = webroot.join(".well-known");
        fs::create_dir(&well_known).unwrap();
        let challenge_link = well_known.join("acme-challenge");
        let target = tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), &challenge_link).unwrap();

        let result = write_http01(webroot, "token", "keyauth");
        assert!(result.is_err());
    }

    #[test]
    fn test_write_http01_rejects_existing_file() {
        let dir = tempdir().unwrap();
        let webroot = dir.path();
        let token = "test_token";
        let key_auth = "keyauth";

        write_http01(webroot, token, key_auth).unwrap();
        let result = write_http01(webroot, token, "different");
        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, "content").unwrap();
        assert!(file.exists());

        cleanup(&file).unwrap();
        assert!(!file.exists());
    }
}
