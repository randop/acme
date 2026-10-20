use anyhow::{Context, Result};
use std::{
    ffi::{CStr, CString},
    fs::{self, File},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
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

/// Retains the directory used for creation, including when its pathname changes.
pub struct Http01File {
    directory: File,
    token: CString,
    path: PathBuf,
}
impl Http01File {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn open_at(parent: &File, name: &CStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: the parent descriptor and NUL-terminated name remain valid during openat.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new, owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn challenge_directory(root: &Path) -> Result<File> {
    // Walk the canonical absolute path from a retained root handle. Every component
    // is opened without following symlinks, including components of the webroot.
    let mut parent = File::open("/")?;
    for component in root.components() {
        if let std::path::Component::Normal(part) = component {
            let name = CString::new(part.as_bytes())?;
            parent = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        }
    }
    for part in [".well-known", "acme-challenge"] {
        let name = CString::new(part)?;
        let mut created = false;
        let directory = match open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // SAFETY: the parent descriptor and name are valid for mkdirat.
                let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error.into());
                    }
                } else {
                    created = true;
                }
                open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
            }
            Err(error) => return Err(error.into()),
        };
        if created {
            directory.set_permissions(fs::Permissions::from_mode(0o755))?;
        }
        parent = directory;
    }
    Ok(parent)
}

/// Write a single http-01 response into the user's existing webroot.
pub fn write_http01(webroot: &Path, token: &str, key_authorization: &str) -> Result<Http01File> {
    validate_token(token)?;
    let root = webroot
        .canonicalize()
        .with_context(|| format!("resolving webroot {}", webroot.display()))?;
    let directory = challenge_directory(&root).context("opening challenge directory")?;
    let path = root.join(".well-known/acme-challenge").join(token);
    let challenge = Http01File {
        directory,
        token: CString::new(token)?,
        path,
    };
    let mut file = open_at(
        &challenge.directory,
        &challenge.token,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .with_context(|| {
        format!(
            "creating challenge file {} (existing files are not overwritten)",
            challenge.path.display()
        )
    })?;
    if let Err(error) = file
        .write_all(key_authorization.as_bytes())
        .and_then(|_| file.set_permissions(fs::Permissions::from_mode(0o644)))
        .and_then(|_| file.sync_all())
    {
        let _ = cleanup(&challenge);
        return Err(error)
            .with_context(|| format!("writing challenge response {}", challenge.path.display()));
    }
    Ok(challenge)
}

pub fn cleanup(challenge: &Http01File) -> Result<()> {
    // SAFETY: both the retained descriptor and token name remain valid for unlinkat.
    let result =
        unsafe { libc::unlinkat(challenge.directory.as_raw_fd(), challenge.token.as_ptr(), 0) };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }
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

        let challenge = write_http01(webroot, token, key_auth).unwrap();
        let path = challenge.path();
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

        let challenge = write_http01(webroot, token, key_auth).unwrap();
        let path = challenge.path();
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
        let challenge = write_http01(dir.path(), "token", "content").unwrap();
        cleanup(&challenge).unwrap();
        assert!(!challenge.path().exists());
    }

    #[test]
    fn cleanup_uses_retained_directory() {
        let root = tempdir().unwrap();
        let other = tempdir().unwrap();
        let challenge = write_http01(root.path(), "token", "original").unwrap();
        let parent = challenge.path().parent().unwrap();
        let moved = root.path().join("moved");
        fs::rename(parent, &moved).unwrap();
        fs::write(other.path().join("token"), "unrelated").unwrap();
        std::os::unix::fs::symlink(other.path(), parent).unwrap();
        cleanup(&challenge).unwrap();
        assert!(!moved.join("token").exists());
        assert_eq!(
            fs::read_to_string(other.path().join("token")).unwrap(),
            "unrelated"
        );
    }

    #[test]
    fn readable_under_restrictive_umask() {
        if std::env::var_os("ACME_TEST_UMASK_CHILD").is_some() {
            // Isolated subprocess: umask is process-wide.
            unsafe {
                libc::umask(0o077);
            }
            let root = tempdir().unwrap();
            let challenge = write_http01(root.path(), "token", "response").unwrap();
            assert_eq!(
                fs::metadata(challenge.path()).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert_eq!(
                fs::metadata(challenge.path().parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        } else {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "tests::readable_under_restrictive_umask"])
                    .env("ACME_TEST_UMASK_CHILD", "1")
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
}
