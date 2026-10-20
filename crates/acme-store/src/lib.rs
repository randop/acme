use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone)]
pub struct StorePath {
    pub path: PathBuf,
    pub source: &'static str,
}
pub fn resolve_path(
    cli: Option<&Path>,
    env: Option<&str>,
    config: Option<&Path>,
) -> Result<StorePath> {
    if let Some(p) = cli {
        return normalize(p, "cli");
    };
    if let Some(p) = env.filter(|s| !s.is_empty()) {
        return normalize(Path::new(p), "environment");
    }
    if let Some(p) = config {
        return normalize(p, "config");
    }
    if let Some(home) = std::env::var_os("ACME_HOME") {
        return normalize(&PathBuf::from(home).join("store.db"), "default");
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    normalize(&PathBuf::from(home).join(".acme/store.db"), "default")
}
fn normalize(p: &Path, source: &'static str) -> Result<StorePath> {
    let s = p.to_string_lossy();
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(dirs::home_dir);
    let p = if s == "~" {
        home.clone().context("home directory is not set")?
    } else if let Some(rest) = s.strip_prefix("~/") {
        home.context("home directory is not set")?.join(rest)
    } else {
        p.to_path_buf()
    };
    let p = if p.is_absolute() {
        p
    } else {
        std::env::current_dir()?.join(p)
    };
    Ok(StorePath { path: p, source })
}
pub struct Store {
    conn: Connection,
}
impl Store {
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
    pub fn open(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .context("store path must include a parent directory")?;
        use std::os::unix::fs::PermissionsExt;
        let parent_existed = parent.exists();
        fs::create_dir_all(parent)?;
        if !parent_existed {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let version = if path.exists() {
            let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .context("inspecting store schema")?;
            conn.busy_timeout(Duration::from_secs(10))?;
            let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            if version > 2 {
                return Ok(Self { conn });
            }
            version
        } else {
            0
        };
        let mut c = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        c.busy_timeout(Duration::from_secs(10))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        c.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;",
        )?;
        if version < 2 && version > 0 {
            let backup_path = path.with_extension(format!("pre-migration-v{version}.db"));
            if !backup_path.exists() {
                let mut backup_conn = Connection::open(&backup_path)?;
                fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
                rusqlite::backup::Backup::new(&c, &mut backup_conn)?.run_to_completion(
                    100,
                    Duration::from_millis(20),
                    None,
                )?;
            }
        }
        let tx = c.transaction()?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS domains(id INTEGER PRIMARY KEY,primary_name TEXT NOT NULL UNIQUE,names_json TEXT NOT NULL DEFAULT '[]',ca TEXT NOT NULL DEFAULT '',key_type TEXT NOT NULL DEFAULT '',challenge_type TEXT NOT NULL DEFAULT '',state TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL,updated_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY,domain_id INTEGER NOT NULL REFERENCES domains(id),serial TEXT,fingerprint TEXT,not_before TEXT,not_after TEXT NOT NULL,issued_at TEXT NOT NULL,order_url TEXT,replaces_id INTEGER REFERENCES certificates(id),ari_start TEXT,ari_end TEXT,ari_checked_at TEXT,next_renew_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY,command TEXT NOT NULL,version TEXT NOT NULL,started_at TEXT NOT NULL,ended_at TEXT,exit_code INTEGER); CREATE TABLE IF NOT EXISTS activities(id INTEGER PRIMARY KEY,run_id INTEGER REFERENCES runs(id),domain_id INTEGER REFERENCES domains(id),at TEXT NOT NULL,action TEXT NOT NULL,outcome TEXT NOT NULL,message TEXT NOT NULL DEFAULT '',problem_type TEXT,details_json TEXT,duration_ms INTEGER); CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS activities_domain_time ON activities(domain_id,at DESC); CREATE INDEX IF NOT EXISTS certificates_expiration ON certificates(not_after);")?;
        ensure_column(&tx, "certificates", "serial", "TEXT")?;
        ensure_column(&tx, "certificates", "fingerprint", "TEXT")?;
        ensure_column(&tx, "certificates", "not_before", "TEXT")?;
        ensure_column(&tx, "certificates", "order_url", "TEXT")?;
        ensure_column(
            &tx,
            "certificates",
            "replaces_id",
            "INTEGER REFERENCES certificates(id)",
        )?;
        ensure_column(&tx, "certificates", "ari_start", "TEXT")?;
        ensure_column(&tx, "certificates", "ari_end", "TEXT")?;
        ensure_column(&tx, "certificates", "ari_checked_at", "TEXT")?;
        ensure_column(
            &tx,
            "certificates",
            "next_renew_at",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        tx.execute(
            "INSERT INTO schema_meta(version) SELECT 2 WHERE NOT EXISTS(SELECT 1 FROM schema_meta)",
            [],
        )?;
        tx.execute("UPDATE schema_meta SET version=2", [])?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;
        Ok(Self { conn: c })
    }
    pub fn check(&self) -> Result<()> {
        let s: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        anyhow::ensure!(s == "ok", "SQLite integrity check failed: {s}");
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<DomainRow>> {
        let mut q=self.conn.prepare("SELECT d.primary_name,d.state,c.not_after,c.next_renew_at FROM domains d LEFT JOIN certificates c ON c.id=(SELECT id FROM certificates WHERE domain_id=d.id ORDER BY issued_at DESC LIMIT 1) ORDER BY d.primary_name")?;
        Ok(q.query_map([], |r| {
            Ok(DomainRow {
                name: r.get(0)?,
                state: r.get(1)?,
                expires: r.get(2)?,
                next_renew: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?)
    }
    pub fn history(
        &self,
        name: Option<&str>,
        since: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ActivityRow>> {
        let mut q=self.conn.prepare("SELECT a.at,COALESCE(d.primary_name,''),a.action,a.outcome,a.message FROM activities a LEFT JOIN domains d ON d.id=a.domain_id WHERE (?1 IS NULL OR d.primary_name=?1) AND (?2 IS NULL OR julianday(a.at)>=julianday(?2)) ORDER BY a.id DESC LIMIT ?3")?;
        Ok(q.query_map(params![name, since, limit as i64], |r| {
            Ok(ActivityRow {
                at: r.get(0)?,
                domain: r.get(1)?,
                action: r.get(2)?,
                outcome: r.get(3)?,
                message: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?)
    }
    pub fn status(&self, name: &str) -> Result<Option<DomainRow>> {
        let mut q=self.conn.prepare("SELECT d.primary_name,d.state,c.not_after,c.next_renew_at FROM domains d LEFT JOIN certificates c ON c.id=(SELECT id FROM certificates WHERE domain_id=d.id ORDER BY issued_at DESC LIMIT 1) WHERE d.primary_name=?1")?;
        Ok(q.query_row([name], |r| {
            Ok(DomainRow {
                name: r.get(0)?,
                state: r.get(1)?,
                expires: r.get(2)?,
                next_renew: r.get(3)?,
            })
        })
        .optional()?)
    }
    pub fn set_domain_state(&self, name: &str, state: &str) -> Result<bool> {
        anyhow::ensure!(
            matches!(state, "revoked" | "removed"),
            "invalid terminal state"
        );
        let now = Utc::now().to_rfc3339();
        let changed = self.conn.execute(
            "UPDATE domains SET state=?2,updated_at=?3 WHERE primary_name=?1",
            params![name, state, now],
        )? == 1;
        if changed {
            let domain_id: i64 = self.conn.query_row(
                "SELECT id FROM domains WHERE primary_name=?1",
                [name],
                |row| row.get(0),
            )?;
            self.conn.execute("INSERT INTO runs(command,version,started_at,ended_at,exit_code) VALUES(?1,?2,?3,?3,0)",params![state,env!("CARGO_PKG_VERSION"),now])?;
            let run_id = self.conn.last_insert_rowid();
            self.conn.execute("INSERT INTO activities(run_id,domain_id,at,action,outcome,message) VALUES(?1,?2,?3,?4,'succeeded',?5)",params![run_id,domain_id,now,state,format!("{name} marked {state}")])?;
        }
        Ok(changed)
    }
    pub fn set_ari_window(&self, name: &str, start: &str, end: &str) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let updated = self.conn.execute(
            "UPDATE certificates SET ari_start=?2,ari_end=?3,ari_checked_at=?4,next_renew_at=?2 WHERE id=(SELECT c.id FROM certificates c JOIN domains d ON d.id=c.domain_id WHERE d.primary_name=?1 ORDER BY c.issued_at DESC LIMIT 1)",
            params![name, start, end, now],
        )? == 1;
        if updated {
            let _ = self.record_activity(
                name,
                "ari_poll",
                "succeeded",
                &format!("ARI renewal window is {start} through {end}"),
            )?;
        }
        Ok(updated)
    }
    pub fn record_activity(
        &self,
        name: &str,
        action: &str,
        outcome: &str,
        message: &str,
    ) -> Result<bool> {
        anyhow::ensure!(
            matches!(
                outcome,
                "started" | "succeeded" | "failed" | "skipped" | "warning"
            ),
            "invalid activity outcome"
        );
        let domain_id = self
            .conn
            .query_row(
                "SELECT id FROM domains WHERE primary_name=?1",
                [name],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(domain_id) = domain_id else {
            return Ok(false);
        };
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO runs(command,version,started_at,ended_at,exit_code) VALUES(?1,?2,?3,?3,0)",
            params![action, env!("CARGO_PKG_VERSION"), now],
        )?;
        let run_id = self.conn.last_insert_rowid();
        self.conn.execute(
            "INSERT INTO activities(run_id,domain_id,at,action,outcome,message) VALUES(?1,?2,?3,?4,?5,?6)",
            params![run_id, domain_id, now, action, outcome, message],
        )?;
        Ok(true)
    }
    pub fn start_run(&self, command: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO runs(command,version,started_at) VALUES(?1,?2,?3)",
            params![command, env!("CARGO_PKG_VERSION"), Utc::now().to_rfc3339()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }
    pub fn finish_run(&self, run_id: i64, exit_code: i32) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET ended_at=?2,exit_code=?3 WHERE id=?1",
            params![run_id, Utc::now().to_rfc3339(), exit_code],
        )?;
        Ok(())
    }
    pub fn record_certificate(
        &self,
        names: &[String],
        ca: &str,
        key_type: &str,
        challenge: &str,
        not_before: &str,
        not_after: &str,
        serial: &str,
        fingerprint: &str,
        order_url: &str,
        action: &str,
    ) -> Result<()> {
        anyhow::ensure!(
            !names.is_empty(),
            "cannot record a certificate without names"
        );
        let now = Utc::now().to_rfc3339();
        let primary = names
            .iter()
            .find(|n| !n.starts_with("*."))
            .context("certificate has no primary DNS name")?;
        let names_json = serde_json::to_string(names)?;
        let tx = self.conn.unchecked_transaction()?;
        anyhow::ensure!(
            action == "issue" || action == "renew",
            "unsupported certificate activity action"
        );
        tx.execute(
            "INSERT INTO runs(command,version,started_at,ended_at,exit_code) VALUES(?1,?2,?3,?3,0)",
            params![action, env!("CARGO_PKG_VERSION"), now],
        )?;
        let run_id = tx.last_insert_rowid();
        tx.execute("INSERT INTO domains(primary_name,names_json,ca,key_type,challenge_type,state,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,'active',?6,?6) ON CONFLICT(primary_name) DO UPDATE SET names_json=excluded.names_json,ca=excluded.ca,key_type=excluded.key_type,challenge_type=excluded.challenge_type,state='active',updated_at=excluded.updated_at",params![primary,names_json,ca,key_type,challenge,now])?;
        let domain_id: i64 = tx.query_row(
            "SELECT id FROM domains WHERE primary_name=?1",
            [primary],
            |r| r.get(0),
        )?;
        let next_renew = chrono::DateTime::parse_from_rfc3339(not_after)
            .context("certificate expiration must be RFC 3339")?
            .with_timezone(&chrono::Utc)
            - chrono::Duration::days(30);
        let replaced: Option<i64> = tx
            .query_row(
                "SELECT id FROM certificates WHERE domain_id=?1 ORDER BY issued_at DESC LIMIT 1",
                [domain_id],
                |row| row.get(0),
            )
            .optional()?;
        tx.execute(
            "INSERT INTO certificates(domain_id,serial,fingerprint,not_before,not_after,issued_at,order_url,next_renew_at,replaces_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![domain_id, serial, fingerprint, not_before, not_after, now, order_url, next_renew.to_rfc3339(), replaced],
        )?;
        tx.execute("INSERT INTO activities(run_id,domain_id,at,action,outcome,message) VALUES(?1,?2,?3,?4,'succeeded',?5)",params![run_id,domain_id,now,action,format!("{} certificate for {}",action,names.join(", "))])?;
        tx.commit()?;
        Ok(())
    }
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(());
        }
    }
    conn.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
    ))?;
    Ok(())
}
#[derive(Debug, Serialize)]
pub struct DomainRow {
    pub name: String,
    pub state: String,
    pub expires: Option<String>,
    pub next_renew: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ActivityRow {
    pub at: String,
    pub domain: String,
    pub action: String,
    pub outcome: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_store() -> (Store, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let store = Store::open(&path).unwrap();
        (store, dir)
    }

    #[test]
    fn test_store_open_creates_schema() {
        let (store, _dir) = make_store();
        let conn = store.connection();
        let tables: Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'").unwrap()
            .query_map([], |r| r.get(0)).unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(tables.contains(&"domains".to_string()));
        assert!(tables.contains(&"certificates".to_string()));
        assert!(tables.contains(&"runs".to_string()));
        assert!(tables.contains(&"activities".to_string()));
        assert!(tables.contains(&"schema_meta".to_string()));
    }

    #[test]
    fn test_record_and_list_domain() {
        let (store, _dir) = make_store();
        store.record_certificate(
            &["example.com".to_string()],
            "zerossl",
            "ec-256",
            "http-01",
            "2024-01-01T00:00:00Z",
            "2024-12-31T23:59:59Z",
            "serial123",
            "fingerprint123",
            "https://acme.example.com/order/1",
            "issue",
        ).unwrap();

        let domains = store.list().unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].name, "example.com");
        assert_eq!(domains[0].state, "active");
    }

    #[test]
    fn test_history() {
        let (store, _dir) = make_store();
        store.record_certificate(
            &["example.com".to_string()],
            "zerossl",
            "ec-256",
            "http-01",
            "2024-01-01T00:00:00Z",
            "2024-12-31T23:59:59Z",
            "serial123",
            "fingerprint123",
            "https://acme.example.com/order/1",
            "issue",
        ).unwrap();

        let history = store.history(Some("example.com"), None, 10).unwrap();
        assert!(!history.is_empty());
        assert!(history.iter().any(|h| h.action == "issue"));
    }

    #[test]
    fn test_status() {
        let (store, _dir) = make_store();
        store.record_certificate(
            &["example.com".to_string()],
            "zerossl",
            "ec-256",
            "http-01",
            "2024-01-01T00:00:00Z",
            "2024-12-31T23:59:59Z",
            "serial123",
            "fingerprint123",
            "https://acme.example.com/order/1",
            "issue",
        ).unwrap();

        let status = store.status("example.com").unwrap().unwrap();
        assert_eq!(status.name, "example.com");
        assert_eq!(status.state, "active");
    }

    #[test]
    fn test_set_domain_state() {
        let (store, _dir) = make_store();
        store.record_certificate(
            &["example.com".to_string()],
            "zerossl",
            "ec-256",
            "http-01",
            "2024-01-01T00:00:00Z",
            "2024-12-31T23:59:59Z",
            "serial123",
            "fingerprint123",
            "https://acme.example.com/order/1",
            "issue",
        ).unwrap();

        let changed = store.set_domain_state("example.com", "revoked").unwrap();
        assert!(changed);
        let status = store.status("example.com").unwrap().unwrap();
        assert_eq!(status.state, "revoked");
    }

    #[test]
    fn test_ari_window() {
        let (store, _dir) = make_store();
        store.record_certificate(
            &["example.com".to_string()],
            "zerossl",
            "ec-256",
            "http-01",
            "2024-01-01T00:00:00Z",
            "2024-12-31T23:59:59Z",
            "serial123",
            "fingerprint123",
            "https://acme.example.com/order/1",
            "issue",
        ).unwrap();

        let updated = store.set_ari_window("example.com", "2024-12-01T00:00:00Z", "2024-12-15T00:00:00Z").unwrap();
        assert!(updated);
    }

    #[test]
    fn test_store_check() {
        let (store, _dir) = make_store();
        store.check().unwrap();
    }

    #[test]
    fn test_resolve_path_precedence() {
        let dir = tempdir().unwrap();
        let cli_path = dir.path().join("cli.db");
        let env_path = dir.path().join("env.db");
        let config_path = dir.path().join("config.db");
        let default_path = dir.path().join("default.db");

        let p = resolve_path(Some(&cli_path), None, None).unwrap();
        assert_eq!(p.path, cli_path);
        assert_eq!(p.source, "cli");

        let p = resolve_path(None, Some(&env_path.to_string_lossy()), None).unwrap();
        assert_eq!(p.path, env_path);
        assert_eq!(p.source, "environment");

        let p = resolve_path(None, None, Some(&config_path)).unwrap();
        assert_eq!(p.path, config_path);
        assert_eq!(p.source, "config");
    }
}
