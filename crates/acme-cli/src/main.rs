#[cfg(not(target_os = "linux"))]
compile_error!("acme supports Linux targets only");

use acme_state::{Config, config_path, home_dir, load};
use acme_store::{Store, resolve_path};
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use rusqlite::backup::Backup;
use std::{
    fs,
    io::Write,
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Parser)]
#[command(name = "acme", version, about = "ACME certificate management")]
struct Cli {
    #[arg(long, global = true, env = "ACME_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long, global = true, env = "ACME_STORE_PATH")]
    store_path: Option<PathBuf>,
    #[arg(long, global = true)]
    no_store: bool,
    #[arg(long, global = true)]
    store_required: bool,
    #[arg(long, global = true, value_parser = ["continue", "fail"])]
    dns_wait_timeout_action: Option<String>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Request a certificate using webroot http-01 or DNS validation.
    Issue(IssueArgs),
    #[command(name = "dns-account-01")]
    DnsAccount01(DnsAccountArgs),
    #[command(name = "dns-persist-01")]
    DnsPersist01(DnsAccountArgs),
    #[command(name = "dns-alias")]
    DnsAlias(DnsAliasArgs),
    /// Renew one certificate or all managed certificates.
    Renew(RenewArgs),
    /// Copy the installed certificate and private key to explicit paths.
    InstallCert {
        #[arg(short = 'd', long)]
        domain: String,
        #[arg(long)]
        key_path: PathBuf,
        #[arg(long)]
        fullchain_path: PathBuf,
    },
    Revoke {
        #[arg(short = 'd', long)]
        domain: String,
    },
    Remove {
        #[arg(short = 'd', long)]
        domain: String,
    },
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        expiring_within: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        fail_if_expiring: bool,
    },
    History {
        #[arg(short = 'd', long)]
        domain: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(short = 'd', long)]
        domain: String,
    },
    /// Print a user-applied nginx webroot location block.
    PrintNginxSnippet {
        #[arg(short = 'w', long)]
        webroot: PathBuf,
    },
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
}
#[derive(Args)]
struct IssueArgs {
    #[arg(short = 'd', long, required = true)]
    domains: Vec<String>,
    #[arg(short = 'w', long)]
    webroot: Option<PathBuf>,
    #[arg(long)]
    dns: Option<String>,
    #[arg(long)]
    dns_profile: Option<PathBuf>,
    #[arg(long, env = "ACME_EMAIL")]
    email: Option<String>,
    #[arg(long)]
    ca: Option<String>,
    #[arg(long)]
    no_preflight: bool,
}
#[derive(Args)]
struct DnsAccountArgs {
    #[arg(short = 'd', long, required = true)]
    domains: Vec<String>,
    #[arg(long, env = "ACME_EMAIL")]
    email: Option<String>,
    #[arg(long)]
    ca: Option<String>,
    #[arg(long)]
    dns: Option<String>,
}
#[derive(Args)]
struct DnsAliasArgs {
    #[arg(short = 'd', long, required = true)]
    domains: Vec<String>,
    #[arg(long, env = "ACME_EMAIL")]
    email: Option<String>,
    #[arg(long)]
    ca: Option<String>,
    #[arg(long)]
    dns: Option<String>,
    #[arg(long, required = true)]
    target: String,
}
#[derive(Args)]
struct RenewArgs {
    #[arg(short = 'd', long)]
    domain: Option<String>,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    force: bool,
}
#[derive(Subcommand)]
enum AccountCommand {
    Register {
        #[arg(long, env = "ACME_EMAIL")]
        email: Option<String>,
        #[arg(long)]
        ca: Option<String>,
    },
}
#[derive(Subcommand)]
enum StoreCommand {
    Path,
    Check,
    Backup { file: PathBuf },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("acme: {e:#}");
        let code = if e
            .chain()
            .any(|cause| cause.is::<acme_core::DnsWaitTimeoutError>())
        {
            4
        } else {
            1
        };
        std::process::exit(code);
    }
}
fn run() -> Result<()> {
    let mut cli = Cli::parse();
    let cfg_path = config_path(cli.config.as_deref())?;
    let cfg = load(&cfg_path)?;
    anyhow::ensure!(
        matches!(cfg.dns.wait_timeout_action.as_str(), "continue" | "fail"),
        "dns.wait_timeout_action must be 'continue' or 'fail'"
    );
    let dns_timeout_action = cli
        .dns_wait_timeout_action
        .as_deref()
        .unwrap_or(cfg.dns.wait_timeout_action.as_str());
    let mut run_guard =
        if store_enabled(&cli, &cfg) && !matches!(&cli.command, Command::Store { .. }) {
            let label = command_label(&cli.command);
            match open_store(&cli, &cfg).and_then(|store| {
                let id = store.start_run(label)?;
                Ok(RunGuard {
                    store,
                    id,
                    finished: false,
                })
            }) {
                Ok(guard) => Some(guard),
                Err(error) if store_required(&cli, &cfg) => return Err(error),
                Err(error) => {
                    eprintln!("warning: could not record command run: {error:#}");
                    None
                }
            }
        } else {
            None
        };
    let command = std::mem::replace(
        &mut cli.command,
        Command::Store {
            command: StoreCommand::Path,
        },
    );
    match command {
        Command::PrintNginxSnippet { webroot } => {
            println!(
                "location ^~ /.well-known/acme-challenge/ {{\n    root {};\n}}",
                webroot.display()
            );
        }
        Command::Store { command } => store_command(&cli, &cfg, command)?,
        Command::Account {
            command: AccountCommand::Register { email, ca },
        } => {
            let email =
                email.context("--email or ACME_EMAIL is required for account registration")?;
            let (ca, custom) = acme_core::resolve_ca(&ca.unwrap_or(cfg.ca.default))?;
            let directory = ca.directory(custom.as_deref())?.to_owned();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let id = runtime.block_on(acme_core::register_account(
                &home_dir()?,
                &directory,
                &email,
            ))?;
            println!("account registered: {id}");
        }
        Command::List {
            status,
            expiring_within,
            json,
            fail_if_expiring,
        } => {
            if let Some(value) = status.as_deref() {
                anyhow::ensure!(
                    matches!(
                        value,
                        "pending"
                            | "active"
                            | "failed"
                            | "revoked"
                            | "removed"
                            | "valid"
                            | "expiring"
                            | "expired"
                            | "unknown"
                    ),
                    "invalid --status {value:?}; use a lifecycle or expiry status"
                );
            }
            let rows = open_store(&cli, &cfg)?.list()?;
            let deadline = expiring_within
                .as_deref()
                .map(parse_duration)
                .transpose()?
                .map(|d| {
                    chrono::Utc::now()
                        .checked_add_signed(
                            chrono::Duration::from_std(d).context("duration is too large")?,
                        )
                        .context("expiration deadline is out of range")
                })
                .transpose()?;
            let matches: Vec<_> = rows
                .into_iter()
                .filter(|r| {
                    let expiry = expiry_status(r);
                    status
                        .as_deref()
                        .map_or(true, |s| s == r.state || s == expiry)
                        && deadline.as_ref().map_or(true, |end| {
                            r.expires
                                .as_deref()
                                .and_then(parse_datetime)
                                .is_some_and(|at| at <= end.clone())
                        })
                })
                .collect();
            if json {
                let out:Vec<_>=matches.iter().map(|r|serde_json::json!({"domain":r.name,"state":r.state,"expiry_status":expiry_status(r),"expires":r.expires,"next_renewal":r.next_renew})).collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("DOMAIN\tSTATE\tEXPIRY\tEXPIRES\tNEXT RENEWAL");
                for r in &matches {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        r.name,
                        r.state,
                        expiry_status(r),
                        r.expires.as_deref().unwrap_or("-"),
                        r.next_renew.as_deref().unwrap_or("-")
                    );
                }
            }
            if fail_if_expiring
                && matches.iter().any(|r| {
                    matches!(expiry_status(r).as_str(), "expiring" | "expired")
                        || deadline.as_ref().is_some_and(|end| {
                            r.expires
                                .as_deref()
                                .and_then(parse_datetime)
                                .is_some_and(|at| at <= end.clone())
                        })
                })
            {
                anyhow::bail!("one or more managed certificates are expiring or expired");
            }
        }
        Command::History {
            domain,
            since,
            limit,
            json,
        } => {
            let since = since
                .as_deref()
                .map(|value| {
                    parse_datetime(value)
                        .with_context(|| format!("invalid RFC 3339 timestamp: {value}"))
                })
                .transpose()?
                .map(|date| date.to_rfc3339());
            let rows =
                open_store(&cli, &cfg)?.history(domain.as_deref(), since.as_deref(), limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?)
            } else {
                for r in rows {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        r.at, r.domain, r.action, r.outcome, r.message
                    )
                }
            }
        }
        Command::Status { domain } => {
            let store = open_store(&cli, &cfg)?;
            match store.status(&domain)? {
                Some(r) => {
                    println!(
                        "{}\nstate: {}\nexpires: {}\nnext renewal: {}",
                        r.name,
                        r.state,
                        r.expires.as_deref().unwrap_or("unknown"),
                        r.next_renew.as_deref().unwrap_or("unknown")
                    );
                    for activity in store.history(Some(&domain), None, 5)? {
                        println!(
                            "{}\t{}\t{}\t{}",
                            activity.at, activity.action, activity.outcome, activity.message
                        );
                    }
                }
                None => anyhow::bail!("domain is not managed: {domain}"),
            }
        }
        Command::Issue(a) => {
            anyhow::ensure!(
                a.webroot.is_some() ^ (a.dns.is_some() || a.dns_profile.is_some()),
                "choose exactly one of --webroot or --dns"
            );
            anyhow::ensure!(
                !(a.dns.is_some() && a.dns_profile.is_some()),
                "choose one DNS profile selector"
            );
            let email = a
                .email
                .context("--email or ACME_EMAIL is required for account registration")?;
            let ca_value = a.ca.unwrap_or_else(|| cfg.ca.default.clone());
            let (ca, custom) = acme_core::resolve_ca(&ca_value)?;
            let directory = ca.directory(custom.as_deref())?.to_owned();
            let home = home_dir()?;
            for name in &a.domains {
                acme_core::validate_identifier(name)?;
                anyhow::ensure!(
                    a.dns.is_some() || a.dns_profile.is_some() || !name.starts_with("*."),
                    "wildcard certificates require dns-01"
                );
            }
            let primary = a
                .domains
                .iter()
                .find(|name| !name.starts_with("*."))
                .context("at least one non-wildcard domain is required")?;
            let _lock = DomainLock::acquire(&home.join("certs").join(primary))?
                .context("another issue or renewal is already running for this domain")?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let provider_selector = a.dns.clone().or_else(|| {
                a.dns_profile
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
            });
            let (issued, challenge_type) = if let Some(provider) = provider_selector.as_deref() {
                let timeout = Duration::from_secs(cfg.dns.wait_timeout_seconds);
                let interval = Duration::from_secs(cfg.dns.wait_interval_seconds);
                let settle = Duration::from_secs(cfg.dns.settle_seconds);
                let issued = if provider == "manual" {
                    runtime.block_on(acme_core::issue_dns_manual(
                        &home,
                        &directory,
                        &email,
                        &a.domains,
                        Duration::from_secs(cfg.dns.wait_initial_seconds),
                        timeout,
                        interval,
                        settle,
                        &cfg.dns.quorum,
                        dns_timeout_action,
                        &cfg.defaults.key_type,
                    ))?
                } else {
                    runtime.block_on(acme_core::issue_dns_provider_manual(
                        &home,
                        &directory,
                        &email,
                        &a.domains,
                        provider,
                        Duration::from_secs(cfg.dns.wait_initial_seconds),
                        timeout,
                        interval,
                        settle,
                        &cfg.dns.quorum,
                        dns_timeout_action,
                        &cfg.defaults.key_type,
                    ))?
                };
                (issued, "dns-01")
            } else {
                let root = a
                    .webroot
                    .as_deref()
                    .context("--webroot is required for http-01")?;
                (
                    runtime.block_on(acme_core::issue_webroot(
                        &home,
                        &directory,
                        &email,
                        &a.domains,
                        root,
                        !a.no_preflight,
                        &cfg.defaults.key_type,
                    ))?,
                    "http-01",
                )
            };
            let store_result = if store_enabled(&cli, &cfg) {
                match store_path(&cli, &cfg)
                    .and_then(|p| Store::open(&p.path))
                    .and_then(|s| {
                        s.record_certificate(
                            &a.domains,
                            &ca_value,
                            &cfg.defaults.key_type,
                            challenge_type,
                            &issued.not_before,
                            &issued.not_after,
                            &issued.serial,
                            &issued.fingerprint,
                            &issued.order_url,
                            "issue",
                        )
                    }) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(e),
                }
            } else {
                Ok(())
            };
            if let Err(err) = store_result {
                if store_required(&cli, &cfg) {
                    anyhow::bail!(
                        "certificate issued at {}, but required store update failed: {err:#}",
                        issued.directory.display()
                    );
                }
                eprintln!("warning: certificate issued but store update failed: {err:#}");
            }
            persist_dns_warnings(&cli, &cfg, &issued, &a.domains)?;
            println!("certificate issued for {}", a.domains.join(", "));
            println!("certificate files: {}", issued.directory.display());
            warn_deploy_error(apply_deploy_hooks(&cfg.hooks.deploy, &issued.directory));
            warn_notification_error(runtime.block_on(send_notifications(
                &cfg.hooks.notify,
                "certificate_issued",
                &a.domains,
                &issued.not_after,
                &issued.dns_warnings,
            )));
        }
        Command::DnsAccount01(a) => {
            let email = a.email.context("--email or ACME_EMAIL is required")?;
            let ca_value = a.ca.unwrap_or_else(|| cfg.ca.default.clone());
            let (ca, custom) = acme_core::resolve_ca(&ca_value)?;
            let directory = ca.directory(custom.as_deref())?.to_owned();
            let home = home_dir()?;
            for name in &a.domains {
                acme_core::validate_identifier(name)?;
            }
            let primary = a
                .domains
                .iter()
                .find(|name| !name.starts_with("*."))
                .context("certificate requires a base DNS identifier")?;
            let _lock = DomainLock::acquire(&home.join("certs").join(primary))?
                .context("another issue or renewal is already running for this domain")?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let provider = a.dns.as_deref().filter(|value| *value != "manual");
            let issued = runtime.block_on(acme_core::issue_dns_account_manual(
                &home,
                &directory,
                &email,
                &a.domains,
                provider,
                Duration::from_secs(cfg.dns.wait_initial_seconds),
                Duration::from_secs(cfg.dns.wait_timeout_seconds),
                Duration::from_secs(cfg.dns.wait_interval_seconds),
                Duration::from_secs(cfg.dns.settle_seconds),
                &cfg.dns.quorum,
                dns_timeout_action,
                &cfg.defaults.key_type,
            ))?;
            if store_enabled(&cli, &cfg) {
                let result = store_path(&cli, &cfg)
                    .and_then(|p| Store::open(&p.path))
                    .and_then(|s| {
                        s.record_certificate(
                            &a.domains,
                            &ca_value,
                            &cfg.defaults.key_type,
                            "dns-account-01",
                            &issued.not_before,
                            &issued.not_after,
                            &issued.serial,
                            &issued.fingerprint,
                            &issued.order_url,
                            "issue",
                        )
                    });
                if let Err(error) = result {
                    if store_required(&cli, &cfg) {
                        anyhow::bail!(
                            "certificate issued at {}, but required store update failed: {error:#}",
                            issued.directory.display()
                        );
                    }
                    eprintln!("warning: certificate issued but store update failed: {error:#}");
                }
            }
            persist_dns_warnings(&cli, &cfg, &issued, &a.domains)?;
            println!("certificate issued for {}", a.domains.join(", "));
            println!("certificate files: {}", issued.directory.display());
            warn_deploy_error(apply_deploy_hooks(&cfg.hooks.deploy, &issued.directory));
            warn_notification_error(runtime.block_on(send_notifications(
                &cfg.hooks.notify,
                "certificate_issued",
                &a.domains,
                &issued.not_after,
                &issued.dns_warnings,
            )));
        }
        Command::DnsPersist01(a) => {
            let email = a.email.context("--email or ACME_EMAIL is required")?;
            let ca_value = a.ca.unwrap_or_else(|| cfg.ca.default.clone());
            let (ca, custom) = acme_core::resolve_ca(&ca_value)?;
            let directory = ca.directory(custom.as_deref())?.to_owned();
            let home = home_dir()?;
            for name in &a.domains {
                acme_core::validate_identifier(name)?;
            }
            let primary = a
                .domains
                .iter()
                .find(|name| !name.starts_with("*."))
                .context("certificate requires a base DNS identifier")?;
            let _lock = DomainLock::acquire(&home.join("certs").join(primary))?
                .context("another issue or renewal is already running for this domain")?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let provider = a.dns.as_deref().filter(|value| *value != "manual");
            let issued = runtime.block_on(acme_core::issue_dns_persist(
                &home,
                &directory,
                &email,
                &a.domains,
                provider,
                Duration::from_secs(cfg.dns.wait_initial_seconds),
                Duration::from_secs(cfg.dns.wait_timeout_seconds),
                Duration::from_secs(cfg.dns.wait_interval_seconds),
                Duration::from_secs(cfg.dns.settle_seconds),
                &cfg.dns.quorum,
                dns_timeout_action,
                &cfg.defaults.key_type,
            ))?;
            if store_enabled(&cli, &cfg) {
                let saved = store_path(&cli, &cfg)
                    .and_then(|p| Store::open(&p.path))
                    .and_then(|s| {
                        s.record_certificate(
                            &a.domains,
                            &ca_value,
                            &cfg.defaults.key_type,
                            "dns-persist-01",
                            &issued.not_before,
                            &issued.not_after,
                            &issued.serial,
                            &issued.fingerprint,
                            &issued.order_url,
                            "issue",
                        )
                    });
                if let Err(error) = saved {
                    if store_required(&cli, &cfg) {
                        anyhow::bail!(
                            "certificate issued at {}, but required store update failed: {error:#}",
                            issued.directory.display()
                        );
                    }
                    eprintln!("warning: certificate issued but store update failed: {error:#}");
                }
            }
            persist_dns_warnings(&cli, &cfg, &issued, &a.domains)?;
            println!("certificate issued for {}", a.domains.join(", "));
            println!("certificate files: {}", issued.directory.display());
            warn_deploy_error(apply_deploy_hooks(&cfg.hooks.deploy, &issued.directory));
            warn_notification_error(runtime.block_on(send_notifications(
                &cfg.hooks.notify,
                "certificate_issued",
                &a.domains,
                &issued.not_after,
                &issued.dns_warnings,
            )));
        }
        Command::DnsAlias(a) => {
            let email = a.email.context("--email or ACME_EMAIL is required")?;
            let alias = a.target;
            let ca_value = a.ca.unwrap_or_else(|| cfg.ca.default.clone());
            let (ca, custom) = acme_core::resolve_ca(&ca_value)?;
            let directory = ca.directory(custom.as_deref())?.to_owned();
            let home = home_dir()?;
            for name in &a.domains {
                acme_core::validate_identifier(name)?;
            }
            let primary = a
                .domains
                .iter()
                .find(|name| !name.starts_with("*."))
                .context("certificate requires a base DNS identifier")?;
            let _lock = DomainLock::acquire(&home.join("certs").join(primary))?
                .context("another issue or renewal is already running for this domain")?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let provider = a.dns.as_deref().filter(|value| *value != "manual");
            let issued = runtime.block_on(acme_core::issue_dns_alias(
                &home,
                &directory,
                &email,
                &a.domains,
                &alias,
                provider,
                Duration::from_secs(cfg.dns.wait_initial_seconds),
                Duration::from_secs(cfg.dns.wait_timeout_seconds),
                Duration::from_secs(cfg.dns.wait_interval_seconds),
                Duration::from_secs(cfg.dns.settle_seconds),
                &cfg.dns.quorum,
                dns_timeout_action,
                &cfg.defaults.key_type,
            ))?;
            if store_enabled(&cli, &cfg) {
                let saved = store_path(&cli, &cfg)
                    .and_then(|p| Store::open(&p.path))
                    .and_then(|s| {
                        s.record_certificate(
                            &a.domains,
                            &ca_value,
                            &cfg.defaults.key_type,
                            "dns-alias",
                            &issued.not_before,
                            &issued.not_after,
                            &issued.serial,
                            &issued.fingerprint,
                            &issued.order_url,
                            "issue",
                        )
                    });
                if let Err(error) = saved {
                    if store_required(&cli, &cfg) {
                        anyhow::bail!(
                            "certificate issued at {}, but required store update failed: {error:#}",
                            issued.directory.display()
                        );
                    }
                    eprintln!("warning: certificate issued but store update failed: {error:#}");
                }
            }
            persist_dns_warnings(&cli, &cfg, &issued, &a.domains)?;
            println!("certificate issued for {}", a.domains.join(", "));
            println!("certificate files: {}", issued.directory.display());
            warn_deploy_error(apply_deploy_hooks(&cfg.hooks.deploy, &issued.directory));
            warn_notification_error(runtime.block_on(send_notifications(
                &cfg.hooks.notify,
                "certificate_issued",
                &a.domains,
                &issued.not_after,
                &issued.dns_warnings,
            )));
        }
        Command::Renew(a) => {
            anyhow::ensure!(
                a.all ^ a.domain.is_some(),
                "choose either --all or --domain"
            );
            let result = renew(&cli, &cfg, a)?;
            match result {
                RenewResult::Renewed => {}
                RenewResult::NotDue => {
                    std::process::exit(2);
                }
                RenewResult::Failed => {
                    anyhow::bail!("renewal failed");
                }
                RenewResult::DnsTimeout => {
                    anyhow::bail!(acme_core::DnsWaitTimeoutError("DNS timeout during renewal".into()));
                }
            }
        }
        Command::InstallCert {
            domain,
            key_path,
            fullchain_path,
        } => {
            acme_core::validate_identifier(&domain)?;
            anyhow::ensure!(
                !domain.starts_with("*."),
                "wildcard domain cannot be installed as a directory name"
            );
            let cert_dir = home_dir()?.join("certs").join(&domain);
            let _lock = DomainLock::acquire(&cert_dir)?
                .context("another operation is already running for this domain")?;
            install(&cert_dir, &key_path, &fullchain_path)?;
            record_store_event(
                &cli,
                &cfg,
                &domain,
                "install",
                "succeeded",
                "certificate files installed",
            )?;
        }
        Command::Revoke { domain } => {
            acme_core::validate_identifier(&domain)?;
            anyhow::ensure!(
                !domain.starts_with("*."),
                "use the base domain to revoke a wildcard lineage"
            );
            let cert_dir = home_dir()?.join("certs").join(&domain);
            anyhow::ensure!(
                cert_dir.join("metadata.json").is_file(),
                "domain is not managed: {domain}"
            );
            let _lock = DomainLock::acquire(&cert_dir)?
                .context("another operation is already running for this domain")?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(acme_core::revoke_certificate(&cert_dir))?;
            if store_enabled(&cli, &cfg) {
                let store = open_store(&cli, &cfg)?;
                anyhow::ensure!(
                    store.set_domain_state(&domain, "revoked")?,
                    "domain is missing from the store: {domain}"
                );
            }
            println!("revoked {domain}");
        }
        Command::Remove { domain } => {
            acme_core::validate_identifier(&domain)?;
            anyhow::ensure!(
                !domain.starts_with("*."),
                "use the base domain to remove a wildcard lineage"
            );
            let cert_dir = home_dir()?.join("certs").join(&domain);
            anyhow::ensure!(
                cert_dir.join("metadata.json").is_file(),
                "domain is not managed: {domain}"
            );
            let _lock = DomainLock::acquire(&cert_dir)?
                .context("another operation is already running for this domain")?;
            if store_enabled(&cli, &cfg) {
                let store = open_store(&cli, &cfg)?;
                anyhow::ensure!(
                    store.set_domain_state(&domain, "removed")?,
                    "domain is missing from the store: {domain}"
                );
            }
            fs::remove_dir_all(&cert_dir)
                .with_context(|| format!("removing certificate files for {domain}"))?;
            println!("removed {domain}");
        }
    }
    if let Some(guard) = run_guard.as_mut() {
        guard.finish(0)?;
    }
    Ok(())
}

fn command_label(command: &Command) -> &'static str {
    match command {
        Command::Issue(_) => "issue",
        Command::DnsAccount01(_) => "dns-account-01",
        Command::DnsPersist01(_) => "dns-persist-01",
        Command::DnsAlias(_) => "dns-alias",
        Command::Renew(_) => "renew",
        Command::InstallCert { .. } => "install-cert",
        Command::Revoke { .. } => "revoke",
        Command::Remove { .. } => "remove",
        Command::List { .. } => "list",
        Command::History { .. } => "history",
        Command::Status { .. } => "status",
        Command::PrintNginxSnippet { .. } => "print-nginx-snippet",
        Command::Account { .. } => "account",
        Command::Store { .. } => "store",
    }
}

struct RunGuard {
    store: Store,
    id: i64,
    finished: bool,
}
impl RunGuard {
    fn finish(&mut self, exit_code: i32) -> Result<()> {
        self.store.finish_run(self.id, exit_code)?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for RunGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.store.finish_run(self.id, 1);
        }
    }
}
fn store_path(cli: &Cli, cfg: &Config) -> Result<acme_store::StorePath> {
    let config_value = cfg.store.path.as_deref();
    resolve_path(
        cli.store_path.as_deref(),
        std::env::var("ACME_STORE_PATH").ok().as_deref(),
        config_value,
    )
}
fn open_store(cli: &Cli, cfg: &Config) -> Result<Store> {
    anyhow::ensure!(store_enabled(cli, cfg), "the store is disabled");
    let p = store_path(cli, cfg)?;
    Store::open(&p.path).with_context(|| format!("opening store {}", p.path.display()))
}
fn store_enabled(cli: &Cli, cfg: &Config) -> bool {
    !cli.no_store
        && cfg.store.enabled
        && !matches!(
            std::env::var("ACME_STORE_ENABLED").as_deref(),
            Ok("false" | "0" | "no")
        )
}
fn store_required(cli: &Cli, cfg: &Config) -> bool {
    cli.store_required || cfg.store.required
}
fn store_command(cli: &Cli, cfg: &Config, cmd: StoreCommand) -> Result<()> {
    let p = store_path(cli, cfg)?;
    match cmd {
        StoreCommand::Path => println!("{} ({})", p.path.display(), p.source),
        StoreCommand::Check => {
            open_store(cli, cfg)?.check()?;
            println!("store is healthy: {}", p.path.display());
        }
        StoreCommand::Backup { file } => {
            let src = Store::open(&p.path)?;
            if let Some(parent) = file.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            let mut dst = rusqlite::Connection::open(&file)?;
            Backup::new(src.connection(), &mut dst)?.run_to_completion(
                100,
                std::time::Duration::from_millis(50),
                None,
            )?;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
            println!("backup written to {}", file.display());
        }
    }
    Ok(())
}
struct DomainLock(fs::File);
impl DomainLock {
    fn acquire(dir: &Path) -> Result<Option<Self>> {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        let path = dir.join(".renew.lock");
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            Ok(Some(Self(file)))
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error.into())
            }
        }
    }
}
impl Drop for DomainLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
#[derive(Debug)]
enum RenewResult {
    Renewed,
    NotDue,
    Failed,
    DnsTimeout,
}

fn renew(cli: &Cli, cfg: &Config, args: RenewArgs) -> Result<RenewResult> {
    let dns_timeout_action = cli
        .dns_wait_timeout_action
        .as_deref()
        .unwrap_or(cfg.dns.wait_timeout_action.as_str());
    let home = home_dir()?;
    let cert_root = home.join("certs");
    let dirs: Vec<PathBuf> = if args.all {
        fs::read_dir(&cert_root)
            .with_context(|| format!("reading managed certificates from {}", cert_root.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.is_dir() && p.join("metadata.json").is_file())
            .collect()
    } else {
        let domain = args.domain.as_deref().context("domain is required")?;
        acme_core::validate_identifier(domain)?;
        anyhow::ensure!(
            !domain.starts_with("*."),
            "wildcard renewal requires dns-01"
        );
        let path = cert_root.join(domain);
        anyhow::ensure!(
            path.join("metadata.json").is_file(),
            "domain is not managed: {domain}"
        );
        vec![path]
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let mut renewed = 0usize;
    let mut failures = Vec::new();
    let mut dns_timeout_failures = Vec::new();
    let mut any_due = false;
    for dir in dirs {
        let metadata = match acme_core::read_certificate_metadata(&dir) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{}: {e:#}", dir.display()));
                continue;
            }
        };
        anyhow::ensure!(
            matches!(
                metadata.challenge.as_str(),
                "http-01" | "dns-01" | "dns-account-01" | "dns-persist-01" | "dns-alias"
            ),
            "{} uses unsupported renewal challenge {}",
            dir.display(),
            metadata.challenge
        );
        let lock = match DomainLock::acquire(&dir) {
            Ok(Some(v)) => v,
            Ok(None) => {
                eprintln!("skipped {}: another renewal is running", dir.display());
                continue;
            }
            Err(e) => {
                failures.push(format!("{} lock: {e:#}", dir.display()));
                continue;
            }
        };
        let expiry = parse_datetime(&metadata.not_after)
            .context("invalid not_after in certificate metadata")?;
        let primary = metadata
            .domains
            .iter()
            .find(|n| !n.starts_with("*."))
            .context("managed lineage has no primary domain")?;
        let ari = match runtime.block_on(acme_core::renewal_window(&dir)) {
            Ok(window) => window,
            Err(error) => {
                eprintln!(
                    "warning: ARI lookup failed for {primary}: {error:#}; using stored renewal time"
                );
                None
            }
        };
        if let (Some((start, end)), true) = (&ari, store_enabled(cli, cfg)) {
            if let Err(error) = store_path(cli, cfg)
                .and_then(|p| Store::open(&p.path))
                .and_then(|store| {
                    anyhow::ensure!(
                        store.set_ari_window(primary, start, end)?,
                        "no certificate row for {primary}"
                    );
                    Ok(())
                })
            {
                eprintln!("warning: could not persist ARI window for {primary}: {error:#}");
            }
        }
        let stored_next = if store_enabled(cli, cfg) {
            store_path(cli, cfg)
                .and_then(|p| Store::open(&p.path))
                .and_then(|store| Ok(store.status(primary)?.and_then(|row| row.next_renew)))
                .ok()
                .flatten()
        } else {
            None
        };
        let now = chrono::Utc::now();
        let due = if let Some((start, _)) = ari.as_ref() {
            parse_datetime(start).is_some_and(|start| start <= now)
        } else {
            stored_next
                .as_deref()
                .and_then(parse_datetime)
                .map_or(expiry <= now + chrono::Duration::days(30), |start| {
                    start <= now
                })
        };
        if !args.force && !due {
            println!(
                "not due: {} expires {}",
                metadata.domains.join(", "),
                metadata.not_after
            );
            record_store_event(
                cli,
                cfg,
                primary,
                "renew",
                "skipped",
                "certificate is not due for renewal",
            )?;
            drop(lock);
            continue;
        }
        any_due = true;
        let result = if metadata.challenge == "dns-alias" {
            runtime.block_on(acme_core::issue_dns_alias(
                &home,
                &metadata.ca_directory,
                &metadata.email,
                &metadata.domains,
                metadata
                    .dns_alias
                    .as_deref()
                    .context("DNS alias renewal is missing its alias target")?,
                metadata.dns_profile.as_deref(),
                Duration::from_secs(cfg.dns.wait_initial_seconds),
                Duration::from_secs(cfg.dns.wait_timeout_seconds),
                Duration::from_secs(cfg.dns.wait_interval_seconds),
                Duration::from_secs(cfg.dns.settle_seconds),
                &cfg.dns.quorum,
                dns_timeout_action,
                &metadata.key_type,
            ))
        } else if metadata.challenge == "dns-persist-01" {
            runtime.block_on(acme_core::issue_dns_persist(
                &home,
                &metadata.ca_directory,
                &metadata.email,
                &metadata.domains,
                metadata.dns_profile.as_deref(),
                Duration::from_secs(cfg.dns.wait_initial_seconds),
                Duration::from_secs(cfg.dns.wait_timeout_seconds),
                Duration::from_secs(cfg.dns.wait_interval_seconds),
                Duration::from_secs(cfg.dns.settle_seconds),
                &cfg.dns.quorum,
                dns_timeout_action,
                &metadata.key_type,
            ))
        } else if metadata.challenge == "dns-account-01" {
            runtime.block_on(acme_core::issue_dns_account_manual(
                &home,
                &metadata.ca_directory,
                &metadata.email,
                &metadata.domains,
                metadata.dns_profile.as_deref(),
                Duration::from_secs(cfg.dns.wait_initial_seconds),
                Duration::from_secs(cfg.dns.wait_timeout_seconds),
                Duration::from_secs(cfg.dns.wait_interval_seconds),
                Duration::from_secs(cfg.dns.settle_seconds),
                &cfg.dns.quorum,
                dns_timeout_action,
                &metadata.key_type,
            ))
        } else if metadata.challenge == "dns-01" {
            if let Some(provider) = metadata.dns_profile.as_deref() {
                runtime.block_on(acme_core::issue_dns_provider_manual(
                    &home,
                    &metadata.ca_directory,
                    &metadata.email,
                    &metadata.domains,
                    provider,
                    Duration::from_secs(cfg.dns.wait_initial_seconds),
                    Duration::from_secs(cfg.dns.wait_timeout_seconds),
                    Duration::from_secs(cfg.dns.wait_interval_seconds),
                    Duration::from_secs(cfg.dns.settle_seconds),
                    &cfg.dns.quorum,
                    dns_timeout_action,
                    &metadata.key_type,
                ))
            } else {
                runtime.block_on(acme_core::issue_dns_manual(
                    &home,
                    &metadata.ca_directory,
                    &metadata.email,
                    &metadata.domains,
                    Duration::from_secs(cfg.dns.wait_initial_seconds),
                    Duration::from_secs(cfg.dns.wait_timeout_seconds),
                    Duration::from_secs(cfg.dns.wait_interval_seconds),
                    Duration::from_secs(cfg.dns.settle_seconds),
                    &cfg.dns.quorum,
                    dns_timeout_action,
                    &metadata.key_type,
                ))
            }
        } else {
            runtime.block_on(acme_core::issue_webroot(
                &home,
                &metadata.ca_directory,
                &metadata.email,
                &metadata.domains,
                &metadata.webroot,
                true,
                &metadata.key_type,
            ))
        };
        let issued = match result {
            Ok(v) => v,
            Err(e) => {
                if let Some(timeout) = e.downcast_ref::<acme_core::DnsWaitTimeoutError>() {
                    dns_timeout_failures.push(format!(
                        "{}: {}",
                        metadata.domains.join(", "),
                        timeout
                    ));
                }
                failures.push(format!("{}: {e:#}", metadata.domains.join(", ")));
                drop(lock);
                continue;
            }
        };
        if store_enabled(cli, cfg) {
            let saved = store_path(cli, cfg)
                .and_then(|p| Store::open(&p.path))
                .and_then(|s| {
                    s.record_certificate(
                        &metadata.domains,
                        &metadata.ca_directory,
                        &metadata.key_type,
                        &metadata.challenge,
                        &issued.not_before,
                        &issued.not_after,
                        &issued.serial,
                        &issued.fingerprint,
                        &issued.order_url,
                        "renew",
                    )
                });
            if let Err(e) = saved {
                if store_required(cli, cfg) {
                    failures.push(format!(
                        "{} issued but required store update failed: {e:#}",
                        metadata.domains.join(", ")
                    ));
                } else {
                    eprintln!("warning: renewal succeeded but store update failed: {e:#}");
                }
            }
        }
        println!(
            "renewed {} -> {}",
            metadata.domains.join(", "),
            issued.directory.display()
        );
        persist_dns_warnings(cli, cfg, &issued, &metadata.domains)?;
        warn_deploy_error(apply_deploy_hooks(&cfg.hooks.deploy, &issued.directory));
        warn_notification_error(runtime.block_on(send_notifications(
            &cfg.hooks.notify,
            "certificate_renewed",
            &metadata.domains,
            &issued.not_after,
            &issued.dns_warnings,
        )));
        renewed += 1;
        drop(lock);
    }
    if !dns_timeout_failures.is_empty() {
        return Ok(RenewResult::DnsTimeout);
    }
    if !failures.is_empty() {
        return Ok(RenewResult::Failed);
    }
    if renewed == 0 {
        println!("no certificates were renewed");
        if any_due {
            return Ok(RenewResult::Failed);
        }
        return Ok(RenewResult::NotDue);
    }
    Ok(RenewResult::Renewed)
}
fn parse_datetime(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}
fn expiry_status(row: &acme_store::DomainRow) -> String {
    let Some(expiry) = row.expires.as_deref().and_then(parse_datetime) else {
        return "unknown".into();
    };
    let now = chrono::Utc::now();
    if expiry <= now {
        return "expired".into();
    }
    let due = row
        .next_renew
        .as_deref()
        .and_then(parse_datetime)
        .unwrap_or(expiry - chrono::Duration::days(30));
    if due <= now {
        "expiring".into()
    } else {
        "valid".into()
    }
}
fn parse_duration(value: &str) -> Result<Duration> {
    let (n, multiplier) = if let Some(n) = value.strip_suffix('d') {
        (n, 86400u64)
    } else if let Some(n) = value.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = value.strip_suffix('m') {
        (n, 60u64)
    } else {
        anyhow::bail!("duration must use d, h, or m (for example 30d)")
    };
    let count: u64 = n.parse().context("invalid duration")?;
    Ok(Duration::from_secs(count.saturating_mul(multiplier)))
}
fn install(dir: &Path, key: &Path, chain: &Path) -> Result<()> {
    anyhow::ensure!(
        key != chain,
        "key and fullchain destinations must be different"
    );
    atomic_copy(&dir.join("key.pem"), key, 0o600)?;
    atomic_copy(&dir.join("fullchain.pem"), chain, 0o644)?;
    Ok(())
}

fn persist_dns_warnings(
    cli: &Cli,
    cfg: &Config,
    issued: &acme_core::IssuedCertificate,
    names: &[String],
) -> Result<()> {
    if issued.dns_warnings.is_empty() || !store_enabled(cli, cfg) {
        return Ok(());
    }
    let result = (|| -> Result<()> {
        let primary = names
            .iter()
            .find(|name| !name.starts_with("*."))
            .context("certificate has no primary DNS name")?;
        let store_path = store_path(cli, cfg)?;
        let store = Store::open(&store_path.path)?;
        for warning in &issued.dns_warnings {
            let _ = store.record_activity(primary, "dns_wait", "warning", warning)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        if store_required(cli, cfg) {
            anyhow::bail!("certificate issued but required DNS warning audit failed: {error:#}");
        }
        eprintln!("warning: could not save DNS wait warning to the store: {error:#}");
    }
    Ok(())
}

fn record_store_event(
    cli: &Cli,
    cfg: &Config,
    domain: &str,
    action: &str,
    outcome: &str,
    message: &str,
) -> Result<()> {
    if !store_enabled(cli, cfg) {
        return Ok(());
    }
    let result = store_path(cli, cfg)
        .and_then(|path| Store::open(&path.path))
        .and_then(|store| {
            store
                .record_activity(domain, action, outcome, message)
                .map(|_| ())
        })
        .with_context(|| format!("recording {action} activity for {domain}"));
    if let Err(error) = result {
        if store_required(cli, cfg) {
            return Err(error);
        }
        eprintln!("warning: could not record {action} activity for {domain}: {error:#}");
    }
    Ok(())
}

fn apply_deploy_hooks(hooks: &[acme_state::DeployHook], certificate_dir: &Path) -> Result<()> {
    for hook in hooks {
        install(certificate_dir, &hook.key_path, &hook.fullchain_path).with_context(|| {
            format!("deploying certificate to {}", hook.fullchain_path.display())
        })?;
    }
    Ok(())
}

fn warn_deploy_error(result: Result<()>) {
    if let Err(error) = result {
        eprintln!("warning: certificate deploy hook failed: {error:#}");
    }
}

async fn send_notifications(
    hooks: &[acme_state::NotifyHook],
    event: &str,
    domains: &[String],
    expires: &str,
    warnings: &[String],
) -> Result<()> {
    if hooks.is_empty() {
        return Ok(());
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    for hook in hooks {
        let url = reqwest::Url::parse(&hook.url).context("invalid notify hook URL")?;
        anyhow::ensure!(
            url.scheme() == "https"
                && url.port_or_known_default() == Some(443)
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "notify hook URLs must use standard HTTPS without embedded credentials or fragments"
        );
        let mut request = client.post(url).json(&serde_json::json!({
            "event": event,
            "domains": domains,
            "expires": expires,
            "warnings": warnings,
            "version": env!("CARGO_PKG_VERSION"),
        }));
        if let Some(variable) = hook.token_env.as_deref() {
            let token = std::env::var(variable)
                .with_context(|| format!("notify hook requires environment variable {variable}"))?;
            request = request.bearer_auth(token);
        }
        request.send().await?.error_for_status()?;
    }
    Ok(())
}

fn warn_notification_error(result: Result<()>) {
    if let Err(error) = result {
        eprintln!("warning: certificate notification failed: {error:#}");
    }
}

fn atomic_copy(src: &Path, dest: &Path, mode: u32) -> Result<()> {
    let data = fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension(format!("acme-tmp-{}", std::process::id()));
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    }
    fs::rename(&tmp, dest).with_context(|| format!("installing {}", dest.display()))?;
    if let Some(parent) = dest.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use chrono::Datelike;

    #[test]
    fn test_parse_datetime() {
        let dt = parse_datetime("2024-12-31T23:59:59Z").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 12);
        assert_eq!(dt.day(), 31);
    }

    #[test]
    fn test_parse_datetime_invalid() {
        assert!(parse_datetime("invalid").is_none());
        assert!(parse_datetime("").is_none());
    }

    #[test]
    fn test_expiry_status_expired() {
        let row = acme_store::DomainRow {
            name: "example.com".to_string(),
            state: "active".to_string(),
            expires: Some("2020-01-01T00:00:00Z".to_string()),
            next_renew: None,
        };
        assert_eq!(expiry_status(&row), "expired");
    }

    #[test]
    fn test_expiry_status_expiring() {
        let future = chrono::Utc::now() + chrono::Duration::days(15);
        let row = acme_store::DomainRow {
            name: "example.com".to_string(),
            state: "active".to_string(),
            expires: Some(future.to_rfc3339()),
            next_renew: None,
        };
        assert_eq!(expiry_status(&row), "expiring");
    }

    #[test]
    fn test_expiry_status_valid() {
        let future = chrono::Utc::now() + chrono::Duration::days(60);
        let row = acme_store::DomainRow {
            name: "example.com".to_string(),
            state: "active".to_string(),
            expires: Some(future.to_rfc3339()),
            next_renew: None,
        };
        assert_eq!(expiry_status(&row), "valid");
    }

    #[test]
    fn test_expiry_status_unknown() {
        let row = acme_store::DomainRow {
            name: "example.com".to_string(),
            state: "active".to_string(),
            expires: None,
            next_renew: None,
        };
        assert_eq!(expiry_status(&row), "unknown");
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30d").unwrap(), std::time::Duration::from_secs(30 * 86400));
        assert_eq!(parse_duration("24h").unwrap(), std::time::Duration::from_secs(24 * 3600));
        assert_eq!(parse_duration("60m").unwrap(), std::time::Duration::from_secs(60 * 60));
        assert!(parse_duration("invalid").is_err());
    }

    #[test]
    fn test_atomic_copy() {
        let src_dir = tempdir().unwrap();
        let dest_dir = tempdir().unwrap();
        let src = src_dir.path().join("source.txt");
        let dest = dest_dir.path().join("dest.txt");
        fs::write(&src, "test content").unwrap();

        atomic_copy(&src, &dest, 0o644).unwrap();
        assert!(dest.exists());
        assert_eq!(fs::read_to_string(&dest).unwrap(), "test content");
    }

    #[test]
    fn test_command_label() {
        assert_eq!(command_label(&Command::Issue(IssueArgs {
            domains: vec![],
            webroot: None,
            dns: None,
            dns_profile: None,
            email: None,
            ca: None,
            no_preflight: false,
        })), "issue");
        assert_eq!(command_label(&Command::Renew(RenewArgs {
            domain: None,
            all: false,
            force: false,
        })), "renew");
        assert_eq!(command_label(&Command::List { status: None, expiring_within: None, json: false, fail_if_expiring: false }), "list");
    }
}
