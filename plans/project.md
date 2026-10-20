# Plan: Rewriting acme.sh in Rust

The latest clone of https://github.com/acmesh-official/acme.sh is already downloaded on $HOME/projects/acme.sh

## 0. Summary of Revisions

This revision narrows scope, reworks the DNS flow, adds a SQLite store, adds agent token estimates, names the released binary **`acme`**, and **drops legacy acme.sh compatibility**:

1. **Linux only.** Windows, macOS, FreeBSD, OpenBSD, Solaris and other targets are dropped. Supported targets are Linux on x86_64 and aarch64 (optionally armv7), built as static musl binaries.
2. **No built-in hosting of validation responses.** The binary never opens a listening socket. For http-01 it only *writes* the challenge file into a directory the user specifies (the directory their nginx already serves). The standalone HTTP server, the standalone ALPN (tls-alpn-01) server, and the nginx config-rewrite mode are removed.
3. **No Apache support.** All Apache modes and `apachectl` integration are removed.
4. **No nginx reload.** The binary never runs `nginx -s reload` or any reload command, and `--reloadcmd` is removed. Reloading nginx after a renewal is the user's responsibility.
5. **DNS challenges use a configurable HTTP API client.** DNS providers are described by declarative profiles (data files) that drive a generic HTTP client to add and remove TXT records, replacing the per-provider shell plugins. The required TXT record is *always* printed to stdout as a manual fallback.
6. **DNS challenges wait for the record.** After the record is added (by API or by hand), the binary waits, with configurable delay and polling, until the record is visible in DNS or a configurable timeout expires, then continues with certificate processing in the same run. On timeout it logs a warning and submits to the CA anyway.
7. **SQLite store for domains, activities, statuses, and expirations.** A local SQLite database (default `$HOME/.acme/store.db`, configurable by CLI flag, environment variable, or config file) records managed domains, certificate expirations, and an activity history, and powers `list`, `history`, and `status` commands.
8. **Agent token estimates** are added to the roadmap (section 6), per phase and for the post-1.0 provider long tail.
9. **Released binary is named `acme`.** Not `acme-rs` or `acme.sh`. All CLI examples and packaging use this name.
10. **No legacy acme.sh compatibility.** The tool does not read, write, or migrate `~/.acme.sh/` state; does not accept acme.sh CLI flags or credential variable names; does not shell out to legacy `dnsapi`/`deploy`/`notify` scripts; and does not provide an `acme.sh` symlink or `--cron` alias. State, config, and CLI are modern and self-contained under `~/.acme/`.

Everything else from the previous plan (scheduler-free design, ARI renewal logic) is retained, minus the compat layer.

## 1. Goals and Non-Goals

**Goals**
- Produce a single, statically-linked Linux binary named **`acme`** (musl target) that replaces acme.sh for supported modes: register ACME accounts, issue, renew, install, and revoke certificates.
- Use a modern CLI, TOML config, and a clean state layout under `~/.acme/` (not `~/.acme.sh/`).
- Eliminate the fragile parts of shell: no dependence on system `openssl`, `curl`, `sed`, `awk`, or `nc`; memory-safe parsing of X.509, JWS, and config files.
- Keep a queryable local record of managed domains, their statuses and expirations, and everything the tool has done to them, in a single SQLite file whose location is user-configurable.
- Run as an unprivileged user wherever possible. The only filesystem privilege needed for http-01 is write access to the challenge directory.
- Sensible defaults aligned with common practice: ZeroSSL as default CA (including EAB), ECC P-256 as default key type, ARI-aware renewal per RFC 9773.

**Non-Goals**
- **No built-in scheduler.** No cron, systemd timer, or other scheduler management. Renewal is a command (`renew`, `renew --all`) invoked by the user's own scheduler. The binary decides *whether* a renewal is due, never *when to run*. **No cron or systemd integration features of any kind** (no installing, generating, or managing scheduler units).
- **No built-in validation server.** No HTTP server on :80, no TLS server on :443, no stateless responder. The binary writes files; the user's nginx serves them.
- **No web-server configuration management or reloading.** The binary does not parse, edit, inject into, or reload nginx, and does not support Apache at all. It runs no post-install reload command. A helper may *print* a recommended nginx snippet for the user to apply themselves.
- **No remote or server database, and no secrets in the store.** The store is a local SQLite file only. It never holds private keys, account keys, API credentials, or certificate bodies, and it is an index and history, not the only copy of anything needed to renew.
- **No non-Linux platforms.** Windows, macOS, the BSDs, Solaris, and similar are out of scope.
- **No legacy acme.sh compatibility.** No reading or migrating `~/.acme.sh/` layouts, no acme.sh-flag CLI surface, no `acme.sh` symlink, no `--cron` alias, no shell-script DNS/deploy/notify fallbacks, no preservation of acme.sh credential env var names or per-domain `.conf` shell format.
- **No ACME client libraries.** Do not use any existing ACME client crates (e.g., `acme-lib`, `acme-client`, `acme`, `letsencrypt`, etc.). The RFC 8555 / RFC 9773 implementation must be written from scratch in this codebase. Existing libraries may be consulted **only as reference source** to aid implementation decisions.
- Byte-for-byte reimplementation of shell quirks; the "works on any POSIX box with zero deps" property is intentionally traded for a compiled artifact.
- Shipping profiles for all ~150 DNS providers at launch (see phased roadmap).

## 2. Feature Inventory (What Must Be Ported)

| Area | Details | Status |
|---|---|---|
| ACME protocol core | RFC 8555 (accounts, orders, authorizations, challenges, finalize, revoke), JWS signing (ES256/ES384/RS256), nonce handling, error handling, directory caching | Port |
| Challenge types | http-01 (file output only), dns-01, dns-account-01, plus the draft dns-persist-01 flow | Port |
| Issuance modes | **webroot** (write challenge file to a specified nginx-served directory), **DNS via configurable HTTP API profiles**, DNS manual (print record + wait), DNS alias | Port |
| Key types | ECDSA P-256/P-384/P-521, RSA 2048/3072/4096, CSR generation and `sign-csr` for existing CSRs | Port |
| CA support | ZeroSSL (default, incl. EAB), Let's Encrypt, Google Public CA, SSL.com, Actalis, any RFC 8555 CA | Port |
| Lifecycle | issue → install-cert → renew (invoked externally) → remove → revoke; self-update; notifications on renewal outcome | Port |
| Renewal intelligence | RFC 9773 ARI (renewalInfo polling, `replaces=` in newOrder, suggestedWindow), stored next-renew time fallback, evaluated only when a renew command runs | Port |
| Plugin ecosystems | DNS providers as declarative HTTP API profiles (phased); deploy hooks (ssh, docker, haproxy, vault…; no nginx reload); notify hooks (mail, slack, telegram…) — all native or profile-driven, **no shell-script fallback** | Port (phased) |
| Store | SQLite database (default `$HOME/.acme/store.db`) recording domains, certificates, activities, statuses, and expirations; path configurable via CLI, environment variable, or config file | New |
| State | `~/.acme/` directory: account keys, TOML config, per-domain cert/key/CSR/fullchain and metadata | New (not acme.sh layout) |
| **Explicitly excluded** | Crontab/systemd/launchd/Task Scheduler management; standalone HTTP server; tls-alpn-01; stateless mode; nginx config-injection; reload commands; Apache; Windows/macOS/BSD/Solaris; **legacy `~/.acme.sh/` state, acme.sh CLI flags, shell plugins, migration from acme.sh** | Removed |

Notes on removed modes:
- **tls-alpn-01 is removed entirely.** It requires the client to terminate TLS on :443 with a special certificate, which conflicts with "never host verifications."
- **Standalone / stateless / nginx / Apache modes are removed** because they either host validation or manage web-server config, which is outside the output-files-only model.

## 3. Architecture

A Cargo workspace:

```
acme-rs/
├── crates/
│   ├── acme-core        # RFC 8555 client: JWS, nonce, order/authz/challenge state machine
│   ├── acme-crypto      # key generation (EC/RSA), CSR, PEM/DER, cert parsing
│   ├── acme-http        # outbound HTTP client with retries, proxy support (no server code)
│   ├── acme-challenge   # http-01 file writer (webroot), dns-01 / dns-account-01 / dns-persist-01 orchestrators
│   ├── acme-state       # ~/.acme/ state store, TOML config schema
│   ├── acme-store       # SQLite store: schema, migrations, domain/activity/expiry queries
│   ├── acme-dnsapi      # configurable HTTP DNS API client (profile engine), bundled provider profiles, native-provider trait
│   ├── acme-dnswait     # DNS propagation waiter: authoritative-NS polling, CNAME/alias following, delay/timeout policy
│   ├── acme-deploy      # deploy hooks framework (native / declarative only)
│   ├── acme-notify      # notification framework (native / declarative only)
│   └── acme-cli         # binary named `acme`: CLI parsing, command dispatch
└── xtask/               # build, Linux cross-compile (musl), packaging, release
```

The released binary is named **`acme`** (not `acme-rs` or `acme.sh`). The binary has no listening sockets and no server dependencies. There is no legacy shell-fallback path and no acme.sh state loader.

**Key crate choices**

| Concern | Crate(s) | Rationale |
|---|---|---|
| TLS (client only) | `rustls` (+ `ring` or `aws-lc-rs`) | Pure-Rust, no OpenSSL dependency, small static binaries |
| HTTP (client only) | `reqwest` (rustls backend) | No `curl` shell-outs; no `hyper` server features needed |
| Crypto | `ring` / `aws-lc-rs`, `p256`, `p384`, `rsa`, `x509-parser`, `der` | Keys, CSRs, JWS |
| JWS | `josekit` or hand-rolled on `ring` | ACME's JWS profile is small; hand-rolling on `ring` is feasible — **no ACME client crates** |
| Async | `tokio` (client-side only) | Parallel domain validation, parallel provider calls |
| DNS lookups | `hickory-resolver` (client only) | Query authoritative nameservers directly for TXT/CNAME/NS during the propagation wait |
| SQLite | `rusqlite` (`bundled` feature) + embedded migrations | SQLite is statically linked into the musl binary; no system `libsqlite3` dependency |
| Profile engine | `serde` + `toml`, `minijinja` (sandboxed templates), `serde_json_path` | Declarative request templates and response extraction; no code execution in profiles |
| CLI | `clap` v4 (derive) | Strong help generation; modern subcommand style |
| Config | TOML (`~/.acme/config.toml`) | Single structured format; no shell `KEY=VALUE` parsers |
| Filesystem | `rustix` / `nix` | `O_NOFOLLOW`, `O_EXCL`, `fsync`, and permission control for challenge-file writes |
| Logging | `tracing` + `tracing-subscriber` | Structured levels, `--debug` mapping |
| Time | `time` or `jiff` | Renewal-due evaluation, ARI windows |

**Explicitly forbidden:** any crate whose primary purpose is ACME client functionality (e.g., `acme-lib`, `acme-client`, `acme`, `letsencrypt`, `lego`, etc.). The ACME protocol implementation must be native to this codebase.

## 4. Design (Modern Only)

**State directory.** Everything lives under `$ACME_HOME` (default `~/.acme/`):

- `config.toml` — global settings (CA, defaults, store path, DNS wait defaults).
- `account/` — account keys and CA registration metadata (PEM + TOML).
- `certs/<domain>/` — key, cert, fullchain, CSR, and a small TOML sidecar for per-domain options (webroot path, DNS profile name, install paths, key type).
- `store.db` — SQLite index and activity log (see below); may be relocated via config.

No `~/.acme.sh/` layout is read or written. Users migrating from acme.sh re-issue or copy cert/key files manually and reconfigure domains with the new CLI; there is no automated migration tool.

**CLI surface.** Modern, normalized subcommands only; the binary is invoked as **`acme`**:

```
acme issue -d example.com -w /var/www/html
acme issue -d example.com --dns cloudflare
acme renew -d example.com [--force]
acme renew --all
acme install-cert -d example.com --key-path ... --fullchain-path ...
acme revoke -d example.com
acme remove -d example.com
acme list [--status ...] [--expiring-within 30d]
acme history [-d example.com]
acme status -d example.com
acme print-nginx-snippet -w /path
acme store path | check | backup <file>
```

There is no compat flag layer, no `acme.sh` symlink, and no `--cron` alias. Schedulers should invoke `acme renew --all` directly. Flags that existed only in removed modes (`--standalone`, `--alpn`, `--stateless`, `--apache`, `--nginx`, `--reloadcmd`) are not recognized.

**http-01 via webroot (the only file-based mode).**
- `-w /path/to/served/dir` names the directory that the user's nginx already serves for `/.well-known/acme-challenge/`.
- The binary creates `<dir>/.well-known/acme-challenge/` if missing, writes `<token>` containing the key authorization, then removes the file after validation (success or failure).
- The user is responsible for configuring nginx to serve that directory on port 80 for each domain. The binary never edits nginx config and never reloads nginx, for validation or otherwise.
- **Preflight self-check (on by default):** after writing the file and before notifying the CA, the binary fetches `http://<domain>/.well-known/acme-challenge/<token>` using its own HTTP client. A failure produces a precise diagnostic (DNS not pointing here, nginx not serving the directory, redirect loop, wrong root) instead of waiting for the CA to report a generic error. Disable with `--no-preflight`.
- **`acme print-nginx-snippet -w /path`** prints a ready-to-paste `location ^~ /.well-known/acme-challenge/ { root /path; }` block. It prints only; it touches no files.
- **Hardening for the file writer:** token filenames are validated against the base64url charset before any path is built; writes use `O_NOFOLLOW`/`O_EXCL`; the challenge directory is created `0755` and files `0644`; the binary refuses to follow symlinks inside the challenge path; cleanup runs on every exit path, including errors and signals.

**Certificate installation and nginx.** `install-cert` copies the key and fullchain to the paths the user specifies (nginx's `ssl_certificate` / `ssl_certificate_key` locations) and stops there. **It does not reload nginx and does not run any post-install command.** To pick up a renewed certificate, the user's own scheduler or wrapper script reloads nginx when `acme renew` exits with the "renewed" code. Files are written atomically (temp file + `fsync` + rename) so a reload by the user at any time never sees a partial certificate.

**DNS challenge flow (dns-01, dns-account-01, dns-persist-01).** Every DNS-validated identifier goes through the same sequence:

1. **Print the record (always).** Before any API call, each required TXT record is printed to stdout in a stable format; logs and diagnostics go to stderr so stdout can be captured. This happens whether or not a provider is configured, so it doubles as the manual fallback.
   ```
   DNS record required:
     Name:  _acme-challenge.example.com
     Type:  TXT
     Value: <token-derived value>
     TTL:   60 (suggested)
   ```
   `--output json` emits the same data as JSON lines for scripting.
2. **Add via API (if a provider is configured).** All records for all identifiers are added first. Several values may share one name (for example `example.com` plus `*.example.com`), so add never overwrites an existing TXT value and removal deletes only the value it added. If the API call fails, the default (`--dns-api-failure manual`) keeps the record printed and proceeds to the wait step so the user can add it by hand; `--dns-api-failure fail` aborts instead.
3. **Wait for the record to be visible.** The binary waits, then polls, until the expected value is returned by DNS or the wait timeout expires (details below). Either way, it then proceeds to the next step.
4. **Continue.** Once the record is confirmed, or the wait has timed out (in which case a warning is logged), the binary notifies the CA, polls the authorization, finalizes the order, downloads the certificate, and installs it, all in the same invocation. There is no interactive prompt, so the flow works under any scheduler.
5. **Clean up.** Records added through the API are removed on every exit path (success, failure, signal). For manually added records, the binary prints that the record can now be removed.

**Propagation wait (`acme-dnswait`).**
- **Delay and polling:** `--dns-wait-initial` (initial delay before the first check, default 10s), `--dns-wait-interval` (poll interval, default 10s), `--dns-wait-timeout` (maximum total time to wait for the record to become visible; default 5 min when the record was added by API, 15 min in manual mode; `0` skips polling entirely). Defaults are proposals to be tuned in testing.
- **What is polled:** the authoritative nameservers for the zone, queried directly (discovered via NS lookups walking up the name). By default *all* authoritative servers must return the value (`--dns-wait-quorum all|any`). CNAME chains are followed so DNS alias mode checks the alias zone. An optional public resolver check is available via `--dns-wait-resolver`.
- **Settle time:** `--dns-settle` adds a short extra delay (default 5s) after the record is first seen, to account for CA-side resolver caching.
- **On timeout, proceed anyway with a warning:** when the timeout expires before every record is confirmed, the binary logs a warning to stderr, then notifies the CA and continues with certificate processing as normal. The warning names each unconfirmed record (name and which nameservers did not return the value), the time waited, and the timeout setting. The warning does not change the exit code: if the CA validates and the certificate is issued, the run succeeds. If the CA's validation then fails, the error message references the earlier timeout warning so the cause is clear. Warnings also go through the configured notification hooks when a renewal run is unattended. The stricter behavior is opt-in: `--dns-wait-timeout-action fail` aborts before contacting the CA, removes added records, and exits with a distinct exit code (useful when failed-validation rate limits are a concern).
- **Multiple records:** all records are polled in parallel; the wait ends when every one is confirmed or the timeout is reached.

**Configurable HTTP API client for DNS providers (`acme-dnsapi`).** A single generic HTTP client is driven by declarative **provider profiles** (TOML) that describe how to add and remove a TXT record.
- **Profile contents:** base URL and allowed hosts; auth scheme; ordered request steps for `zone_lookup`, `add`, `find` (locate a previously added record, so removal works even after a crash), and `remove`. Each step has a method, URL template, headers, JSON or form body template, expected status codes, and response extraction (JSON path) into variables that later steps can use (`zone_id`, `record_id`).
- **Template variables:** `{{ fulldomain }}`, `{{ txt_value }}`, `{{ zone }}`, `{{ ttl }}`, `{{ env.NAME }}` for credentials. Templates are sandboxed (`minijinja`): no file, process, or network access.
- **Auth schemes built into the engine:** bearer token, custom header, basic auth, query-parameter key, OAuth2 client-credentials, plus native signers for the few schemes that cannot be expressed as templates (AWS SigV4 for Route53, service-account JWT for Google Cloud DNS).
- **Zone discovery:** walks parent labels of the domain until the zone lookup succeeds.
- **Selection:** `--dns cloudflare` selects the bundled profile `cloudflare`. User profiles load from `~/.acme/dnsapi.d/*.toml` or `--dns-profile ./foo.toml`, so a new provider needs no recompilation. Credential env vars use a consistent `ACME_DNS_<PROVIDER>_…` (or profile-declared) naming scheme — not the historical acme.sh names.
- **Resilience:** per-request timeouts, retries with backoff on 429/5xx, `Retry-After` honored.
- **Safety:** a profile may only call hosts it declares in `allowed_hosts`, and redirects to other hosts are refused, so a bad profile cannot send credentials elsewhere. Credentials come from environment variables or the stored per-domain config (mode `0600`), and are redacted from all logs, debug output, and error messages.
- **Illustrative profile (Cloudflare-style):**
  ```toml
  name = "cloudflare"
  allowed_hosts = ["api.cloudflare.com"]
  base_url = "https://api.cloudflare.com/client/v4"

  [auth]
  type = "bearer"
  token = "{{ env.ACME_DNS_CLOUDFLARE_TOKEN }}"

  [[zone_lookup]]            # tried for each parent label until one succeeds
  method = "GET"
  url = "/zones?name={{ candidate_zone }}"
  extract = { zone_id = "$.result[0].id" }

  [[add]]
  method = "POST"
  url = "/zones/{{ zone_id }}/dns_records"
  json = { type = "TXT", name = "{{ fulldomain }}", content = "{{ txt_value }}", ttl = 120 }
  expect_status = [200]
  extract = { record_id = "$.result.id" }

  [[remove]]
  method = "DELETE"
  url = "/zones/{{ zone_id }}/dns_records/{{ record_id }}"
  expect_status = [200]
  ```
- **Escape hatches:** a native `DnsProvider` trait (`add_txt`, `rm_txt`) remains for providers whose logic cannot be expressed declaratively. **There is no shell-script fallback.**
- **Priority providers:** Cloudflare, Route53, DigitalOcean, GoDaddy, AliDNS, DNSPod, Namecheap, Google Cloud DNS, Azure DNS, OVH, Vultr, Linode, Hetzner, Porkbun, deSEC, NS1, Gandi, ClouDNS, DuckDNS, LuaDNS get bundled profiles first.
- Since wildcard certificates require dns-01, DNS challenges (API or manual) are the only path for wildcards in this design.

**Renewal model (scheduler-free).** The binary exposes:
- `acme renew -d example.com [--force]`: renew one cert if due.
- `acme renew --all`: iterate managed domains, evaluating each cert in order: force flag → ARI suggestedWindow started → stored next-renew time passed. Exit codes distinguish "renewed", "not due", and "failed" so external schedulers and monitoring can react.
- `acme status` / `list` report next renewal times so a human or scheduler can plan.
- First-run / install docs print a suggested **cron line and systemd timer/service unit** for the user to adopt. The printed snippets show only the renew command; any nginx reload step is left for the user to add.

**SQLite store (`acme-store`).** A local SQLite database records the domains the tool manages, what it has done to them, their statuses, and when their certificates expire.

*Location and configuration.* The default path is `$HOME/.acme/store.db`. The path is resolved in this order, first match wins:
1. CLI flag: `--store-path <file>`
2. Environment variable: `ACME_STORE_PATH`
3. Config file: `[store] path = "<file>"` in `~/.acme/config.toml` (the config file itself can be relocated with `--config <file>` or `ACME_CONFIG`)
4. Built-in default: `$HOME/.acme/store.db`

`~` is expanded, relative paths resolve against the working directory, the parent directory is created with mode `0700`, and the file is created `0600`. `acme store path` prints the resolved path and which of the four sources supplied it. The store can be disabled with `--no-store`, `ACME_STORE_ENABLED=false`, or `store.enabled = false`.

```toml
# ~/.acme/config.toml (illustrative)
[store]
path = "/var/lib/acme/store.db"   # optional; default is $HOME/.acme/store.db
enabled = true
required = false                       # true: store errors abort the run
```

*What it stores (sketch schema).*
- `domains`: one row per managed certificate lineage: primary name, SAN list (child table `domain_names`), CA, key type, challenge type (webroot or DNS), webroot path or DNS profile *name*, install paths, lifecycle state, created/updated timestamps.
- `certificates`: one row per issued certificate: serial, SHA-256 fingerprint, `not_before`, `not_after`, issue time, ACME order URL, a link to the certificate it replaced, ARI `suggested_window_start`/`suggested_window_end` and `ari_checked_at`, and `next_renew_at`.
- `runs`: one row per invocation: command, binary version, start and end time, exit code.
- `activities`: append-only event log linked to a run and a domain: timestamp, action (`issue`, `renew`, `revoke`, `remove`, `install`, `webroot_preflight`, `dns_record_added`, `dns_wait`, `ca_validation`, `finalize`, `ari_poll`, ...), outcome (`started`, `succeeded`, `failed`, `skipped`, `warning`), message, ACME problem type when present, JSON details, and duration. A DNS wait timeout (which proceeds to the CA with a warning) is recorded as a `warning` activity.
- `schema_meta`: schema version.
- **Never stored:** private keys, account keys, API tokens or other credentials, or certificate bodies (those stay on disk as files). DNS profiles are referenced by name only, and activity details pass through the same redaction as logs.

*Status and expirations.* Only lifecycle state is stored: `pending`, `active`, `failed`, `revoked`, `removed`. Because the tool has no background scheduler to keep rows fresh, expiry-related status is **derived at read time** from `not_after`, the renewal threshold, and the ARI window: `valid`, `expiring` (renewal due or ARI window started), or `expired`. A `list` run therefore never shows stale expiry status.

*Commands.*
- `acme list [--status <s>] [--expiring-within 30d] [--json]`: managed domains with status and expiration. `--fail-if-expiring` exits non-zero when any domain matches, so external monitoring can alert on it.
- `acme history [-d example.com] [--since <time>] [--limit N] [--json]`: the activity log.
- `acme status -d example.com`: one domain's state, current certificate, next renewal time, and last activities.
- `acme store path | check | backup <file>`: store maintenance. `backup` uses SQLite's online backup so it is safe while other runs are active.

*Relationship to on-disk state.* Certificates, keys, and CSRs stay on disk under `~/.acme/certs/`. The store is the metadata index and history. Renewal-due evaluation reads `next_renew_at` and the ARI window from the store. After each successful issue or renewal both are updated.

*Failure behavior.* By default a store problem (locked, unwritable, corrupt, or a newer schema) logs a warning and does **not** block issuance or renewal. `--store-required` / `store.required = true` makes store failures fatal for users who need a guaranteed audit trail. A corrupt file is never deleted automatically; the warning points to `store check`.

*Concurrency and safety.* The database uses WAL mode, a busy timeout, and short transactions, so overlapping scheduler runs are safe. A per-domain `flock` lock file prevents two concurrent renewals of the same domain from both contacting the CA; the second run records a `skipped` activity and exits with the "not due/skipped" code. Embedded forward-only migrations are tracked with `PRAGMA user_version` and applied on open after taking a pre-migration copy; a database with a newer schema than the binary understands is opened read-only with a warning.

*Retention: records are kept in perpetuity.* The tool never deletes or expires rows. `runs` and `activities` are append-only, and `domains` and `certificates` rows are never removed: when a domain is removed or a certificate is revoked or replaced, its row is marked (`removed`, `revoked`, or linked to its replacement) and stays in the store as history. There is no retention setting and no prune command. Growth is expected to be modest and is handled by `store backup` and by SQLite maintenance (`VACUUM`/`ANALYZE`, run by `store check`) rather than by discarding history.

## 5. Testing Strategy

1. **Unit tests** for JWS, base64url, thumbprints, PEM/DER round-trips, config parsing, renewal-due arithmetic, and challenge-token validation/path construction.
2. **Protocol integration tests** against [Pebble](https://github.com/letsencrypt/pebble) in CI: full issue/renew/revoke flows for **http-01 (webroot, with a real nginx container serving the challenge directory)** and dns-01 (via Pebble's challenge test server), including Pebble's "strict" and random-failure modes; plus ZeroSSL's staging CA for EAB paths.
3. **DNS flow tests:** stdout record format snapshots (including `--output json`); API failure falls back to printed record plus wait; same-name multi-value add/remove leaves other values intact; propagation wait against a test authoritative DNS server (record appears late, appears on only some nameservers, never appears → warning logged and CA submission still happens, CNAME alias chain; `--dns-wait-timeout-action fail` aborts before the CA; `--dns-wait-timeout 0` skips polling); cleanup on failure and SIGTERM.
4. **Provider profile tests:** every bundled profile runs add/find/remove against a mock HTTP server (request/response replay); template rendering and extraction unit tests; host allowlist and cross-host redirect refusal; secret redaction in logs and errors; retry/backoff on 429/5xx.
5. **Webroot-specific tests:** missing directory creation, read-only directory error messages, symlink-in-path rejection, cleanup after failure/SIGTERM, preflight self-check success and each failure diagnostic (wrong root, redirect, DNS mismatch).
6. **CLI snapshot tests** for exit codes and key output of the modern command surface (`acme …`).
7. **Linux CI matrix:** x86_64 and aarch64; glibc and musl; container images (alpine, debian-slim, scratch). No Windows/macOS/BSD runners.
8. **Fuzzing** with `cargo-fuzz` on X.509 parsing, directory JSON, config files, and provider profile / template parsing.
9. **Store tests:** path resolution precedence (CLI > env > config file > default) including `~` expansion and the `store path` source report; directory/file permissions (`0700`/`0600`); migration from each prior schema version and refusal to write a newer schema; concurrent writers from several processes; per-domain lock prevents double renewal; store unavailable, read-only, and corrupt cases (default continues with a warning, `--store-required` fails); derived expiry status at boundary times; records are never deleted (domain removal, revocation, and replacement leave history intact, and no code path issues a `DELETE` on `runs`, `activities`, `domains`, or `certificates`); confirmation that no key material or credentials appear in any table (secret-scanning test over a full issue/renew run).

## 6. Phased Roadmap (Agentic Implementation)

Estimated assuming implementation by AI coding agents, with a human supervising architecture decisions, reviewing security-critical diffs, and running anything that touches live CAs or production DNS credentials. Code generation is no longer the bottleneck; verification, integration testing against live services, and review throughput are.

**Assumptions**
- Agents work from detailed specs (this plan); a human provides repo access, Pebble/staging environments, and API credentials for DNS providers.
- Wall-clock estimates assume parallel agent runs where dependencies allow.
- Human review is sized for a security-sensitive codebase (crypto, JWS, file writes into web-served directories).

| Phase | Scope | Wall-clock | Human involvement |
|---|---|---|---|
| 0. Foundations | Workspace scaffolding, **Linux-only** CI matrix, crypto/JWS/HTTP-client layers, state model (`~/.acme/`), **`acme-store` schema, migrations, and path/config resolution**; binary name `acme` | **2–3 days** | High upfront: human locks architecture, crate choices, and state schema before agents fan out |
| 1. Core issuance | ACME state machine, **webroot http-01 writer + preflight self-check**, dns-01 orchestrator with stdout record output and the propagation wait (`acme-dnswait`), key/CSR handling | **~1–1.5 weeks** | Human reviews JWS signing, poll/retry logic, and the challenge-file writer (path validation, symlink handling, cleanup) line-by-line; runs first Pebble issue manually |
| 2. Lifecycle | Renew/revoke/remove, install-cert (atomic file install only, no reload), renewal-due evaluation with ARI (RFC 9773), **recording runs/activities/statuses/expirations in the store, `list`/`history`/`status` commands**, exit-code contract | **~1 week** | Human validates renewal-due edge cases (ARI window vs. stored time) and exit-code semantics for external schedulers |
| 3. DNS providers & hooks | **Profile engine (configurable HTTP API client)**, bundled profiles for top 20 providers, native trait (no shell fallback), deploy/notify hooks | **2–4 weeks for top 20** | Human reviews the profile engine's auth handling, host allowlist, and secret redaction line-by-line; holds live DNS API credentials, since each profile needs one real add/find/remove TXT test only a credentialed human/CI secret can run |
| 4. Polish & release | `print-nginx-snippet`, DNS alias / dns-persist, Linux packaging (static tarballs named `acme`, deb, rpm, apk, container image), docs including "you must schedule renewal and configure nginx yourself" — with **example cron line and systemd timer unit printed as user documentation only** (no tool generates/installs them), and migration notes for acme.sh users (manual reconfigure) | **~1 week** | Human approves release and reviews docs for clarity |

**Totals**
- **Agentic estimate:** **~4–6 weeks wall-clock** to v1.0. Phase 3 (DNS providers & hooks) runs in parallel with phase 4 where possible.
- Compared with the previous revision, this removes: the standalone HTTP and ALPN servers, tls-alpn-01, nginx config parsing and injection, all Apache work, the entire non-Linux verification matrix, **and the entire legacy compatibility / migration surface** (state loader, CLI compat layer, golden acme.sh fixtures, shell fallbacks, `store import`/`reconcile` from acme.sh).
- Provider porting continues post-1.0 at near-zero marginal cost: each remaining provider is a self-contained agent task (write a TOML profile → replay test against a mock HTTP server), with no Rust changes or recompilation, gated only by credential availability for live tests.

**Agent token estimates**

These are rough, order-of-magnitude figures for planning budgets, not measurements. They are model-agnostic and expressed in tokens, not money, because pricing and caching discounts vary by model and provider.

- **Output tokens** are everything agents generate: code, edits, tool calls, and reasoning, including rewrites and fixes, not just the final code that lands in the repo.
- **Total tokens processed** is output plus all input read across turns, including re-reads of cached context. In long agentic sessions this is 20-40x the output figure and is what usage limits and bills are typically based on.
- Running agents in parallel shortens wall-clock time but does not reduce total tokens.

| Phase | Output tokens | Total tokens processed | Main drivers |
|---|---|---|---|
| 0. Foundations | ~0.3-0.6M | ~8-20M | Scaffolding, crypto/JWS/HTTP layers, modern state model, store schema and migrations (~5-8k lines of Rust) |
| 1. Core issuance | ~0.8-1.5M | ~25-50M | ACME state machine, webroot writer, dns-01 orchestrator and propagation wait, key/CSR handling (~10-15k lines); Pebble debugging loops |
| 2. Lifecycle | ~0.5-1.0M | ~15-35M | Renew/revoke, ARI renewal logic, store recording, `list`/`history`/`status` (~7-10k lines); exit-code and edge-case tests |
| 3. DNS providers & hooks | ~0.8-2.0M | ~32-85M | Profile engine (~5-8k lines) plus 20 bundled profiles, deploy/notify hooks |
| 4. Polish & release | ~0.3-0.6M | ~8-18M | `print-nginx-snippet`, DNS alias/dns-persist, packaging, docs |
| **Subtotal** | **~2.7-5.7M** | **~88-208M** | |
| Contingency (+25-40%) | ~0.7-2.3M | ~22-83M | Failed attempts, rework after human review, flaky-CI triage, agent-run review passes |
| **Estimated total to v1.0** | **~3.5-8M** | **~110-290M** | |

- **Post-1.0 provider long tail:** each additional DNS provider profile costs roughly ~20-60k output and ~1-3M total tokens. The remaining ~130 providers come to roughly ~2.6-7.8M output and ~130-390M total tokens, in independent sessions that can run in parallel.
- **Biggest sources of variance:** debugging loops against Pebble and staging CAs (Phases 1-2), rework after security review of the JWS, challenge-file writer, and profile-engine code, and how much context each agent session must re-read.
- **Not included:** human use of AI tools outside the agent runs, and any live-service testing costs (CA, DNS provider, or CI infrastructure charges).

**What actually gets faster vs. what doesn't**

*Compresses dramatically (10–30×):*
- Implementing ACME, webroot, and DNS orchestration from a clean spec (no need to mirror shell quirks).
- Unit tests, fixtures, mock-HTTP harnesses, CLI snapshot tests.
- Boilerplate: clap definitions, config schemas, packaging, docs.
- The provider long tail: embarrassingly parallel, one profile per agent session.

*Compresses only modestly (2–3×):*
- Integration testing against Pebble/staging CAs: bounded by CA rate limits and real polling delays.
- Security review of crypto/JWS and the challenge-file writer: human reading speed is the hard limit, and this is the one place not to cut.

*Doesn't compress at all:*
- Live DNS provider credential testing, CA rate-limit windows, and judgment calls on product edge cases.

Dropping non-Linux platforms, server/web-server-config code, and **legacy compatibility** removes the slowest verification items (cross-OS matrix, golden acme.sh fixtures, lossless migration) and the most security-sensitive surface that was not needed (config rewriter, long-running listener). The critical path is human review bandwidth and live-service validation.

## 7. Risks and Mitigations

- **Provider ecosystem is the moat.** Mitigation: declarative profiles (no Rust needed per provider) + agent-generated profiles. Users who relied on unported shell plugins must use manual DNS or wait for a profile.
- **Profile engine expressiveness.** Some providers have unusual auth or multi-step flows that templates can't capture. Mitigation: built-in signers for the known hard cases (SigV4, service-account JWT) and the native `DnsProvider` trait.
- **Secrets in profiles and logs.** The engine handles API credentials for production DNS. Mitigation: credentials only via env vars or `0600` config, never inlined in profiles, redacted everywhere, host allowlist enforced, sandboxed templates, and mandatory human review of the engine.
- **Propagation wait vs. CA behavior.** Authoritative servers may show the record before the CA's resolvers do, and split-horizon or delegated zones can mislead polling. Mitigation: configurable settle delay, quorum setting, CNAME/alias following, optional public-resolver check, and, because a wait timeout proceeds to the CA by default, a clear warning naming the unconfirmed records plus the opt-in `--dns-wait-timeout-action fail` for users who want to protect failed-validation rate limits.
- **Long-running wait in a scheduled job.** A renewal can block for the length of the wait timeout. Mitigation: bounded, configurable timeouts and documentation for scheduler job timeouts; a timeout produces a warning and continues rather than failing the run.
- **Behavioral differences from acme.sh.** This is intentional: no drop-in replacement for scripts, cron lines, or state directories. Mitigation: docs lead with a clear "not a drop-in" statement and a short manual migration guide (copy certs if desired, re-issue or re-register domains with the new CLI, point the scheduler at `acme renew --all`).
- **Certificates not picked up after renewal.** With no reload command, a renewed certificate sits on disk until the user reloads nginx. Mitigation: documentation leads with this; the "renewed" exit code gives wrappers a reliable trigger.
- **Users without a web server on :80.** Hosts that previously used standalone mode need nginx (or another server they configure themselves) serving the challenge directory, or must switch to dns-01. Mitigation: documentation leads with this; the preflight self-check and `print-nginx-snippet` reduce setup friction.
- **Challenge-file writer as a security surface.** A bug in path handling could write attacker-influenced content or follow symlinks in a web-served directory. Mitigation: strict base64url token validation, `O_NOFOLLOW`/`O_EXCL`, no path joins from unvalidated input, fuzzing of the token/path logic, and mandatory human line-by-line review.
- **Scheduler removal as a product expectation.** Users may expect renewal to "just happen." Mitigation: docs and first-run output print ready-to-use cron and systemd-timer snippets.
- **Store drift from on-disk state.** Two records of the same facts can disagree (for example a user edits or deletes cert files by hand). Mitigation: files remain authoritative for key material; `status` flags certificates whose files are missing or whose fingerprint differs from the stored one.
- **Store failures affecting renewals.** A locked or corrupt database must not cause a missed renewal. Mitigation: store errors are warnings by default, WAL plus busy timeout for overlapping runs, no automatic deletion of a corrupt file, and opt-in `--store-required` for users who prefer failing closed.
- **Metadata exposure.** The store lists every domain name and activity. Mitigation: `0600` file in a `0700` directory, no credentials or key material stored, redaction of activity details, and documentation for choosing a custom path on shared hosts.
- **Concurrent renewals of one domain.** Overlapping scheduler runs could double-submit orders. Mitigation: per-domain `flock` lock with a recorded `skipped` activity.
- **Token and compute cost overruns.** Long debugging loops against live-like services can multiply token use well past the estimates. Mitigation: per-session token budgets, small well-scoped agent tasks with a human-approved module map, caching of stable context (this plan and module specs), reusing Pebble fixtures, and tracking actual tokens per phase against the estimates.
- **Agent-specific risks:** subtle divergence when agents parallelize interdependent modules; over-eager refactoring. Mitigation: a human-approved module map before fan-out, per-phase diff review, and CLI/protocol snapshot tests.
- **Linux architecture and libc coverage.** Routers and embedded Linux (OpenWRT-class) may need armv7 or MIPS targets. Mitigation: document supported targets honestly (x86_64, aarch64 at v1.0; armv7 best-effort); keep musl static builds small.
- **Licensing:** acme.sh is GPLv3. The rewrite should be GPLv3 (or dual GPL/Apache only if written clean-room) to avoid license friction and respect contributors.

## 8. Success Metrics

- All RFC 8555 + RFC 9773 flows green in CI against Pebble and staging CAs for **webroot http-01 (behind a real nginx) and dns-01**.
- Modern CLI and `~/.acme/` state are the only supported interface; no code paths read or write `~/.acme.sh/`.
- The released binary is named **`acme`** in all packaging artifacts (tarball, deb, rpm, apk, container).
- The binary spawns **no nginx or reload processes** in any command path (verified in CI).
- The binary opens **zero listening sockets** in every command path (verified in CI).
- Static musl binary < 10 MB stripped, < 20 MB RSS during issuance, zero external runtime dependencies.
- The store defaults to `$HOME/.acme/store.db` and is overridable by CLI flag, environment variable, and config file, in that precedence order, verified by tests.
- `list --expiring-within` and `history` return correct results after a full issue, renew, and failed-renew sequence, and a store failure never causes a missed renewal unless `--store-required` is set.
- ≥ 20 DNS provider profiles bundled at v1.0; a user can add a new provider by writing a TOML profile, with no recompilation, and a documented agent-driven path covers the rest.
- Every dns-01 run prints the required TXT record(s) to stdout before any API call, whether or not a provider is configured.
- DNS issuance proceeds from record creation to certificate installation in a single invocation, with the wait step covered by tests for late, partial, and never-appearing records.
- No shell-outs to external DNS/deploy/notify scripts in any code path.
