```
⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛
⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛
⬛⬛⬛⏺️⏺️⏺️⬛⏺️⏺️⏺️⏺️⬛⏺️⏺️⏺️⏺️⏺️⬛⏺️⏺️⏺️⏺️⬛⬛
⬛⬛⬛⬛⬛⏺️⬛⏺️⬛⬛⬛⬛⏺️⬛⏺️⬛⏺️⬛⏺️⬛⬛⏺️⬛⬛
⬛⬛⏺️⏺️⏺️⏺️⬛⏺️⬛⬛⬛⬛⏺️⬛⏺️⬛⏺️⬛⏺️⏺️⏺️⏺️⬛⬛
⬛⬛⏺️⬛⬛⏺️⬛⏺️⬛⬛⬛⬛⏺️⬛⏺️⬛⏺️⬛⏺️⬛⬛⬛⬛⬛
⬛⬛⏺️⏺️⏺️⏺️⬛⏺️⏺️⏺️⏺️⬛⏺️⬛⏺️⬛⏺️⬛⏺️⏺️⏺️⏺️⬛⬛
⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛
⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛
```

`acme` is a standalone ACME client.

## Commands

```sh
acme account register --email admin@example.com --ca letsencrypt
acme issue -d example.com -w /var/www/html --email admin@example.com --ca letsencrypt
acme issue -d example.com --dns manual --email admin@example.com --ca letsencrypt
acme dns-account-01 -d example.com --email admin@example.com --ca letsencrypt
acme dns-persist-01 -d example.com --email admin@example.com --ca https://ca.example/directory
acme dns-alias -d example.com --target delegated.example.net --dns epik --email admin@example.com
acme renew --all
acme revoke -d example.com
acme remove -d example.com
acme list --status expiring
acme history -d example.com --since 2026-01-01T00:00:00Z
acme status -d example.com
acme store path
```

The default CA is ZeroSSL. ZeroSSL registration requires `ACME_EAB_KID` and `ACME_EAB_HMAC_KEY`. Let's Encrypt and custom HTTPS directory URLs are also supported.

Certificate keys default to `ec-256`. Set `[defaults].key_type = "ec-384"` in the TOML config to use ECDSA P-384. Also supported: `ec-521`, `rsa-2048`, `rsa-3072`, `rsa-4096`.

Webroot http-01 writes the token file under the selected served directory and checks the public challenge URL by default. The user configures nginx to serve that directory and reloads nginx themselves after certificate installation or renewal.

DNS challenge records are printed to stdout before the ACME challenge is acknowledged. Manual DNS mode queries Cloudflare, Google, and Quad9 DNS-over-HTTPS endpoints and applies `[dns].quorum = "all"` or `"any"` before continuing (or proceeds after timeout). This checks public recursive resolvers; authoritative nameserver polling is not implemented yet. Set `--dns-wait-timeout-action fail` (or `dns.wait_timeout_action = "fail"`) to abort before notifying the CA when propagation times out; it exits with code 4 and cleans up records added by the API. Epik is the only bundled DNS provider; use `--dns epik` with `ACME_DNS_EPIK_SIGNATURE` set to the API signature from the Epik account settings. The profile adds only the matching TXT record and removes it by record ID after issuance. Other custom declarative profiles can be placed in `~/.acme/dnsapi.d/<name>.toml` or supplied with `--dns-profile <file>`.

`dns-account-01` and `dns-persist-01` are draft challenge types. The CA must offer the corresponding challenge. `dns-persist-01` also requires the directory `accountHashPrefix` metadata.

The embedded database defaults to `~/.acme/store.db`. Configure it with `--store-path`, `ACME_STORE_PATH`, or `[store].path` in the TOML config. Disable it with `--no-store`, `ACME_STORE_ENABLED=false`, or `store.enabled = false`.

Deploy hooks can atomically copy each new key and fullchain to explicit paths. Notification hooks can send JSON events to HTTPS webhooks; optional bearer tokens are read from the named environment variable. Hook failures are warnings and do not undo an issued certificate. No hook runs a shell command or reloads a service.

```toml
[[hooks.notify]]
url = "https://notify.example.net/acme-events"
token_env = "ACME_NOTIFY_TOKEN" # optional

[[hooks.deploy]]
key_path = "/etc/ssl/example/key.pem"
fullchain_path = "/etc/ssl/example/fullchain.pem"
```

Renewals are run with `acme renew --all`; invoke that command from a scheduler configured by the operator. The command does not install a scheduler or reload nginx.

## Build

```sh
cargo build -p acme-cli --release --target x86_64-unknown-linux-musl
```

