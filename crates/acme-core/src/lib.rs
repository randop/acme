//! A small native ACME v2 client. It implements ES256 JWS, account creation,
//! http-01 and manual dns-01 issuance without an ACME client dependency.
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::{CertificateParams, KeyPair};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const LE_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LE_STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const ZEROSSL_DIRECTORY: &str = "https://acme.zerossl.com/v2/DV90";

pub struct IssuedCertificate {
    pub directory: PathBuf,
    pub not_after: String,
    pub not_before: String,
    pub serial: String,
    pub fingerprint: String,
    pub order_url: String,
    pub dns_warnings: Vec<String>,
}

#[derive(Debug)]
pub struct DnsWaitTimeoutError(pub String);
impl std::fmt::Display for DnsWaitTimeoutError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "DNS propagation did not reach the configured quorum before timeout: {}",
            self.0
        )
    }
}
impl std::error::Error for DnsWaitTimeoutError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub domains: Vec<String>,
    pub ca_directory: String,
    pub challenge: String,
    pub not_after: String,
    pub webroot: PathBuf,
    pub email: String,
    pub key_type: String,
    #[serde(default)]
    pub dns_profile: Option<String>,
    #[serde(default)]
    pub dns_alias: Option<String>,
}

#[derive(Clone, Copy)]
pub enum Ca {
    LetsEncrypt,
    LetsEncryptStaging,
    Custom,
}
impl Ca {
    pub fn directory(self, custom: Option<&str>) -> Result<&str> {
        match self {
            Self::LetsEncrypt => Ok(LE_DIRECTORY),
            Self::LetsEncryptStaging => Ok(LE_STAGING_DIRECTORY),
            Self::Custom => custom.context("custom CA requires --ca-url"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Credentials {
    directory: String,
    account_url: String,
    email: String,
    key_pkcs8: String,
}
#[derive(Debug)]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
    revoke_cert: Option<String>,
    account_hash_prefix: Option<String>,
    renewal_info: Option<String>,
}
struct Acme {
    http: reqwest::Client,
    directory: Directory,
    credentials: Credentials,
    key: EcdsaKeyPair,
}

impl Acme {
    async fn open(path: &Path, directory_url: &str, email: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let value: Value = http
            .get(directory_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let directory = Directory {
            new_nonce: value["newNonce"]
                .as_str()
                .context("ACME directory has no newNonce")?
                .to_owned(),
            new_account: value["newAccount"]
                .as_str()
                .context("ACME directory has no newAccount")?
                .to_owned(),
            new_order: value["newOrder"]
                .as_str()
                .context("ACME directory has no newOrder")?
                .to_owned(),
            revoke_cert: value["revokeCert"].as_str().map(str::to_owned),
            account_hash_prefix: value["meta"]["accountHashPrefix"]
                .as_str()
                .map(str::to_owned),
            renewal_info: value["renewalInfo"].as_str().map(str::to_owned),
        };
        let credentials = if path.exists() {
            let raw = fs::read(path)
                .with_context(|| format!("reading account credentials {}", path.display()))?;
            let c: Credentials =
                serde_json::from_slice(&raw).context("decoding account credentials")?;
            anyhow::ensure!(
                c.directory == directory_url,
                "account credentials belong to a different CA"
            );
            c
        } else {
            let eab_kid = std::env::var("ACME_EAB_KID").ok();
            let eab_hmac = std::env::var("ACME_EAB_HMAC_KEY").ok();
            anyhow::ensure!(
                eab_kid.is_some() == eab_hmac.is_some(),
                "set both ACME_EAB_KID and ACME_EAB_HMAC_KEY"
            );
            anyhow::ensure!(
                directory_url != ZEROSSL_DIRECTORY || eab_kid.is_some(),
                "ZeroSSL registration requires ACME_EAB_KID and ACME_EAB_HMAC_KEY"
            );
            let rng = SystemRandom::new();
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let pkcs8 = key.serialize_der();
            let ring_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
                .map_err(|_| anyhow::anyhow!("loading account signing key failed"))?;
            let jwk = jwk(ring_key.public_key().as_ref())?;
            let payload =
                json!({"termsOfServiceAgreed":true,"contact":[format!("mailto:{email}")]});
            let eab = match (eab_kid, eab_hmac) {
                (Some(kid), Some(secret)) => Some(external_account_binding(
                    &kid,
                    &secret,
                    &directory.new_account,
                    &jwk,
                )?),
                _ => None,
            };
            let mut payload = payload;
            if let Some(binding) = eab {
                payload["externalAccountBinding"] = binding;
            }
            let (response, location) = post_jwk(
                &http,
                &directory,
                &ring_key,
                &jwk,
                &directory.new_account,
                payload,
            )
            .await?;
            let account_url = location.context("ACME account response has no Location header")?;
            anyhow::ensure!(
                response.get("status").and_then(Value::as_str) == Some("valid"),
                "ACME account registration did not return valid status"
            );
            let c = Credentials {
                directory: directory_url.to_owned(),
                account_url,
                email: email.to_owned(),
                key_pkcs8: URL_SAFE_NO_PAD.encode(pkcs8),
            };
            atomic_write(path, &serde_json::to_vec_pretty(&c)?, 0o600)?;
            c
        };
        let pkcs8 = URL_SAFE_NO_PAD
            .decode(&credentials.key_pkcs8)
            .context("decoding account private key")?;
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &pkcs8,
            &SystemRandom::new(),
        )
        .map_err(|_| anyhow::anyhow!("loading account private key failed"))?;
        Ok(Self {
            http,
            directory,
            credentials,
            key,
        })
    }

    async fn post(&self, url: &str, payload: Value) -> Result<(Value, Option<String>)> {
        let nonce_rsp = self
            .http
            .head(&self.directory.new_nonce)
            .send()
            .await?
            .error_for_status()?;
        let nonce = nonce_rsp
            .headers()
            .get("Replay-Nonce")
            .context("ACME server omitted Replay-Nonce")?
            .to_str()?
            .to_owned();
        let protected =
            json!({"alg":"ES256","kid":self.credentials.account_url,"nonce":nonce,"url":url});
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
        let payload = if payload.is_null() {
            String::new()
        } else {
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
        };
        let signing_input = format!("{protected}.{payload}");
        let signature = self
            .key
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|_| anyhow::anyhow!("signing ACME JWS failed"))?;
        let body = json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(signature.as_ref())});
        let response = self
            .http
            .post(url)
            .header("content-type", "application/jose+json")
            .json(&body)
            .send()
            .await
            .context("sending ACME request")?;
        let status = response.status();
        let location = response
            .headers()
            .get("Location")
            .and_then(|x| x.to_str().ok())
            .map(str::to_owned);
        let text = response.text().await?;
        let value: Value = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or_else(|_| json!({"detail":text}))
        };
        anyhow::ensure!(
            status.is_success(),
            "ACME request to {url} failed ({status}): {}",
            value
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("server returned an error")
        );
        Ok((value, location))
    }

    async fn get(&self, url: &str) -> Result<Value> {
        Ok(self.post(url, Value::Null).await?.0)
    }

    async fn get_pem(&self, url: &str) -> Result<String> {
        let nonce_rsp = self
            .http
            .head(&self.directory.new_nonce)
            .send()
            .await?
            .error_for_status()?;
        let nonce = nonce_rsp
            .headers()
            .get("Replay-Nonce")
            .context("ACME server omitted Replay-Nonce")?
            .to_str()?
            .to_owned();
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"alg":"ES256","kid":self.credentials.account_url,"nonce":nonce,"url":url}),
        )?);
        let input = format!("{protected}.");
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|_| anyhow::anyhow!("signing certificate download request failed"))?;
        let response = self.http.post(url).header("content-type","application/jose+json").header("accept","application/pem-certificate-chain").json(&json!({"protected":protected,"payload":"","signature":URL_SAFE_NO_PAD.encode(sig.as_ref())})).send().await?.error_for_status()?;
        Ok(response.text().await?)
    }
}

fn jwk(public: &[u8]) -> Result<Value> {
    anyhow::ensure!(
        public.len() == 65 && public[0] == 4,
        "unexpected P-256 public key encoding"
    );
    Ok(
        json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(&public[1..33]),"y":URL_SAFE_NO_PAD.encode(&public[33..65])}),
    )
}

async fn post_jwk(
    http: &reqwest::Client,
    directory: &Directory,
    key: &EcdsaKeyPair,
    jwk: &Value,
    url: &str,
    payload: Value,
) -> Result<(Value, Option<String>)> {
    let nonce_rsp = http
        .head(&directory.new_nonce)
        .send()
        .await?
        .error_for_status()?;
    let nonce = nonce_rsp
        .headers()
        .get("Replay-Nonce")
        .context("ACME server omitted Replay-Nonce")?
        .to_str()?
        .to_owned();
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"alg":"ES256","jwk":jwk,"nonce":nonce,"url":url}),
    )?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let input = format!("{protected}.{payload}");
    let sig = key
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| anyhow::anyhow!("signing ACME account request failed"))?;
    let response = http.post(url).header("content-type","application/jose+json").json(&json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(sig.as_ref())})).send().await?;
    let status = response.status();
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response.text().await?;
    let value: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).unwrap_or_else(|_| json!({"detail":body}))
    };
    anyhow::ensure!(
        status.is_success(),
        "ACME account request failed ({status}): {}",
        value
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("server returned an error")
    );
    Ok((value, location))
}

fn external_account_binding(kid: &str, encoded_key: &str, url: &str, jwk: &Value) -> Result<Value> {
    use ring::hmac;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded_key.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded_key.trim()))
        .context("ACME_EAB_HMAC_KEY must be base64 encoded")?;
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"alg":"HS256","kid":kid,"url":url}),
    )?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(jwk)?);
    let input = format!("{protected}.{payload}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, &raw);
    let sig = hmac::sign(&key, input.as_bytes());
    Ok(
        json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(sig.as_ref())}),
    )
}

pub async fn issue_webroot(
    home: &Path,
    directory: &str,
    email: &str,
    names: &[String],
    webroot: &Path,
    preflight: bool,
    key_type: &str,
) -> Result<IssuedCertificate> {
    issue(
        home,
        directory,
        email,
        names,
        Challenge::Http(webroot, preflight),
        Duration::ZERO,
        Duration::ZERO,
        Duration::from_secs(10),
        Duration::ZERO,
        "any",
        "continue",
        key_type,
    )
    .await
}

pub async fn issue_dns_manual(
    home: &Path,
    directory: &str,
    email: &str,
    names: &[String],
    initial: Duration,
    timeout: Duration,
    interval: Duration,
    settle: Duration,
    quorum: &str,
    timeout_action: &str,
    key_type: &str,
) -> Result<IssuedCertificate> {
    issue(
        home,
        directory,
        email,
        names,
        Challenge::Dns(None),
        initial,
        timeout,
        interval,
        settle,
        quorum,
        timeout_action,
        key_type,
    )
    .await
}

pub async fn issue_dns_provider_manual(
    home: &Path,
    directory: &str,
    email: &str,
    names: &[String],
    provider: &str,
    initial: Duration,
    timeout: Duration,
    interval: Duration,
    settle: Duration,
    quorum: &str,
    timeout_action: &str,
    key_type: &str,
) -> Result<IssuedCertificate> {
    issue(
        home,
        directory,
        email,
        names,
        Challenge::Dns(Some(provider)),
        initial,
        timeout,
        interval,
        settle,
        quorum,
        timeout_action,
        key_type,
    )
    .await
}

pub async fn issue_dns_account_manual(
    home: &Path,
    directory: &str,
    email: &str,
    names: &[String],
    provider: Option<&str>,
    initial: Duration,
    timeout: Duration,
    interval: Duration,
    settle: Duration,
    quorum: &str,
    timeout_action: &str,
    key_type: &str,
) -> Result<IssuedCertificate> {
    issue(
        home,
        directory,
        email,
        names,
        Challenge::DnsAccount(provider),
        initial,
        timeout,
        interval,
        settle,
        quorum,
        timeout_action,
        key_type,
    )
    .await
}

pub async fn issue_dns_persist(
    home: &Path,
    directory: &str,
    email: &str,
    names: &[String],
    provider: Option<&str>,
    initial: Duration,
    timeout: Duration,
    interval: Duration,
    settle: Duration,
    quorum: &str,
    timeout_action: &str,
    key_type: &str,
) -> Result<IssuedCertificate> {
    let challenge = Challenge::DnsPersist(provider);
    issue(
        home,
        directory,
        email,
        names,
        challenge,
        initial,
        timeout,
        interval,
        settle,
        quorum,
        timeout_action,
        key_type,
    )
    .await
}

pub async fn issue_dns_alias(
    home: &Path,
    directory: &str,
    email: &str,
    names: &[String],
    alias: &str,
    provider: Option<&str>,
    initial: Duration,
    timeout: Duration,
    interval: Duration,
    settle: Duration,
    quorum: &str,
    timeout_action: &str,
    key_type: &str,
) -> Result<IssuedCertificate> {
    validate_identifier(alias)?;
    issue(
        home,
        directory,
        email,
        names,
        Challenge::DnsAlias { provider, alias },
        initial,
        timeout,
        interval,
        settle,
        quorum,
        timeout_action,
        key_type,
    )
    .await
}

#[derive(Clone, Copy)]
enum Challenge<'a> {
    Http(&'a Path, bool),
    Dns(Option<&'a str>),
    DnsAccount(Option<&'a str>),
    DnsPersist(Option<&'a str>),
    DnsAlias {
        provider: Option<&'a str>,
        alias: &'a str,
    },
}

#[derive(Clone, Deserialize)]
struct DnsProfile {
    name: String,
    base_url: String,
    allowed_hosts: Vec<String>,
    token_env: String,
    #[serde(default = "default_dns_auth_type")]
    auth_type: String,
    #[serde(default)]
    auth_header: Option<String>,
    #[serde(default)]
    find_path: Option<String>,
    #[serde(default)]
    find_records_path: Option<String>,
    #[serde(default)]
    find_id_path: Option<String>,
    #[serde(default)]
    find_name_path: Option<String>,
    #[serde(default)]
    find_type_path: Option<String>,
    #[serde(default)]
    find_value_path: Option<String>,
    zone_lookup_path: String,
    zone_id_path: String,
    add_path: String,
    add_body: String,
    #[serde(default)]
    record_id_path: Option<String>,
    remove_path: String,
}
fn default_dns_auth_type() -> String {
    "bearer".into()
}
#[derive(Clone)]
struct AddedDnsRecord {
    profile: DnsProfile,
    token: String,
    zone_id: String,
    record_id: String,
    cleanup_on_exit: bool,
}

const EPIK_PROFILE: &str = include_str!("../profiles/epik.toml");
const CLOUDFLARE_PROFILE: &str = include_str!("../profiles/cloudflare.toml");
const DIGITALOCEAN_PROFILE: &str = include_str!("../profiles/digitalocean.toml");
const GODADDY_PROFILE: &str = include_str!("../profiles/godaddy.toml");
const ALIDNS_PROFILE: &str = include_str!("../profiles/alidns.toml");
const DNSPOD_PROFILE: &str = include_str!("../profiles/dnspod.toml");
const NAMECHEAP_PROFILE: &str = include_str!("../profiles/namecheap.toml");
const GCLOUD_PROFILE: &str = include_str!("../profiles/gcloud.toml");
const AZURE_PROFILE: &str = include_str!("../profiles/azure.toml");
const OVH_PROFILE: &str = include_str!("../profiles/ovh.toml");
const VULTR_PROFILE: &str = include_str!("../profiles/vultr.toml");
const LINODE_PROFILE: &str = include_str!("../profiles/linode.toml");
const HEZTNER_PROFILE: &str = include_str!("../profiles/hetzner.toml");
const PORKBUN_PROFILE: &str = include_str!("../profiles/porkbun.toml");
const DESEC_PROFILE: &str = include_str!("../profiles/desec.toml");
const GANDI_PROFILE: &str = include_str!("../profiles/gandi.toml");
const DUCKDNS_PROFILE: &str = include_str!("../profiles/duckdns.toml");
const LUADNS_PROFILE: &str = include_str!("../profiles/luadns.toml");
const CLOUDDNS_PROFILE: &str = include_str!("../profiles/clouddns.toml");

fn dns_profile(home: &Path, name: &str) -> Result<DnsProfile> {
    let bundled = match name {
        "epik" => Some(EPIK_PROFILE),
        "cloudflare" => Some(CLOUDFLARE_PROFILE),
        "digitalocean" => Some(DIGITALOCEAN_PROFILE),
        "godaddy" => Some(GODADDY_PROFILE),
        "alidns" => Some(ALIDNS_PROFILE),
        "dnspod" => Some(DNSPOD_PROFILE),
        "namecheap" => Some(NAMECHEAP_PROFILE),
        "gcloud" => Some(GCLOUD_PROFILE),
        "azure" => Some(AZURE_PROFILE),
        "ovh" => Some(OVH_PROFILE),
        "vultr" => Some(VULTR_PROFILE),
        "linode" => Some(LINODE_PROFILE),
        "hetzner" => Some(HEZTNER_PROFILE),
        "porkbun" => Some(PORKBUN_PROFILE),
        "desec" => Some(DESEC_PROFILE),
        "gandi" => Some(GANDI_PROFILE),
        "duckdns" => Some(DUCKDNS_PROFILE),
        "luadns" => Some(LUADNS_PROFILE),
        "clouddns" => Some(CLOUDDNS_PROFILE),
        _ => None,
    };
    let content = if let Some(content) = bundled {
        content.to_owned()
    } else {
        let path = if name.ends_with(".toml") {
            PathBuf::from(name)
        } else {
            home.join("dnsapi.d").join(format!("{name}.toml"))
        };
        fs::read_to_string(&path)
            .with_context(|| format!("loading DNS profile {}", path.display()))?
    };
    let profile: DnsProfile = toml::from_str(&content).context("parsing DNS profile TOML")?;
    anyhow::ensure!(
        !profile.allowed_hosts.is_empty(),
        "DNS profile has no allowed_hosts"
    );
    anyhow::ensure!(
        profile.name == name || name.ends_with(".toml"),
        "loaded DNS profile name does not match selector"
    );
    Ok(profile)
}

fn render_profile(value: &str, vars: &[(&str, &str)]) -> Result<String> {
    let mut rendered = value.to_owned();
    for (key, val) in vars {
        rendered = rendered.replace(&format!("{{{{{key}}}}}"), val);
    }
    anyhow::ensure!(
        !rendered.contains("{{"),
        "DNS profile template contains an unresolved variable"
    );
    Ok(rendered)
}

async fn profile_request(
    profile: &DnsProfile,
    token: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let base = reqwest::Url::parse(&format!("{}/", profile.base_url.trim_end_matches('/')))
        .context("invalid DNS profile base_url")?;
    anyhow::ensure!(
        base.scheme() == "https",
        "DNS provider profile base_url must use HTTPS"
    );
    anyhow::ensure!(
        base.username().is_empty() && base.password().is_none() && base.fragment().is_none(),
        "DNS provider base_url cannot contain credentials or a fragment"
    );
    let url = base
        .join(path.trim_start_matches('/'))
        .context("invalid DNS profile request URL")?;
    anyhow::ensure!(
        url.scheme() == "https",
        "DNS provider request URL must use HTTPS"
    );
    anyhow::ensure!(
        url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "DNS provider request URL must use the standard HTTPS port and cannot contain credentials or a fragment"
    );
    let host = url.host_str().context("DNS profile URL has no host")?;
    anyhow::ensure!(
        profile
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host)),
        "DNS profile attempted to call undeclared host {host}"
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    for attempt in 0..4u32 {
        let mut request = client.request(method.clone(), url.clone());
        request = match profile.auth_type.as_str() {
            "bearer" => request.bearer_auth(token),
            "header" => {
                let name = profile
                    .auth_header
                    .as_deref()
                    .context("DNS profile custom header auth requires auth_header")?;
                let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .context("DNS profile auth_header is invalid")?;
                let value = reqwest::header::HeaderValue::from_str(token)
                    .context("DNS provider token is not valid as an HTTP header")?;
                request.header(name, value)
            }
            "query" => {
                let mut url = url.clone();
                url.query_pairs_mut().append_pair("SIGNATURE", token);
                client.request(method.clone(), url)
            }
            other => bail!("unsupported DNS profile auth type {other:?}"),
        }
        .header("content-type", "application/json");
        let request = if let Some(body) = body.as_ref() {
            request.json(body)
        } else {
            request
        };
        let response = request.send().await.map_err(|error| {
            anyhow::anyhow!(
                "DNS provider {} request failed: {}",
                profile.name,
                error.without_url()
            )
        })?;
        let status = response.status();
        if (status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
            && attempt < 3
        {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            tokio::time::sleep(Duration::from_secs(
                retry_after.unwrap_or(1u64 << attempt).min(30),
            ))
            .await;
            continue;
        }
        anyhow::ensure!(
            status.is_success(),
            "DNS provider {} returned HTTP {status}",
            profile.name
        );
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(Value::Null);
        }
        return Ok(response.json().await.unwrap_or(Value::Null));
    }
    bail!("DNS provider {} request retries exhausted", profile.name)
}

fn json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.get(index)?
        } else {
            current.get(segment)?
        };
    }
    Some(current)
}

async fn provider_add(
    home: &Path,
    name: &str,
    record: &str,
    value: &str,
) -> Result<AddedDnsRecord> {
    let profile = dns_profile(home, name)?;
    let token = std::env::var(&profile.token_env).with_context(|| {
        format!(
            "DNS profile {} requires environment variable {}",
            profile.name, profile.token_env
        )
    })?;
    let labels: Vec<_> = record.split('.').collect();
    let mut zone = None;
    for index in 0..labels.len() {
        let candidate = labels[index..].join(".");
        let path = render_profile(&profile.zone_lookup_path, &[("candidate_zone", &candidate)])?;
        let response = match profile_request(&profile, &token, reqwest::Method::GET, &path, None)
            .await
        {
            Ok(response) => response,
            Err(error) if profile.name == "epik" && format!("{error:#}").contains("HTTP 404") => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Some(id) = json_path(&response, &profile.zone_id_path).and_then(Value::as_str) {
            zone = Some((candidate, id.to_owned()));
            break;
        }
    }
    let (zone_name, zone_id) =
        zone.context("could not find an authoritative DNS zone for challenge record")?;
    let relative_record = record
        .strip_suffix(&zone_name)
        .map(|prefix| prefix.trim_end_matches('.'))
        .filter(|prefix| !prefix.is_empty())
        .unwrap_or("@");
    let path = render_profile(&profile.add_path, &[("zone_id", &zone_id)])?;
    let body_text = render_profile(
        &profile.add_body,
        &[
            ("fulldomain", record),
            ("record_name", relative_record),
            ("txt_value", value),
            ("zone", &zone_name),
            ("zone_id", &zone_id),
            ("ttl", "120"),
        ],
    )?;
    let body: Value =
        serde_json::from_str(&body_text).context("DNS profile add_body rendered invalid JSON")?;
    if profile.find_path.is_some() {
        let existing =
            find_profile_record(&profile, &token, &zone_id, record, relative_record, value).await?;
        if let Some(record_id) = existing {
            return Ok(AddedDnsRecord {
                profile,
                token,
                zone_id,
                record_id,
                cleanup_on_exit: false,
            });
        }
    }
    let response =
        profile_request(&profile, &token, reqwest::Method::POST, &path, Some(body)).await?;
    let record_id = profile
        .record_id_path
        .as_deref()
        .and_then(|record_path| json_path(&response, record_path))
        .and_then(|value| match value {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        });
    let record_id = match record_id {
        Some(record_id) => record_id,
        None if profile.find_path.is_some() => {
            find_profile_record(&profile, &token, &zone_id, record, relative_record, value)
                .await?
                .context(
                    "DNS provider added a record but its record ID could not be found for cleanup",
                )?
        }
        None => bail!("DNS profile response has no string or numeric record_id"),
    };
    Ok(AddedDnsRecord {
        profile,
        token,
        zone_id,
        record_id,
        cleanup_on_exit: true,
    })
}

async fn find_profile_record(
    profile: &DnsProfile,
    token: &str,
    zone_id: &str,
    full_name: &str,
    relative_name: &str,
    value: &str,
) -> Result<Option<String>> {
    let Some(find_path) = profile.find_path.as_deref() else {
        return Ok(None);
    };
    let path = render_profile(find_path, &[("zone_id", zone_id)])?;
    let response = profile_request(profile, token, reqwest::Method::GET, &path, None).await?;
    let records_path = profile
        .find_records_path
        .as_deref()
        .context("DNS profile find_path requires find_records_path")?;
    let records = json_path(&response, records_path)
        .and_then(Value::as_array)
        .context("DNS profile find response has no record array")?;
    let name_paths = profile
        .find_name_path
        .as_deref()
        .context("DNS profile find_path requires find_name_path")?;
    let type_path = profile
        .find_type_path
        .as_deref()
        .context("DNS profile find_path requires find_type_path")?;
    let value_path = profile
        .find_value_path
        .as_deref()
        .context("DNS profile find_path requires find_value_path")?;
    let id_path = profile
        .find_id_path
        .as_deref()
        .context("DNS profile find_path requires find_id_path")?;
    for record in records {
        let Some(record_name) = json_path(record, name_paths).and_then(Value::as_str) else {
            continue;
        };
        let expected_name = if profile.name == "epik" {
            relative_name
        } else {
            full_name
        };
        let record_type = json_path(record, type_path).and_then(Value::as_str);
        let record_value = json_path(record, value_path).and_then(Value::as_str);
        if record_name.eq_ignore_ascii_case(expected_name)
            && record_type == Some("TXT")
            && record_value == Some(value)
        {
            let id = json_path(record, id_path).and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            });
            return Ok(id);
        }
    }
    Ok(None)
}

async fn provider_remove(record: AddedDnsRecord) -> Result<()> {
    let path = render_profile(
        &record.profile.remove_path,
        &[
            ("zone_id", &record.zone_id),
            ("record_id", &record.record_id),
        ],
    )?;
    let _ = profile_request(
        &record.profile,
        &record.token,
        reqwest::Method::DELETE,
        &path,
        None,
    )
    .await?;
    Ok(())
}
async fn issue(
    home: &Path,
    directory_url: &str,
    email: &str,
    names: &[String],
    challenge_kind: Challenge<'_>,
    dns_initial: Duration,
    dns_timeout: Duration,
    dns_interval: Duration,
    dns_settle: Duration,
    dns_quorum: &str,
    dns_timeout_action: &str,
    key_type: &str,
) -> Result<IssuedCertificate> {
    let mut records = Vec::new();
    let mut dns_warnings = Vec::new();
    let result = issue_inner(
        home,
        directory_url,
        email,
        names,
        challenge_kind,
        dns_initial,
        dns_timeout,
        dns_interval,
        dns_settle,
        dns_quorum,
        dns_timeout_action,
        key_type,
        &mut records,
        &mut dns_warnings,
    )
    .await;
    let mut cleanup_errors = Vec::new();
    for record in records.into_iter().rev() {
        if record.cleanup_on_exit {
            if let Err(error) = provider_remove(record).await {
                cleanup_errors.push(format!("{error:#}"));
            }
        }
    }
    match (result, cleanup_errors.is_empty()) {
        (Ok(mut cert), true) => {
            cert.dns_warnings = dns_warnings;
            Ok(cert)
        }
        (Ok(mut cert), false) => {
            cert.dns_warnings = dns_warnings;
            for error in cleanup_errors {
                eprintln!("warning: failed to remove DNS challenge record: {error}");
            }
            Ok(cert)
        }
        (Err(error), _) => Err(error),
    }
}

async fn issue_inner(
    home: &Path,
    directory_url: &str,
    email: &str,
    names: &[String],
    challenge_kind: Challenge<'_>,
    dns_initial: Duration,
    dns_timeout: Duration,
    dns_interval: Duration,
    dns_settle: Duration,
    dns_quorum: &str,
    dns_timeout_action: &str,
    key_type: &str,
    added_records: &mut Vec<AddedDnsRecord>,
    dns_warnings: &mut Vec<String>,
) -> Result<IssuedCertificate> {
    anyhow::ensure!(!names.is_empty(), "at least one domain is required");
    anyhow::ensure!(
        matches!(
            key_type,
            "ec-256" | "ec-384" | "ec-521" | "rsa-2048" | "rsa-3072" | "rsa-4096"
        ),
        "unsupported certificate key type {key_type:?}; supported types are ec-256, ec-384, ec-521, rsa-2048, rsa-3072, rsa-4096"
    );
    anyhow::ensure!(
        matches!(dns_timeout_action, "continue" | "fail"),
        "DNS wait timeout action must be 'continue' or 'fail'"
    );
    let mut seen = std::collections::HashSet::new();
    for name in names {
        validate_identifier(name)?;
        anyhow::ensure!(
            seen.insert(name.to_ascii_lowercase()),
            "duplicate domain identifier: {name}"
        );
    }
    if matches!(challenge_kind, Challenge::Http(..)) {
        anyhow::ensure!(
            names.iter().all(|n| !n.starts_with("*.")),
            "wildcard certificates require dns-01"
        );
    }
    fs::create_dir_all(home)?;
    fs::set_permissions(home, fs::Permissions::from_mode(0o700))?;
    fs::create_dir_all(home.join("account"))?;
    fs::set_permissions(home.join("account"), fs::Permissions::from_mode(0o700))?;
    let account_path = home
        .join("account")
        .join(format!("{}.json", account_name(directory_url)));
    let acme = Acme::open(&account_path, directory_url, email).await?;
    let new_order = acme.directory.new_order.clone();
    let identifiers: Vec<_> = names
        .iter()
        .map(|n| json!({"type":"dns","value":n}))
        .collect();
    let mut order_payload = json!({"identifiers":identifiers});
    if acme.directory.renewal_info.is_some() {
        if let Some(replaces) = certificate_replacement_id(
            &home.join("certs").join(
                names
                    .iter()
                    .find(|n| !n.starts_with("*."))
                    .context("certificate requires base identifier")?,
            ),
        )? {
            order_payload["replaces"] = Value::String(replaces);
        }
    }
    let (mut order, order_url) = acme.post(&new_order, order_payload).await?;
    let order_url = order_url.context("new order response has no Location header")?;
    let authzs = order["authorizations"]
        .as_array()
        .context("order has no authorizations")?
        .clone();
    let mut cleanups = ChallengeCleanup::default();
    for authz_url in authzs {
        let url = authz_url
            .as_str()
            .context("authorization URL is not a string")?;
        let authz = acme.get(url).await?;
        if authz["status"] == "valid" {
            continue;
        }
        let identifier = authz["identifier"]["value"]
            .as_str()
            .context("authorization has no DNS identifier")?
            .to_owned();
        let wildcard = authz["wildcard"].as_bool().unwrap_or(false);
        let challenge_type = match challenge_kind {
            Challenge::Http(..) => "http-01",
            Challenge::Dns(_) => "dns-01",
            Challenge::DnsAccount(_) => "dns-account-01",
            Challenge::DnsPersist(_) => "dns-persist-01",
            Challenge::DnsAlias { .. } => "dns-01",
        };
        let candidates = authz["challenges"]
            .as_array()
            .context("authorization has no challenges")?;
        let ch = candidates
            .iter()
            .find(|c| c["type"] == challenge_type)
            .with_context(|| format!("CA does not offer {challenge_type} for {identifier}"))?;
        let token = ch["token"].as_str().unwrap_or("");
        let challenge_url = ch["url"].as_str().context("challenge has no URL")?;
        if challenge_type != "dns-persist-01" {
            anyhow::ensure!(
                token.len() >= 16
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "ACME challenge token is not valid base64url"
            );
        }
        let key_auth = format!("{token}.{}", thumbprint(&acme.key)?);
        match challenge_kind {
            Challenge::Http(root, preflight) => {
                let file = acme_challenge::write_http01(root, token, &key_auth)?;
                cleanups.0.push(file);
                if preflight {
                    preflight_http01(&identifier, token, &key_auth).await?;
                }
            }
            Challenge::Dns(_)
            | Challenge::DnsAccount(_)
            | Challenge::DnsPersist(_)
            | Challenge::DnsAlias { .. } => {
                use sha2::Digest;
                let name = identifier.trim_start_matches("*.");
                let (record, lookup_record, value, persist) = match challenge_kind {
                    Challenge::DnsAccount(_) => {
                        let r = format!(
                            "_acme-challenge_{}.{}",
                            base32_lower(
                                &sha2::Sha256::digest(acme.credentials.account_url.as_bytes())
                                    [..10]
                            ),
                            name
                        );
                        (
                            r.clone(),
                            r,
                            URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(key_auth.as_bytes())),
                            false,
                        )
                    }
                    Challenge::DnsPersist(_) => {
                        let issuers = ch["issuerDomainNames"]
                            .as_array()
                            .context("dns-persist-01 challenge has no issuerDomainNames")?;
                        anyhow::ensure!(
                            !issuers.is_empty() && issuers.len() <= 10,
                            "dns-persist-01 issuerDomainNames must contain 1 to 10 values"
                        );
                        let issuer = issuers[0]
                            .as_str()
                            .context("dns-persist-01 issuer name is not a string")?;
                        let prefix =
                            acme.directory.account_hash_prefix.as_deref().context(
                                "CA does not advertise dns-persist-01 accountHashPrefix",
                            )?;
                        anyhow::ensure!(
                            issuer.len() <= 253
                                && issuer == issuer.to_ascii_lowercase()
                                && !issuer.ends_with('.'),
                            "dns-persist-01 issuer domain name is not normalized"
                        );
                        let key = thumbprint(&acme.key)?;
                        let account_hash =
                            persist_account_hash(name, &key, &acme.credentials.account_url);
                        let prefix = if prefix.ends_with('/') {
                            prefix.to_owned()
                        } else {
                            format!("{prefix}/")
                        };
                        let mut value =
                            format!("{issuer}; accounturi={prefix}sha-256/{account_hash}");
                        if wildcard || identifier.starts_with("*.") {
                            value.push_str("; policy=wildcard");
                        }
                        let record = format!("_validation-persist.{name}");
                        (record.clone(), record, value, true)
                    }
                    Challenge::DnsAlias { alias, .. } => (
                        format!("_acme-challenge.{alias}"),
                        format!("_acme-challenge.{name}"),
                        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(key_auth.as_bytes())),
                        false,
                    ),
                    _ => {
                        let r = format!("_acme-challenge.{name}");
                        (
                            r.clone(),
                            r,
                            URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(key_auth.as_bytes())),
                            false,
                        )
                    }
                };
                if let Challenge::DnsAlias { alias, .. } = challenge_kind {
                    println!(
                        "CNAME required:\n  Name:  _acme-challenge.{name}\n  Type:  CNAME\n  Value: _acme-challenge.{alias}"
                    );
                }
                println!(
                    "DNS record required:\n  Name:  {record}\n  Type:  TXT\n  Value: {value}\n  TTL:   60 (suggested)"
                );
                let provider = match challenge_kind {
                    Challenge::Dns(p)
                    | Challenge::DnsAccount(p)
                    | Challenge::DnsPersist(p)
                    | Challenge::DnsAlias { provider: p, .. } => p,
                    _ => None,
                };
                if let Some(profile_name) = provider {
                    match provider_add(home, profile_name, &record, &value).await {
                        Ok(mut added) => {
                            added.cleanup_on_exit = !persist;
                            added_records.push(added)
                        }
                        Err(error) => eprintln!(
                            "warning: DNS API update failed ({error:#}); add the printed TXT record manually"
                        ),
                    }
                }
                if !dns_timeout.is_zero() {
                    let end = tokio::time::Instant::now() + dns_timeout;
                    tokio::time::sleep(dns_initial.min(dns_timeout)).await;
                    while !dns_txt_visible(&lookup_record, &value, dns_quorum)
                        .await
                        .unwrap_or(false)
                    {
                        if tokio::time::Instant::now() >= end {
                            if dns_timeout_action == "fail" {
                                bail!(DnsWaitTimeoutError(record.clone()));
                            }
                            dns_warnings.push(format!(
                                "DNS propagation timed out for {record} after {} seconds; continuing to the CA",
                                dns_timeout.as_secs()
                            ));
                            eprintln!(
                                "warning: DNS propagation timeout for {record}; submitting authorization anyway"
                            );
                            break;
                        }
                        tokio::time::sleep(dns_interval.max(Duration::from_secs(1))).await;
                    }
                    if !dns_settle.is_zero() {
                        tokio::time::sleep(dns_settle).await;
                    }
                }
            }
        }
        acme.post(challenge_url, json!({}))
            .await
            .context("notifying CA that challenge is ready")?;
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        order = acme.get(&order_url).await?;
        match order["status"].as_str() {
            Some("ready") => break,
            Some("invalid") => bail!("ACME order became invalid: {}", order["error"]),
            Some("pending" | "processing") => {}
            other => bail!("unexpected ACME order status: {other:?}"),
        };
        if tokio::time::Instant::now() >= until {
            bail!("timed out waiting for ACME authorizations");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let key = match key_type {
        "ec-256" => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?,
        "ec-384" => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?,
        "ec-521" => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512)?,
        "rsa-2048" => KeyPair::generate_rsa_for(
            &rcgen::PKCS_RSA_SHA256,
            rcgen::RsaKeySize::_2048,
        )?,
        "rsa-3072" => KeyPair::generate_rsa_for(
            &rcgen::PKCS_RSA_SHA256,
            rcgen::RsaKeySize::_3072,
        )?,
        "rsa-4096" => KeyPair::generate_rsa_for(
            &rcgen::PKCS_RSA_SHA256,
            rcgen::RsaKeySize::_4096,
        )?,
        other => bail!(
            "unsupported certificate key type {other:?}; supported types are ec-256, ec-384, ec-521, rsa-2048, rsa-3072, rsa-4096"
        ),
    };
    let params = CertificateParams::new(names.to_vec())?;
    let csr = params.serialize_request(&key)?;
    let finalize = order["finalize"]
        .as_str()
        .context("order has no finalize URL")?;
    acme.post(
        finalize,
        json!({"csr":URL_SAFE_NO_PAD.encode(csr.der().as_ref())}),
    )
    .await
    .context("finalizing ACME order")?;
    let cert_until = tokio::time::Instant::now() + Duration::from_secs(600);
    let cert_url;
    loop {
        order = acme.get(&order_url).await?;
        if let Some(url) = order["certificate"].as_str() {
            cert_url = url.to_owned();
            break;
        }
        if order["status"] == "invalid" {
            bail!("ACME certificate order failed: {}", order["error"])
        }
        if tokio::time::Instant::now() >= cert_until {
            bail!("timed out waiting for certificate issuance");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let pem = acme.get_pem(&cert_url).await?;
    let leaf = first_certificate_pem(&pem)?.to_owned();
    let (not_before, expiry, serial, fingerprint) = certificate_details(&pem)?;
    let primary = names
        .iter()
        .find(|n| !n.starts_with("*."))
        .context("certificate needs a non-wildcard primary domain")?;
    let cert_dir = home.join("certs").join(primary);
    fs::create_dir_all(&cert_dir)?;
    fs::set_permissions(&cert_dir, fs::Permissions::from_mode(0o700))?;
    atomic_write(
        &cert_dir.join("key.pem"),
        key.serialize_pem().as_bytes(),
        0o600,
    )?;
    atomic_write(&cert_dir.join("cert.pem"), leaf.as_bytes(), 0o644)?;
    atomic_write(&cert_dir.join("fullchain.pem"), pem.as_bytes(), 0o644)?;
    let webroot = match challenge_kind {
        Challenge::Http(root, _) => root.to_path_buf(),
        Challenge::Dns(_)
        | Challenge::DnsAccount(_)
        | Challenge::DnsPersist(_)
        | Challenge::DnsAlias { .. } => PathBuf::new(),
    };
    let challenge = match challenge_kind {
        Challenge::Http(..) => "http-01",
        Challenge::Dns(_) => "dns-01",
        Challenge::DnsAccount(_) => "dns-account-01",
        Challenge::DnsPersist(_) => "dns-persist-01",
        Challenge::DnsAlias { .. } => "dns-alias",
    };
    let metadata = CertificateMetadata {
        domains: names.to_vec(),
        ca_directory: directory_url.to_owned(),
        challenge: challenge.into(),
        not_after: expiry.clone(),
        webroot,
        email: email.into(),
        key_type: key_type.into(),
        dns_profile: match challenge_kind {
            Challenge::Dns(Some(profile))
            | Challenge::DnsAccount(Some(profile))
            | Challenge::DnsPersist(Some(profile))
            | Challenge::DnsAlias {
                provider: Some(profile),
                ..
            } => Some(profile.to_owned()),
            _ => None,
        },
        dns_alias: match challenge_kind {
            Challenge::DnsAlias { alias, .. } => Some(alias.to_owned()),
            _ => None,
        },
    };
    atomic_write(
        &cert_dir.join("metadata.json"),
        &serde_json::to_vec_pretty(&metadata)?,
        0o600,
    )?;
    Ok(IssuedCertificate {
        directory: cert_dir,
        not_after: expiry,
        not_before,
        serial,
        fingerprint,
        order_url,
        dns_warnings: Vec::new(),
    })
}

fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut acc = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn persist_account_hash(domain: &str, key_thumbprint: &str, account_url: &str) -> String {
    use sha2::Digest;
    let mut input = Vec::with_capacity(domain.len() + key_thumbprint.len() + account_url.len() + 1);
    input.push(domain.len() as u8);
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(key_thumbprint.as_bytes());
    input.extend_from_slice(account_url.as_bytes());
    URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input))
}

fn thumbprint(key: &EcdsaKeyPair) -> Result<String> {
    let jwk = jwk(key.public_key().as_ref())?;
    Ok(URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, &serde_json::to_vec(&jwk)?).as_ref()))
}
async fn dns_txt_visible(
    name: &str,
    expected: &str,
    quorum: &str,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(quorum, "all" | "any"),
        "DNS quorum must be 'all' or 'any'"
    );
    let authoritative_servers = find_authoritative_nameservers(name).await?;
    if authoritative_servers.is_empty() {
        bail!("no authoritative nameservers found for {name}");
    }
    let results = query_authoritative_servers(&authoritative_servers, name, expected).await;
    Ok(if quorum == "all" {
        results.iter().all(|r| *r)
    } else {
        results.iter().any(|r| *r)
    })
}

async fn find_authoritative_nameservers(name: &str) -> Result<Vec<std::net::SocketAddr>> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_proto::rr::{RecordType, RecordData};
    use hickory_proto::rr::rdata::name::NS;
    use std::net::ToSocketAddrs;

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        ResolverOpts::default(),
    );
    let mut servers = Vec::new();
    let mut current = name.to_owned();
    loop {
        let response = resolver.lookup(current.clone(), RecordType::NS).await;
        if let Ok(ns_response) = response {
            for record in ns_response.record_iter() {
                if let Some(rdata) = record.data() {
                    if let Some(ns) = NS::try_borrow(rdata) {
                        if let Ok(addrs) = ns.0.to_string().to_socket_addrs() {
                            for addr in addrs {
                                servers.push(addr);
                            }
                        }
                    }
                }
            }
            if !servers.is_empty() {
                return Ok(servers);
            }
        }
        if let Some(idx) = current.find('.') {
            current = current[idx + 1..].to_owned();
        } else {
            break;
        }
    }
    Ok(servers)
}

async fn query_authoritative_servers(
    servers: &[std::net::SocketAddr],
    name: &str,
    expected: &str,
) -> Vec<bool> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
    use hickory_proto::rr::{RecordType, RecordData};
    use hickory_proto::rr::rdata::txt::TXT;

    let mut results = Vec::new();
    for &server in servers {
        let config = ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::new(server, hickory_resolver::config::Protocol::Udp)]);
        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());
        let result = match resolver.lookup(name.to_owned(), RecordType::TXT).await {
            Ok(response) => {
                let mut found = false;
                for record in response.record_iter() {
                    if let Some(rdata) = record.data() {
                        if let Some(txt) = TXT::try_borrow(rdata) {
                            for txt_data in txt.iter() {
                                let data = String::from_utf8_lossy(txt_data);
                                if data == expected {
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                    if found {
                        break;
                    }
                }
                found
            }
            Err(_) => false,
        };
        results.push(result);
    }
    results
}

pub async fn register_account(home: &Path, directory: &str, email: &str) -> Result<String> {
    fs::create_dir_all(home.join("account"))?;
    fs::set_permissions(home.join("account"), fs::Permissions::from_mode(0o700))?;
    let path = home
        .join("account")
        .join(format!("{}.json", account_name(directory)));
    let acme = Acme::open(&path, directory, email).await?;
    Ok(acme.credentials.account_url)
}

pub async fn revoke_certificate(cert_dir: &Path) -> Result<()> {
    let metadata = read_certificate_metadata(cert_dir)?;
    let home = if let Some(path) = std::env::var_os("ACME_HOME") {
        PathBuf::from(path)
    } else {
        dirs::home_dir()
            .context("could not determine home directory")?
            .join(".acme")
    };
    let account_path = home
        .join("account")
        .join(format!("{}.json", account_name(&metadata.ca_directory)));
    let acme = Acme::open(&account_path, &metadata.ca_directory, &metadata.email).await?;
    let url = acme
        .directory
        .revoke_cert
        .clone()
        .context("ACME directory has no revokeCert endpoint")?;
    let pem =
        fs::read_to_string(cert_dir.join("cert.pem")).context("reading certificate to revoke")?;
    let der = pem_to_der(&pem)?;
    acme.post(&url, json!({"certificate":URL_SAFE_NO_PAD.encode(der)}))
        .await
        .context("submitting certificate revocation")?;
    Ok(())
}

pub async fn renewal_window(cert_dir: &Path) -> Result<Option<(String, String)>> {
    let metadata = read_certificate_metadata(cert_dir)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let directory: Value = http
        .get(&metadata.ca_directory)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let Some(endpoint) = directory["renewalInfo"].as_str() else {
        return Ok(None);
    };
    let pem = fs::read_to_string(cert_dir.join("cert.pem"))?;
    let der = pem_to_der(&pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("parsing certificate for ARI: {e}"))?;
    let aki = cert
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|v| v.0)
            }
            _ => None,
        })
        .context("certificate has no authority key identifier for ARI")?;
    let cert_id = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(aki),
        URL_SAFE_NO_PAD.encode(cert.tbs_certificate.raw_serial())
    );
    let info: Value = http
        .get(format!("{endpoint}/{cert_id}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let start = info["suggestedWindow"]["start"]
        .as_str()
        .context("ARI response has no window start")?;
    let end = info["suggestedWindow"]["end"]
        .as_str()
        .context("ARI response has no window end")?;
    Ok(Some((start.to_owned(), end.to_owned())))
}

fn certificate_replacement_id(cert_dir: &Path) -> Result<Option<String>> {
    let path = cert_dir.join("cert.pem");
    if !path.exists() {
        return Ok(None);
    }
    let pem = fs::read_to_string(path)?;
    let der = pem_to_der(&pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("parsing prior certificate for ARI: {e}"))?;
    let aki = cert
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|k| k.0)
            }
            _ => None,
        });
    Ok(aki.map(|aki| {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(aki),
            URL_SAFE_NO_PAD.encode(cert.tbs_certificate.raw_serial())
        )
    }))
}
pub fn read_certificate_metadata(cert_dir: &Path) -> Result<CertificateMetadata> {
    let path = cert_dir.join("metadata.json");
    serde_json::from_slice(
        &fs::read(&path)
            .with_context(|| format!("reading certificate metadata {}", path.display()))?,
    )
    .context("parsing certificate metadata")
}

async fn preflight_http01(domain: &str, token: &str, expected: &str) -> Result<()> {
    let url = format!("http://{domain}/.well-known/acme-challenge/{token}");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = client.get(&url).send().await.with_context(|| {
        format!(
            "http-01 preflight could not fetch {url}; check DNS and nginx webroot configuration"
        )
    })?;
    anyhow::ensure!(
        response.status().is_success(),
        "http-01 preflight returned {}; verify nginx serves challenge directory",
        response.status()
    );
    anyhow::ensure!(
        response.text().await?.trim() == expected,
        "http-01 preflight returned a different response; verify nginx root and challenge path"
    );
    Ok(())
}
fn certificate_details(chain: &str) -> Result<(String, String, String, String)> {
    let pem = first_certificate_pem(chain)?;
    let bytes = pem_to_der(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&bytes)
        .map_err(|e| anyhow::anyhow!("parsing X.509 certificate: {e}"))?;
    let format_time = |timestamp| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0)
            .map(|value| value.to_rfc3339())
            .context("certificate validity time out of range")
    };
    let not_before = format_time(cert.validity().not_before.to_datetime().unix_timestamp())?;
    let not_after = format_time(cert.validity().not_after.to_datetime().unix_timestamp())?;
    let serial = cert
        .tbs_certificate
        .raw_serial()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let fingerprint = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((not_before, not_after, serial, fingerprint))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let start = pem
        .find("-----BEGIN CERTIFICATE-----")
        .context("no PEM certificate")?
        + 27;
    let finish = pem[start..]
        .find("-----END CERTIFICATE-----")
        .context("incomplete PEM certificate")?;
    Ok(base64::engine::general_purpose::STANDARD.decode(
        pem[start..start + finish]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    )?)
}
fn first_certificate_pem(chain: &str) -> Result<&str> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = chain
        .find(begin)
        .context("certificate response has no PEM certificate")?;
    let finish = chain[start..]
        .find(end)
        .context("incomplete certificate PEM")?
        + end.len();
    Ok(&chain[start..start + finish])
}
pub fn validate_identifier(name: &str) -> Result<()> {
    let bare = name.strip_prefix("*.").unwrap_or(name);
    anyhow::ensure!(
        !bare.is_empty()
            && bare.len() <= 253
            && bare.split('.').all(|l| !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')),
        "invalid DNS identifier: {name}"
    );
    Ok(())
}
fn account_name(directory: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(directory.as_bytes()))
}
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".acme-{}-{}.tmp",
        std::process::id(),
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)?;
    use std::io::Write;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(e.into());
    }
    fs::rename(&temp, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn resolve_ca(value: &str) -> Result<(Ca, Option<String>)> {
    Ok(match value {
        "zerossl" => (Ca::Custom, Some(ZEROSSL_DIRECTORY.into())),
        "letsencrypt" | "le" => (Ca::LetsEncrypt, None),
        "letsencrypt-staging" | "le-staging" => (Ca::LetsEncryptStaging, None),
        url if url.starts_with("https://") => (Ca::Custom, Some(url.into())),
        _ => bail!(
            "unknown CA {value:?}; use zerossl, letsencrypt, letsencrypt-staging, or an HTTPS directory URL"
        ),
    })
}

fn cleanup_all(paths: &[PathBuf]) {
    for path in paths {
        if let Err(error) = acme_challenge::cleanup(path) {
            eprintln!(
                "warning: failed to remove challenge file {}: {error}",
                path.display()
            );
        }
    }
}
#[derive(Default)]
struct ChallengeCleanup(Vec<PathBuf>);
impl Drop for ChallengeCleanup {
    fn drop(&mut self) {
        cleanup_all(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::Digest;

    #[test]
    fn test_validate_identifier_valid() {
        assert!(validate_identifier("example.com").is_ok());
        assert!(validate_identifier("sub.example.com").is_ok());
        assert!(validate_identifier("*.example.com").is_ok());
        assert!(validate_identifier("a-b.example.com").is_ok());
        assert!(validate_identifier("example.org").is_ok());
    }

    #[test]
    fn test_validate_identifier_invalid() {
        assert!(validate_identifier("").is_err());
        assert!(validate_identifier("-example.com").is_err());
        assert!(validate_identifier("example-.com").is_err());
        assert!(validate_identifier("example..com").is_err());
        assert!(validate_identifier("_example.com").is_err());
        assert!(validate_identifier("example.com-").is_err());
    }

    #[test]
    fn test_validate_token() {
        assert!(acme_challenge::validate_token("valid_token123").is_ok());
        assert!(acme_challenge::validate_token("valid-token_123").is_ok());
        assert!(acme_challenge::validate_token("").is_err());
        assert!(acme_challenge::validate_token("invalid token").is_err());
        assert!(acme_challenge::validate_token("invalid@token").is_err());
    }

    #[test]
    fn test_base64url_encode_decode() {
        let data = b"test data for encoding";
        let encoded = URL_SAFE_NO_PAD.encode(data);
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_jwk_generation() {
        let public = vec![4u8; 65];
        let jwk = jwk(&public).unwrap();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
    }

    #[test]
    fn test_thumbprint_format() {
        let rng = ring::rand::SystemRandom::new();
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let pkcs8 = key.serialize_der();
        let ring_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).unwrap();
        let tp = thumbprint(&ring_key).unwrap();
        assert_eq!(tp.len(), 43); // base64url of 32 bytes = 43 chars
    }

    #[test]
    fn test_external_account_binding() {
        let kid = "test-kid";
        let secret = "dGVzdA=="; // base64 "test"
        let url = "https://acme.example.com/new-account";
        let jwk = json!({"kty":"EC","crv":"P-256","x":"test","y":"test"});
        let eab = external_account_binding(kid, secret, url, &jwk).unwrap();
        assert!(eab["protected"].is_string());
        assert!(eab["payload"].is_string());
        assert!(eab["signature"].is_string());
    }

    #[test]
    fn test_resolve_ca() {
        let (ca, custom) = resolve_ca("zerossl").unwrap();
        assert!(matches!(ca, Ca::Custom));
        assert_eq!(custom, Some(ZEROSSL_DIRECTORY.into()));

        let (ca, custom) = resolve_ca("letsencrypt").unwrap();
        assert!(matches!(ca, Ca::LetsEncrypt));
        assert_eq!(custom, None);

        let (ca, custom) = resolve_ca("letsencrypt-staging").unwrap();
        assert!(matches!(ca, Ca::LetsEncryptStaging));

        let (ca, custom) = resolve_ca("https://custom.acme/dir").unwrap();
        assert!(matches!(ca, Ca::Custom));
        assert_eq!(custom, Some("https://custom.acme/dir".into()));

        assert!(resolve_ca("unknown").is_err());
    }

    #[test]
    fn test_certificate_details() {
        // Use a test certificate PEM
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt\ncGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS\nBgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu\n7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf\nqzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B\nyNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb\n+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK\n-----END CERTIFICATE-----\n";
        let (not_before, not_after, serial, fingerprint) = certificate_details(pem).unwrap();
        assert!(!not_before.is_empty());
        assert!(!not_after.is_empty());
        assert!(!serial.is_empty());
        assert_eq!(fingerprint.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_account_name() {
        let name1 = account_name("https://acme.example.com/dir");
        let name2 = account_name("https://acme.example.com/dir");
        let name3 = account_name("https://other.example.com/dir");
        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
        assert_eq!(name1.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_base32_lower() {
        let data = b"hello";
        let encoded = base32_lower(data);
        assert!(encoded.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_persist_account_hash() {
        let hash = persist_account_hash("example.com", "thumbprint", "https://acme.example.com/account/123");
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_render_profile() {
        let template = "hello {{name}} world";
        let rendered = render_profile(template, &[("name", "test")]).unwrap();
        assert_eq!(rendered, "hello test world");
    }

    #[test]
    fn test_render_profile_unresolved() {
        let template = "hello {{name}} world";
        let result = render_profile(template, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_record_format() {
        use sha2::Digest;
        let key_auth = "token.thumbprint";
        let expected = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(key_auth.as_bytes()));
        assert_eq!(expected.len(), 43);
    }
}
