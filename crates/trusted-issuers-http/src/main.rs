use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use dcp_core::DcpKeyPair;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use trusted_issuers_core::{is_did_web_port, is_dns_name};
use trusted_issuers_http::{AppState, load, router};

/// Trusted issuers registry: which DIDs may issue which credential types in
/// this dataspace.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:8090")]
    bind: SocketAddr,

    /// Host (and optional port) the registry's own `did:web` is served
    /// from, e.g. `registry.example` or `localhost:8090`. The registry DID
    /// becomes `did:web:<host>` (port percent-encoded), served at
    /// `/.well-known/did.json`.
    #[arg(long)]
    did_host: String,

    /// PKCS#8 PEM P-256 private key that signs snapshots. Without it a
    /// fresh key is generated at every start, so snapshots signed before a
    /// restart stop verifying - fine for development only.
    #[arg(long)]
    signing_key_file: Option<PathBuf>,

    /// JSON file the registry is loaded from and saved to after each write.
    /// Without it the registry lives in memory only.
    #[arg(long)]
    data_file: Option<PathBuf>,

    /// Start with an empty registry when `--data-file` doesn't exist yet.
    /// Without it a missing file is a startup error, so an unmounted volume
    /// can't silently serve an empty list.
    #[arg(long)]
    create_data_file: bool,

    /// Bearer token for the admin (write) API. Without it the admin API is
    /// disabled. Prefer the environment variable over the flag, so the
    /// token stays out of process listings.
    #[arg(long, env = "TRUSTED_ISSUERS_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,

    /// How long a signed snapshot stays valid, in seconds.
    #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u64).range(1..))]
    snapshot_ttl_secs: u64,
}

/// `host` or `host:port`, lowercased, checked with the same
/// [`is_dns_name`]/[`is_did_web_port`] rules the registry applies to every
/// did:web it stores. Anything else would produce a `did:web` nobody can
/// resolve, or the registry itself would refuse, so it is refused at
/// startup. Port 443 gets its own message: it is a valid port, but did:web
/// always uses https, so the operator has to leave it out.
fn did_from_host(host: &str) -> Result<String, String> {
    let host = host.trim().to_ascii_lowercase();
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host.as_str(), None),
    };
    if is_dns_name(name) && port == Some("443") {
        return Err(format!(
            "--did-host '{host}' names port 443, but did:web always uses https, whose default port is 443: omit ':443' (--did-host {name})"
        ));
    }
    if !is_dns_name(name) || !port.is_none_or(is_did_web_port) {
        return Err(format!(
            "--did-host '{host}' must be a host name with an optional port, e.g. registry.example or localhost:8090"
        ));
    }
    Ok(match port {
        Some(port) => format!("did:web:{name}%3A{port}"),
        None => format!("did:web:{name}"),
    })
}

fn key_pair(did: String, signing_key: SigningKey) -> DcpKeyPair {
    let point = VerifyingKey::from(&signing_key).to_encoded_point(false);
    DcpKeyPair {
        own_key_id: format!("{did}#registry-key"),
        own_did: did,
        signing_key_bytes: signing_key.to_bytes().into(),
        public_key_xy: (
            (*point.x().expect("uncompressed point has x")).into(),
            (*point.y().expect("uncompressed point has y")).into(),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();

    let did = did_from_host(&cli.did_host)?;
    let key = match &cli.signing_key_file {
        Some(path) => {
            let pem =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let signing_key = SigningKey::from_pkcs8_pem(&pem)
                .map_err(|e| format!("{}: not a PKCS#8 P-256 key: {e}", path.display()))?;
            key_pair(did, signing_key)
        }
        None => {
            tracing::warn!(
                "no --signing-key-file: generated an ephemeral snapshot key; snapshots will stop verifying after a restart"
            );
            key_pair(
                did,
                SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
            )
        }
    };

    let registry: trusted_issuers_core::Registry = match &cli.data_file {
        Some(path) => load(path, cli.create_data_file)?,
        None => Default::default(),
    };
    tracing::info!(
        did = %key.own_did,
        issuers = registry.issuers.len(),
        version = registry.version,
        "trusted issuers registry listening on {}",
        cli.bind
    );

    let state = Arc::new(AppState::new(
        registry,
        key,
        cli.admin_token,
        cli.data_file,
        cli.snapshot_ttl_secs,
    ));
    if !state.admin_enabled() {
        tracing::warn!("no (or an empty) admin token configured: the admin API is disabled");
    }
    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .map_err(|e| format!("bind {}: {e}", cli.bind))?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::did_from_host;

    #[test]
    fn did_host_is_validated() {
        assert_eq!(
            did_from_host("Registry.Example").unwrap(),
            "did:web:registry.example"
        );
        assert_eq!(
            did_from_host("localhost:8090").unwrap(),
            "did:web:localhost%3A8090"
        );
        assert_eq!(
            did_from_host("registry.example:4430").unwrap(),
            "did:web:registry.example%3A4430"
        );
        for bad in [
            "",
            "https://registry.example",
            "a/b",
            "host:",
            "host:0",
            "host:99999",
            "-a.example",
            "a..b",
            // A leading zero would spell the same port a second way.
            "localhost:08090",
            // did:web uses https, so `:443` is the same URL as no port.
            "localhost:443",
            "registry.example:443",
            // did:web DIDs must not be IP addresses.
            "127.0.0.1",
            "127.0.0.1:8090",
        ] {
            assert!(did_from_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn did_host_refuses_what_url_parsing_reads_as_ipv4() {
        // url reads a last label of `0x` and hex digits as a number, so each
        // of these is 127.0.0.1 (or refused by url) and is no more a name
        // than `127.0.0.1` is.
        for bad in [
            "0x7f000001",
            "0X7F000001",
            "0x7f.0x1",
            "0x7f.0.0.0x1",
            "0x7f000001:8090",
            "0x",
            "example.0x10",
        ] {
            assert!(did_from_host(bad).is_err(), "{bad}");
        }
        // Names that merely contain `0x` stay names.
        assert_eq!(
            did_from_host("0xg.Example:8090").unwrap(),
            "did:web:0xg.example%3A8090"
        );
        assert_eq!(
            did_from_host("a.0x1b.example").unwrap(),
            "did:web:a.0x1b.example"
        );
    }

    #[test]
    fn did_host_443_error_says_to_omit_the_port() {
        let err = did_from_host("Localhost:443").unwrap_err();
        assert!(err.contains("omit ':443'"), "{err}");
        // Other bad hosts keep the general message.
        for bad in ["localhost:08090", "a..b", "127.0.0.1", "0x7f000001:443"] {
            let err = did_from_host(bad).unwrap_err();
            assert!(!err.contains("443"), "{bad}: {err}");
        }
    }
}
