use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use dcp_core::DcpKeyPair;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use tokio::sync::RwLock;
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

    /// Bearer token for the admin (write) API. Without it the admin API is
    /// disabled. Prefer the environment variable over the flag, so the
    /// token stays out of process listings.
    #[arg(long, env = "TRUSTED_ISSUERS_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,

    /// How long a signed snapshot stays valid, in seconds.
    #[arg(long, default_value_t = 3600)]
    snapshot_ttl_secs: u64,
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

    let did = format!("did:web:{}", cli.did_host.replace(':', "%3A"));
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

    let registry = match &cli.data_file {
        Some(path) => load(path)?,
        None => Default::default(),
    };
    if cli.admin_token.is_none() {
        tracing::warn!("no admin token configured: the admin API is disabled");
    }
    tracing::info!(
        did = %key.own_did,
        issuers = registry.issuers.len(),
        version = registry.version,
        "trusted issuers registry listening on {}",
        cli.bind
    );

    let state = Arc::new(AppState {
        registry: RwLock::new(registry),
        key,
        admin_token: cli.admin_token,
        data_file: cli.data_file,
        snapshot_ttl_secs: cli.snapshot_ttl_secs,
    });
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
