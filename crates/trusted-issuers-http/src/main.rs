use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use contreforts_core::{ContrefortsConnector, EntityKind};
use dcp_core::DcpKeyPair;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use trusted_issuers_contreforts::{ISSUER_RECORD_KIND, RegistryGraphConnector};
use trusted_issuers_core::{PostalAddress, is_did_web_port, is_dns_name};
use trusted_issuers_http::{AppState, GraphStore, JsonFileStore, MemoryStore, Store, router};

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

    /// JSON file the registry is loaded from and saved to after each write,
    /// with its audit log next to it (`<file>.audit.jsonl`). Without it (or
    /// `--graph-dir`) the registry lives in memory only.
    #[arg(long, conflicts_with = "graph_dir")]
    data_file: Option<PathBuf>,

    /// Directory of the registry graph: records and audit log as RDF in an
    /// on-disk Oxigraph store, reachable through Contreforts' connector
    /// interface (created if missing).
    #[arg(long)]
    graph_dir: Option<PathBuf>,

    /// Move the registry in this JSON data file into `--graph-dir`, which
    /// must not hold a registry yet. A one-time migration from
    /// `--data-file`; its audit log is not carried over.
    #[arg(long, requires = "graph_dir")]
    import_data_file: Option<PathBuf>,

    /// Start with an empty registry when `--data-file` doesn't exist yet.
    /// Without it a missing file is a startup error, so an unmounted volume
    /// can't silently serve an empty list.
    #[arg(long, requires = "data_file")]
    create_data_file: bool,

    /// Bearer token for the admin (write) API. Without it the admin API is
    /// disabled. Prefer the environment variable over the flag, so the
    /// token stays out of process listings.
    #[arg(long, env = "TRUSTED_ISSUERS_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,

    /// Request header the gateway sets to the authenticated person behind
    /// an admin write (e.g. `X-Forwarded-User`), recorded as the actor in
    /// the audit log. Without it every write is recorded as `admin`. Only
    /// set it when nothing but the gateway can reach the admin API.
    #[arg(long, value_parser = parse_header_name)]
    audit_actor_header: Option<String>,

    /// `SchemeOperatorName` of the published LoTE (`GET /v1/lote`).
    #[arg(long, default_value = "Dataspace authority")]
    lote_operator_name: String,

    /// Street of the LoTE scheme operator's postal address. ETSI TS 119 602
    /// requires one, so `GET /v1/lote` answers 503 until the street, the
    /// locality and the country are all given.
    #[arg(long, requires_all = ["lote_operator_locality", "lote_operator_country"])]
    lote_operator_street: Option<String>,

    /// Locality (city) of the LoTE scheme operator's postal address.
    #[arg(long, requires = "lote_operator_street")]
    lote_operator_locality: Option<String>,

    /// Postal code of the LoTE scheme operator's postal address.
    #[arg(long, requires = "lote_operator_street")]
    lote_operator_postal_code: Option<String>,

    /// State, province or region of the LoTE scheme operator's postal
    /// address.
    #[arg(long, requires = "lote_operator_street")]
    lote_operator_region: Option<String>,

    /// Country (ISO 3166-1 alpha-2) of the LoTE scheme operator's postal
    /// address.
    #[arg(long, requires = "lote_operator_street")]
    lote_operator_country: Option<String>,

    /// `LoTEType` URI of the published LoTE.
    #[arg(long, default_value = trusted_issuers_core::DEFAULT_LOTE_TYPE)]
    lote_type: String,

    /// `SchemeTerritory` of the published LoTE (ISO 3166-1 alpha-2, or EU).
    #[arg(long)]
    lote_territory: Option<String>,

    /// Public base URL of the registry API, for the LoTE's addresses and
    /// distribution point. Defaults to the https origin of its did:web.
    #[arg(long)]
    public_base_url: Option<String>,

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

fn parse_header_name(name: &str) -> Result<String, String> {
    axum::http::HeaderName::try_from(name)
        .map(|_| name.to_string())
        .map_err(|_| format!("'{name}' is not a valid HTTP header name"))
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

/// The LoTE operator's postal address from the `--lote-operator-*` flags,
/// `None` when none is given, checked like any party's address.
fn operator_address(cli: &Cli) -> Result<Option<PostalAddress>, String> {
    let (Some(street), Some(locality), Some(country)) = (
        &cli.lote_operator_street,
        &cli.lote_operator_locality,
        &cli.lote_operator_country,
    ) else {
        return Ok(None);
    };
    let address = PostalAddress {
        street_address: street.clone(),
        locality: locality.clone(),
        postal_code: cli.lote_operator_postal_code.clone(),
        state_or_province: cli.lote_operator_region.clone(),
        country: country.clone(),
    };
    match address.problem() {
        Some(problem) => Err(format!("LoTE operator address: {problem}")),
        None => Ok(Some(address)),
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
    // Checked before anything is opened, so a bad address fails fast.
    let operator_address = operator_address(&cli)?;

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

    let (store, registry): (Arc<dyn Store>, trusted_issuers_core::Registry) =
        match (&cli.graph_dir, &cli.data_file) {
            (Some(dir), _) => {
                let (store, registry) = GraphStore::open(dir, cli.import_data_file.as_deref())?;
                // Proves the Contreforts round trip over the graph the admin
                // API writes into, as ds-identity-hub-rs does at startup.
                let records = RegistryGraphConnector::new(store.graph())
                    .pull(EntityKind::new(ISSUER_RECORD_KIND), None)
                    .await
                    .map_err(|e| format!("contreforts round trip: {e}"))?;
                tracing::info!(
                    graph = %dir.display(),
                    records = records.len(),
                    "registry graph open, reachable through the Contreforts connector"
                );
                (Arc::new(store), registry)
            }
            (None, Some(path)) => {
                let (store, registry) = JsonFileStore::open(path, cli.create_data_file)?;
                (Arc::new(store), registry)
            }
            (None, None) => (Arc::new(MemoryStore::new()), Default::default()),
        };
    tracing::info!(
        did = %key.own_did,
        issuers = registry.issuers.len(),
        version = registry.version,
        "trusted issuers registry listening on {}",
        cli.bind
    );

    let mut state = AppState::new(registry, key, cli.admin_token, store, cli.snapshot_ttl_secs);
    if let Some(name) = &cli.audit_actor_header {
        state = state.with_audit_actor_header(name);
    }
    let base_url = cli
        .public_base_url
        .clone()
        .unwrap_or_else(|| trusted_issuers_http::base_url_of(&state.key.own_did));
    match operator_address {
        Some(operator_address) => {
            state = state.with_lote(trusted_issuers_core::LoteOptions {
                operator_name: cli.lote_operator_name.clone(),
                operator_address,
                base_url,
                lote_type: cli.lote_type.clone(),
                territory: cli.lote_territory.clone(),
            });
        }
        None => tracing::warn!(
            "no LoTE operator address configured (--lote-operator-street, -locality, -country): GET /v1/lote is disabled"
        ),
    }
    let state = Arc::new(state);
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
    fn the_lote_base_url_is_the_did_web_origin() {
        use trusted_issuers_http::base_url_of;
        assert_eq!(
            base_url_of("did:web:registry.example"),
            "https://registry.example"
        );
        assert_eq!(
            base_url_of("did:web:localhost%3A8090"),
            "https://localhost:8090"
        );
        assert_eq!(
            base_url_of("did:web:host.example:tir"),
            "https://host.example/tir"
        );
    }

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
        for bad in ["localhost:08090", "a..b", "127.0.0.1"] {
            let err = did_from_host(bad).unwrap_err();
            assert!(!err.contains("443"), "{bad}: {err}");
        }
        // Not a name, so there is no port to omit; the message echoes the
        // host, which is why this checks the advice and not for "443".
        let err = did_from_host("0x7f000001:443").unwrap_err();
        assert!(!err.contains("omit"), "{err}");
    }

    #[test]
    fn the_lote_operator_address_comes_from_its_flags() {
        use super::{Cli, operator_address};
        use clap::Parser;
        let parse = |extra: &[&str]| {
            let args = ["registry", "--did-host", "registry.example"];
            Cli::try_parse_from(args.iter().chain(extra))
        };
        assert_eq!(operator_address(&parse(&[]).unwrap()), Ok(None));
        let cli = parse(&[
            "--lote-operator-street",
            "Rue de la Loi 200",
            "--lote-operator-locality",
            "Brussels",
            "--lote-operator-postal-code",
            "1049",
            "--lote-operator-country",
            "BE",
        ])
        .unwrap();
        let address = operator_address(&cli).unwrap().unwrap();
        assert_eq!(address.locality, "Brussels");
        assert_eq!(address.postal_code.as_deref(), Some("1049"));
        // Street, locality and country go together.
        assert!(parse(&["--lote-operator-street", "Rue de la Loi 200"]).is_err());
        assert!(parse(&["--lote-operator-country", "BE"]).is_err());
        let cli = parse(&[
            "--lote-operator-street",
            "Rue de la Loi 200",
            "--lote-operator-locality",
            "Brussels",
            "--lote-operator-country",
            "Belgium",
        ])
        .unwrap();
        let err = operator_address(&cli).unwrap_err();
        assert!(err.contains("ISO 3166-1"), "{err}");
    }
}
