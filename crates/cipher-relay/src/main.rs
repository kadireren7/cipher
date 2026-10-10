use cipher_relay::api::{AppState, Limits, SystemClock};
use cipher_relay::config::Config;
use cipher_relay::conn_limit::LimitAcceptor;
use cipher_relay::push::NullPush;
use cipher_relay::store::PgStore;
use std::net::SocketAddr;
use std::sync::Arc;

fn die(msg: &str) -> ! {
    tracing::error!("{msg}");
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    // `cipher-relay healthcheck`: container HEALTHCHECK client (reads CIPHER_RELAY_HEALTH_LISTEN; /readyz).
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let ok = match std::env::var("CIPHER_RELAY_HEALTH_LISTEN").ok().and_then(|v| cipher_relay::health::parse_listen(&v)) {
            Some(addr) => cipher_relay::health::probe(addr, "/readyz").await,
            None => false,
        };
        std::process::exit(if ok { 0 } else { 1 });
    }
    cipher_relay::logging::init();
    let cfg = match Config::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => die(&format!("refusing to start: {e}")),
    };
    let ca = cfg.db_ca_pem.as_ref().and_then(|p| std::fs::read(p).ok());
    let pool = match cipher_relay::db::build_pool(&cfg.database_url, cfg.db_pool_size, ca.as_deref()) {
        Ok(p) => p,
        Err(e) => die(&format!("refusing to start: {e}")),
    };
    if cipher_relay::migrations::run(&pool).await.is_err() {
        die("refusing to start: database migration failed or schema is not compatible with this build");
    }
    let store = Arc::new(PgStore::new(pool));
    let state = Arc::new(AppState::new(store.clone(), cfg.clone(), Arc::new(SystemClock), Arc::new(NullPush), Limits::default()));
    let purge_store = store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let _ = purge_store.purge(cipher_relay::api::Clock::now(&SystemClock)).await;
        }
    });
    if let Ok(v) = std::env::var("CIPHER_RELAY_HEALTH_LISTEN") {
        let Some(addr) = cipher_relay::health::parse_listen(&v) else { die("CIPHER_RELAY_HEALTH_LISTEN must be a loopback address") };
        let health = cipher_relay::health::router(state.clone());
        tokio::spawn(async move {
            if let Ok(l) = tokio::net::TcpListener::bind(addr).await {
                let _ = axum::serve(l, health).await;
            }
        });
    }
    let app = cipher_relay::build_app(state).into_make_service_with_connect_info::<SocketAddr>();
    let limit = LimitAcceptor::new(cfg.max_connections);
    match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => {
            let (Ok(cert), Ok(key)) = (std::fs::read(c), std::fs::read(k)) else { die("cannot read TLS material") };
            let Ok(tls) = cipher_relay::tls::server_config(&cert, &key) else { die("invalid TLS material") };
            tracing::info!("listening (TLS 1.3)");
            let rc = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
            let server = axum_server::bind_rustls(cfg.listen, rc)
                .map(|a| a.handshake_timeout(std::time::Duration::from_secs(cfg.tls_handshake_secs)).acceptor(limit));
            if server.serve(app).await.is_err() {
                std::process::exit(1);
            }
        }
        _ => {
            // Config::check_transport already restricted this to explicit loopback dev mode.
            tracing::warn!("INSECURE DEV MODE: plain HTTP on loopback only");
            if axum_server::bind(cfg.listen).acceptor(limit).serve(app).await.is_err() {
                std::process::exit(1);
            }
        }
    }
}
