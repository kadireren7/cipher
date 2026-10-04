//! PostgreSQL connection pool. Transport security to the database is mandatory except for loopback
//! (development / CI service containers): `sslmode=disable|prefer|allow` on a non-loopback host is refused.
use crate::error::ApiError;
use deadpool_postgres::{ManagerConfig, Pool, RecyclingMethod, Runtime};
use std::str::FromStr;
use std::sync::Arc;
use tokio_postgres::config::{Host, SslMode};

#[derive(Debug, thiserror::Error)]
pub enum DbConfigError {
    #[error("invalid database url")]
    Url,
    #[error("database TLS is required for non-loopback hosts (use sslmode=require or verify-full)")]
    TlsRequired,
    #[error("cannot build database pool")]
    Pool,
}

fn is_loopback(cfg: &tokio_postgres::Config) -> bool {
    !cfg.get_hosts().is_empty()
        && cfg.get_hosts().iter().all(|h| match h {
            Host::Tcp(name) => name == "localhost" || name.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()),
            Host::Unix(_) => true,
        })
}

pub fn build_pool(url: &str, max_size: usize, extra_ca_pem: Option<&[u8]>) -> Result<Pool, DbConfigError> {
    let pg = tokio_postgres::Config::from_str(url).map_err(|_| DbConfigError::Url)?;
    let loopback = is_loopback(&pg);
    let manager_cfg = ManagerConfig { recycling_method: RecyclingMethod::Fast };
    let tls_wanted = pg.get_ssl_mode() == SslMode::Require;
    if !loopback && !tls_wanted {
        return Err(DbConfigError::TlsRequired);
    }
    let pool = if tls_wanted {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = extra_ca_pem {
            use rustls::pki_types::pem::PemObject;
            for c in rustls::pki_types::CertificateDer::pem_slice_iter(pem) {
                roots.add(c.map_err(|_| DbConfigError::Url)?).map_err(|_| DbConfigError::Url)?;
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| DbConfigError::Pool)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_postgres_rustls::MakeRustlsConnect::new(tls);
        let mgr = deadpool_postgres::Manager::from_config(pg, connector, manager_cfg);
        Pool::builder(mgr).max_size(max_size).runtime(Runtime::Tokio1).build().map_err(|_| DbConfigError::Pool)?
    } else {
        let mgr = deadpool_postgres::Manager::from_config(pg, tokio_postgres::NoTls, manager_cfg);
        Pool::builder(mgr).max_size(max_size).runtime(Runtime::Tokio1).build().map_err(|_| DbConfigError::Pool)?
    };
    Ok(pool)
}

pub fn internal<E>(_: E) -> ApiError {
    // Deliberately drops the driver error: it can embed row data or SQL fragments.
    ApiError::Internal
}
