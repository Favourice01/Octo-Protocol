//! `octo-migrate-keys` — offline, resumable master-key rotation tool.
//!
//! ## Purpose
//!
//! Re-seals every wallet's HD seed under a new master key (and/or cipher scheme) without
//! requiring a maintenance window. The tool operates in batches so it can be safely interrupted
//! and re-run; already-migrated wallets are skipped automatically.
//!
//! ## Dual-key rotation window
//!
//! During a rotation, **both** the old and the new master key must be available to the running
//! `octo-server` process so it can open seeds that have not yet been migrated. Once this tool
//! reports 0 wallets remaining, the old key can be removed from the environment.
//!
//! Configure the two keys via environment variables:
//!
//! ```text
//! MASTER_KEY      = <base64-encoded current/old key>   # the key octo-server currently uses
//! MASTER_KEY_NEXT = <base64-encoded new key>           # the key to rotate to
//! ```
//!
//! When `MASTER_KEY_NEXT` is absent the tool defaults to `MASTER_KEY` for both old and new,
//! which is still useful as a cipher-upgrade path (re-seal all rows under the latest scheme
//! even if the key itself doesn't change).
//!
//! ## Idempotency
//!
//! A row that already opens under the new key is skipped, and `reseal_wallet` only writes when
//! the row still holds the ciphertext that was read (compare-and-swap). Re-running the tool
//! against a fully-migrated database is safe and produces 0 updates. See `lib.rs`.
//!
//! ## Rollback
//!
//! Old-key and new-key records can coexist indefinitely: during the rotation window the server
//! tries `MASTER_KEY_NEXT` first and falls back to `MASTER_KEY` (AES-GCM authentication tells
//! them apart). To abort, stop the tool. Rolling back a completed rotation means running the tool
//! again with the old and new keys swapped.
//!
//! ## Usage
//!
//! ```bash
//! # Rotate from MASTER_KEY to MASTER_KEY_NEXT, batch of 100 at a time:
//! MASTER_KEY=<old_b64> MASTER_KEY_NEXT=<new_b64> \
//!   cargo run -p octo-migrate-keys -- --batch-size 100
//!
//! # Re-seal all rows under the current key/scheme (cipher upgrade only):
//! MASTER_KEY=<b64> \
//!   cargo run -p octo-migrate-keys -- --batch-size 100
//! ```

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use base64::Engine;
use octo_crypto::{master_key_from_slice, MASTER_KEY_LEN};
use octo_store::Store;

/// Maximum rows per batch (hard cap, configurable via CLI).
const DEFAULT_BATCH_SIZE: i64 = 100;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    init_tracing();

    let cfg = Config::from_env()?;

    tracing::info!(
        batch_size = cfg.batch_size,
        same_key = (cfg.old_key == cfg.new_key),
        "octo-migrate-keys starting"
    );

    let store = Store::connect(&cfg.database_url)
        .await
        .context("connect to database")?;
    store.migrate().await.context("run migrations")?;

    let summary =
        octo_migrate_keys::migrate(&store, &cfg.old_key, &cfg.new_key, cfg.batch_size, |_| {
            Ok(())
        })
        .await?;

    tracing::info!(
        total_migrated = summary.migrated,
        total_skipped = summary.skipped,
        "migration complete — every sealed wallet now opens under the new key"
    );
    Ok(())
}

struct Config {
    database_url: String,
    old_key: [u8; MASTER_KEY_LEN],
    new_key: [u8; MASTER_KEY_LEN],
    batch_size: i64,
}

impl Config {
    fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;

        let old_key = decode_key("MASTER_KEY")?;

        // MASTER_KEY_NEXT is optional: if absent, re-seal under the same key (cipher upgrade only).
        let new_key = if std::env::var("MASTER_KEY_NEXT").is_ok() {
            decode_key("MASTER_KEY_NEXT")?
        } else {
            tracing::info!(
                "MASTER_KEY_NEXT not set; re-sealing under MASTER_KEY (cipher/scheme upgrade only)"
            );
            old_key
        };

        // --batch-size N from argv, or DEFAULT_BATCH_SIZE.
        let batch_size = std::env::args()
            .skip_while(|a| a != "--batch-size")
            .nth(1)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(DEFAULT_BATCH_SIZE);

        Ok(Config {
            database_url,
            old_key,
            new_key,
            batch_size,
        })
    }
}

fn decode_key(env_var: &str) -> Result<[u8; MASTER_KEY_LEN]> {
    let b64 = std::env::var(env_var).with_context(|| format!("{env_var} is required"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .with_context(|| format!("{env_var} is not valid base64"))?;
    master_key_from_slice(&raw).map_err(|_| anyhow::anyhow!("{env_var} must be exactly 32 bytes"))
}

fn init_tracing() {
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info,octo_migrate_keys=debug".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();
}
