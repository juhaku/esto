use std::sync::Arc;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Executor, SqlitePool};

use crate::app::EstoError;

pub async fn init(dbfile: String) -> Result<Arc<SqlitePool>, EstoError> {
    log::info!("Connect and initialize database");
    let pool = SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(dbfile)
            .create_if_missing(true),
    )
    .await?;

    create_tables(&pool).await?;

    Ok(Arc::new(pool))
}

pub async fn create_tables(pool: &SqlitePool) -> Result<(), EstoError> {
    const BLOCKED_IPS_TABLE: &str = "create table if not exists blocked_ips(
        ip text primary key,
        time integer
    )";
    pool.execute(BLOCKED_IPS_TABLE).await?;

    Ok(())
}
