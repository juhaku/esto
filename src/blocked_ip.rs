use std::marker::PhantomData;
use std::sync::Arc;

use sqlx::SqlitePool;
use time::{Duration, OffsetDateTime};
use tokio_stream::StreamExt;

use crate::app::EstoError;
use crate::blocker::CommandService;

#[derive(Debug, Clone)]
pub struct BlockedIpsRepository(pub Arc<SqlitePool>);

impl BlockedIpsRepository {
    pub async fn delete_blocked_ip(&self, ip: &str) -> Result<(), EstoError> {
        log::info!("Deleting ip: {ip}, from blocked ips");
        let BlockedIpsRepository(pool) = self;
        sqlx::query("delete from blocked_ips where ip = ?")
            .bind(ip)
            .execute(pool.as_ref())
            .await
            .map(|result| log::info!("Unblocked ips: {count}", count = result.rows_affected()))
            .map_err(EstoError::Sqlx)
    }

    pub async fn add_blocked_ip(&self, ip: &str, blocked: i64) -> Result<(), EstoError> {
        log::info!("Adding ip: {ip}, to blocked ips");
        let BlockedIpsRepository(pool) = self;

        sqlx::query("insert into blocked_ips (ip, time) values(?, ?)")
            .bind(ip)
            .bind(blocked)
            .execute(pool.as_ref())
            .await
            .map(|_| log::info!("Blocked ip {ip}"))
            .map_err(EstoError::Sqlx)
    }

    pub async fn get_blocked_ips(&self) -> Result<Vec<(String, i64)>, EstoError> {
        let BlockedIpsRepository(pool) = self;

        sqlx::query_as::<_, (String, i64)>("select ip, time from blocked_ips")
            .fetch_all(pool.as_ref())
            .await
            .map_err(EstoError::Sqlx)
    }
}

pub struct BlockedIpService<C>(BlockedIpsRepository, PhantomData<C>);

impl<C> BlockedIpService<C>
where
    C: CommandService,
{
    pub fn new(blocked_ip_repository: BlockedIpsRepository) -> Self {
        Self(blocked_ip_repository, PhantomData)
    }

    pub async fn unblock_expired_stored_blocked_ips(
        &self,
        block_time: Duration,
    ) -> Result<(), EstoError> {
        log::info!("unblocking stored blocked ips");
        let BlockedIpService(repository, ..) = self;
        let now = OffsetDateTime::now_utc();
        let mut expired_stored_ips =
            tokio_stream::iter(repository.get_blocked_ips().await?.into_iter().filter(
                |(_, time)| {
                    let time = OffsetDateTime::from_unix_timestamp(*time)
                        .expect("failed to construct offset date time")
                        + block_time;

                    log::debug!("{time:?} < {now:?}");
                    time < now
                },
            ));

        while let Some((ip, _)) = expired_stored_ips.next().await {
            log::debug!("unblocking ip: {ip}");
            C::unblock(&ip).await?;
            repository.delete_blocked_ip(&ip).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::env;
    use std::fmt::Display;

    use async_trait::async_trait;

    use crate::{blocker, db};

    use super::*;

    #[sqlx::test]
    async fn add_delete_blocked_ip(pool: SqlitePool) {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder().is_test(true).try_init();
        db::create_tables(&pool)
            .await
            .expect("failed to create tables");
        let repository = BlockedIpsRepository(Arc::new(pool));

        repository
            .add_blocked_ip("127.0.0.1", OffsetDateTime::now_utc().unix_timestamp())
            .await
            .expect("failed to add blocked ip");

        assert_eq!(
            1,
            repository
                .get_blocked_ips()
                .await
                .expect("failed to get blocked ips")
                .len(),
            "expected 1 blocked ip"
        );

        repository
            .delete_blocked_ip("127.0.0.1")
            .await
            .expect("failed to delete blocked ip");

        assert_eq!(
            0,
            repository
                .get_blocked_ips()
                .await
                .expect("failed to get blocked ips")
                .len(),
            "expected 0 blocked ip"
        )
    }

    #[sqlx::test]
    async fn unblock_stored_blocked_ips(pool: SqlitePool) {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder().is_test(true).try_init();
        db::create_tables(&pool)
            .await
            .expect("failed to create tables");
        #[derive(Default)]
        struct NopCommandService;

        #[async_trait]
        impl CommandService for NopCommandService {
            async fn block<V: AsRef<str> + Display + Send + Sync>(_: V) -> Result<(), EstoError> {
                Ok(())
            }

            async fn unblock<V: AsRef<str> + Send>(_: V) -> Result<(), EstoError> {
                Ok(())
            }
        }
        let repository = BlockedIpsRepository(Arc::new(pool.clone()));
        let service = BlockedIpService::<NopCommandService>::new(repository.clone());

        repository
            .add_blocked_ip("127.0.0.1", OffsetDateTime::now_utc().unix_timestamp())
            .await
            .expect("failed to add blocked ip");

        repository
            .add_blocked_ip(
                "127.0.0.2",
                (OffsetDateTime::now_utc() - Duration::minutes(31)).unix_timestamp(),
            )
            .await
            .expect("failed to add blocked ip");

        assert_eq!(
            2,
            repository
                .get_blocked_ips()
                .await
                .expect("failed to get blocked ips")
                .len(),
            "expected 2 blocked ips"
        );

        service
            .unblock_expired_stored_blocked_ips(time::Duration::new(
                blocker::BLOCK_TIME.as_secs() as i64,
                0,
            ))
            .await
            .expect("failed to unblock expired stored blocked ips");

        assert_eq!(
            1,
            repository
                .get_blocked_ips()
                .await
                .expect("failed to get blocked ips")
                .len(),
            "expected 1 blocked ips"
        );
    }
}
