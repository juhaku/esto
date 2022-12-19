use std::collections::HashMap;
use std::fmt::Display;
use std::marker::PhantomData;
use std::sync::Arc;

use ::time::OffsetDateTime;
use async_trait::async_trait;
use tokio::process::Command;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{broadcast, Mutex};
use tokio::time;
use tokio::time::{Duration, Instant};
use tokio_stream::StreamExt;

use crate::app::EstoError;
use crate::blocked_ip::BlockedIpsRepository;

#[async_trait]
pub trait CommandService {
    async fn block<V: AsRef<str> + Display + Send + Sync>(value: V) -> Result<(), EstoError>;

    async fn unblock<V: AsRef<str> + Display + Send + Sync>(value: V) -> Result<(), EstoError>;
}

#[derive(Default)]
pub struct DefaultCommandService;

#[async_trait]
impl CommandService for DefaultCommandService {
    // sudo iptables -D INPUT -s 61.177.173.16 -j DROP
    async fn unblock<V: AsRef<str> + Send>(value: V) -> Result<(), EstoError> {
        let value = value.as_ref();
        Command::new("sudo")
            .args(["iptables", "-D", "INPUT", "-s", value, "-j", "DROP"])
            .status()
            .await
            .map(|status| log::debug!("Unblock command exited with status: {status}"))
            .map_err(EstoError::BlockerUnblock)
    }

    // sudo iptables -I INPUT -s 61.177.173.16 -j DROP
    async fn block<V: AsRef<str> + Send>(value: V) -> Result<(), EstoError> {
        let value = value.as_ref();
        Command::new("sudo")
            .args(["iptables", "-I", "INPUT", "-s", value, "-j", "DROP"])
            .status()
            .await
            .map(|status| {
                log::debug!("Block command exited with status: {status}");
            })
            .map_err(EstoError::BlockerBlock)
    }
}

#[derive(Default, Debug)]
pub struct Storage {
    ips: Vec<Ip>,
    candidates: HashMap<String, Vec<Instant>>,
}

#[derive(Default)]
pub struct Blocker<C> {
    _p: PhantomData<C>,
    blocked_ip_repository: Option<BlockedIpsRepository>,
    storage: Arc<Mutex<Storage>>,
}

impl<C> Blocker<C>
where
    C: CommandService + Default,
{
    pub fn new(storage: Arc<Mutex<Storage>>, blocked_ip_repository: BlockedIpsRepository) -> Self {
        Self {
            storage,
            blocked_ip_repository: Some(blocked_ip_repository),
            ..Default::default()
        }
    }

    async fn load_ips_from_blocked_ips(&self) -> Result<(), EstoError> {
        if let Some(repository) = self.blocked_ip_repository.as_ref() {
            log::info!("Loading ips from blocked ips");
            let mut storage = self.storage.lock().await;
            let storage = &mut *storage;
            for (ip, _) in repository.get_blocked_ips().await?.into_iter() {
                storage.ips.push(Ip {
                    ip,
                    blocked: Instant::now(),
                })
            }
        };

        Ok(())
    }

    pub(crate) async fn run(
        &mut self,
        mut ip_receiver: Receiver<String>,
        close: broadcast::Receiver<()>,
    ) -> Result<(), EstoError> {
        log::info!("Staring up esto Blocker");
        let _ = self.load_ips_from_blocked_ips().await;
        const TIMEOUT_SECONDS: u64 = 60;
        let is_blocked_checkup = time::sleep(Duration::from_secs(TIMEOUT_SECONDS));
        tokio::pin!(is_blocked_checkup);
        tokio::pin!(close);

        loop {
            tokio::select! {
                Some(addr) = ip_receiver.recv() => {
                    log::debug!("received ip: {addr}");
                    if self.should_block_ip(addr.clone()).await && !self.is_blocked(&addr).await {
                        log::info!("Blocking ip: {addr}");
                        let ip = Ip { ip: addr, blocked: Instant::now() };
                        ip.block::<C>().await?;
                        if let Some(repository) = self.blocked_ip_repository.as_ref() {
                            repository.add_blocked_ip(&ip.ip, OffsetDateTime::now_utc().unix_timestamp()).await?;
                        };

                        let mut storage = self.storage.lock().await;
                        storage.ips.push(ip);
                    }
                }
                _ = close.recv() => {
                    log::info!("Received close broadcast, closing esto Blocker");
                    break;
                }
                _ = &mut is_blocked_checkup => {
                    {
                        let mut storage = self.storage.lock().await;
                        let storage = &mut *storage;

                        let (mut unblockable, blocked): (Vec<Ip>, Vec<Ip>) = storage
                                                         .ips
                                                         .clone()
                                                         .into_iter()
                                                         .partition(|ip| ip.can_unblock());
                        let mut unblock_ips = tokio_stream::iter(&mut unblockable);
                        while let Some(ip) = unblock_ips.next().await {
                            log::info!("Unblocking ip: {ip}", ip = ip.ip);
                            storage.candidates.remove(&ip.ip);
                            ip.unblock::<C>().await?;

                            if let Some(repository) = self.blocked_ip_repository.as_ref() {
                                repository.delete_blocked_ip(&ip.ip).await?;
                            };
                        }
                        storage.ips = blocked;
                    }
                    self.clear_stale_candidate_ips().await;
                    log::debug!("Restarting unblock ip checker timer");
                    // restart the timer
                    is_blocked_checkup.set(time::sleep(Duration::from_secs(TIMEOUT_SECONDS)));
                }
                else => {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn should_block_ip(&mut self, ip: String) -> bool {
        log::info!("Checking whether should block ip: {ip}");
        let mut storage = self.storage.lock().await;

        if let Some(instants) = storage.candidates.get_mut(&ip) {
            instants.push(Instant::now());

            // Take last 5 instants and check if they are withing block time
            let mut last_5_instants = instants.iter().rev().take(5);
            let last = last_5_instants.by_ref().by_ref().take(1).next();
            let first = last_5_instants.rev().take(1).next();

            let within_block_time = if let Some((first, last)) = first.zip(last) {
                last.duration_since(*first) < BLOCK_TIME
            } else {
                false
            };

            log::debug!(
                "instants: {instants}, within_block_time: {within_block_time}",
                instants = instants.len()
            );
            instants.len() > 4 && within_block_time
        } else {
            log::debug!("ip: '{ip}' is new one, putting it to candidate list");
            storage.candidates.insert(ip.clone(), vec![Instant::now()]);
            false
        }
    }

    async fn clear_stale_candidate_ips(&mut self) {
        let mut storage = self.storage.lock().await;
        let candidates = storage.candidates.len();
        log::info!("Clearing stale ips: {candidates}");
        storage.candidates.retain(|_, instants| {
            instants
                .last()
                .map(|instant| instant.elapsed() < BLOCK_TIME)
                .unwrap_or(true)
        });
        log::debug!(
            "Cleared: {}, previous: {}, current: {}",
            candidates - storage.candidates.len(),
            candidates,
            storage.candidates.len()
        )
    }

    async fn is_blocked(&self, addr: &str) -> bool {
        let storage = self.storage.lock().await;
        storage.ips.iter().any(|ip| ip.ip == addr)
    }
}

pub const BLOCK_TIME: Duration = Duration::from_secs(60 * 30);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Ip {
    ip: String,
    blocked: Instant,
}

impl Ip {
    fn can_unblock(&self) -> bool {
        log::trace!(
            "Can ip: '{}' be unblocked, {:?} > {:?}",
            &self.ip,
            &self.blocked.elapsed(),
            BLOCK_TIME
        );
        self.blocked.elapsed() > BLOCK_TIME
    }

    async fn unblock<C: CommandService>(&self) -> Result<(), EstoError> {
        C::unblock(&self.ip).await
    }

    async fn block<C: CommandService>(&self) -> Result<(), EstoError> {
        C::block(&self.ip).await
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fmt::Display;

    use sqlx::SqlitePool;
    use tokio::sync::{mpsc, OnceCell};

    use crate::db;

    use super::*;

    static IP: OnceCell<String> = OnceCell::const_new();
    static IP_UNBLOCKED: OnceCell<bool> = OnceCell::const_new();

    #[tokio::test(start_paused = true)]
    async fn block_unblock_ip() {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder().is_test(true).try_init();
        let (tx, rx) = mpsc::channel::<String>(100);
        let (btx, brx) = broadcast::channel(1);

        #[derive(Default)]
        struct NopCommandService;

        #[async_trait]
        impl CommandService for NopCommandService {
            async fn block<V: AsRef<str> + Display + Send + Sync>(
                value: V,
            ) -> Result<(), EstoError> {
                assert_eq!("61.177.173.16", value.as_ref(), "called with unexpected ip");
                IP.get_or_init(|| async { value.to_string() }).await;
                Ok(())
            }

            async fn unblock<V: AsRef<str> + Send>(value: V) -> Result<(), EstoError> {
                IP_UNBLOCKED.get_or_init(|| async { true }).await;
                assert_eq!("61.177.173.16", value.as_ref(), "called with unexpected ip");
                Ok(())
            }
        }

        let mut blocker = Blocker::<NopCommandService>::default();
        tokio::spawn(async move { blocker.run(rx, brx).await });

        tx.send("61.177.173.16".to_string()).await.unwrap();
        tx.send("61.177.173.16".to_string()).await.unwrap();
        tx.send("61.177.173.16".to_string()).await.unwrap();
        time::advance(Duration::from_secs(60)).await;
        tx.send("61.177.173.16".to_string()).await.unwrap();
        tx.send("61.177.173.16".to_string()).await.unwrap();
        time::advance(Duration::from_secs(60)).await;

        assert!(IP.get().is_some(), "expected IP to be present");

        time::advance(Duration::from_secs(120)).await;
        assert!(IP_UNBLOCKED.get().is_none(), "expected IP be still blocked");
        time::advance(Duration::from_secs(60 * 30)).await;
        time::advance(Duration::from_secs(60)).await;
        assert!(IP_UNBLOCKED.get().is_some(), "expected IP to be unblocked");
        if btx.send(()).is_ok() {}
    }

    // #[tokio::test(start_paused = true)]
    #[sqlx::test]
    async fn test_clear_block_cahdidates(pool: SqlitePool) {
        db::create_tables(&pool)
            .await
            .expect("failed to create tables");
        time::pause();
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder().is_test(true).try_init();
        let (tx, rx) = mpsc::channel::<String>(100);
        let (btx, brx) = broadcast::channel(1);

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

        let storage = Arc::new(Mutex::new(Storage::default()));
        let local_storage = storage.clone();

        let mut blocker =
            Blocker::<NopCommandService>::new(storage, BlockedIpsRepository(Arc::new(pool)));
        tokio::spawn(async move { blocker.run(rx, brx).await });

        tx.send("61.177.173.16".to_string()).await.unwrap();
        time::advance(Duration::from_secs(60)).await;
        tx.send("61.177.173.16".to_string()).await.unwrap();
        time::advance(Duration::from_secs(60)).await;
        tx.send("61.177.173.16".to_string()).await.unwrap();
        time::advance(Duration::from_secs(60)).await;

        assert!(
            !local_storage.lock().await.candidates.is_empty(),
            "expected block candidates not be empty"
        );

        time::advance(Duration::from_secs(60 * 60 * 3)).await;
        time::advance(Duration::from_secs(120)).await;

        let local_storage = local_storage.lock().await;
        assert!(
            local_storage.candidates.is_empty(),
            "expected block ip candidates be empty"
        );

        if local_storage.candidates.is_empty() && btx.send(()).is_ok() {}
    }

    #[sqlx::test]
    async fn restore_ips_from_blocked_ips(pool: SqlitePool) {
        db::create_tables(&pool)
            .await
            .expect("failed to create tables");
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder().is_test(true).try_init();
        let (_, rx) = mpsc::channel::<String>(100);
        let (btx, brx) = broadcast::channel(1);

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
        let repository = BlockedIpsRepository(Arc::new(pool));
        let _ = repository.add_blocked_ip("127.1.1.3", 1).await;
        let _ = repository.add_blocked_ip("127.1.1.4", 1).await;
        let _ = repository.add_blocked_ip("127.1.1.2", 1).await;

        let storage = Arc::new(Mutex::new(Storage::default()));
        let local_storage = storage.clone();

        let mut blocker = Blocker::<NopCommandService>::new(storage, repository.clone());
        let handle = tokio::spawn(async move { blocker.run(rx, brx).await });
        let (_, _) = tokio::join!(handle, async move {
            let _ = btx.send(());
        });

        assert_eq!(
            3,
            local_storage.lock().await.ips.len(),
            "expected 3 restored ips"
        );
    }
}
