use std::path::PathBuf;
use std::sync::Arc;
use std::{env, io};

use async_recursion::async_recursion;
use futures::{future, Future};
use serde::{Deserialize, Serialize};
use tokio::signal::unix::{self, SignalKind};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::{fs, signal, task};

use crate::analyzer::Analyser;
use crate::blocked_ip::{BlockedIpService, BlockedIpsRepository};
use crate::blocker::{Blocker, BlockerConfig, DefaultCommandService, Storage};
use crate::db;

const ESTO_CONFIG_PATH_KEY: &str = "ESTO_CONFIG_PATH";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub dbfile: String,
    pub block_time_sec: u64,
    pub commands: Vec<Command>,
    pub input: BlockerThresholds,
    pub docker: BlockerThresholds,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Command {
    pub command: String,
    pub contains: Vec<String>,
    pub matcher: Matcher,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Matcher {
    AuthLog,
    KernelLog,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockerThresholds {
    #[serde(default)]
    pub threshold_seconds: u64,
    #[serde(default)]
    pub threshold_ips: i16,
}

#[derive(thiserror::Error, Debug)]
pub enum EstoError {
    #[error("No `ESTO_CONFIG_PATH` env variable set")]
    NoConfigEnvVar(#[from] env::VarError),

    #[error("Toml: could not deserialize: {0}")]
    TomlDeserialize(#[from] toml::de::Error),

    #[error("Io: {0}")]
    Io(#[from] std::io::Error),

    #[error("Could not send ip to blocker: {0}")]
    SendBlocker(mpsc::error::SendError<String>),

    #[error("Failed to receive oneshot result: {0}")]
    OneshotReceive(#[from] oneshot::error::RecvError),

    #[error("Invalid analyzer command: '{0}', should at least be two words")]
    InvalidAnalyzerCommand(String),

    #[error("Tokio join task: {0}")]
    TokioJoin(#[from] task::JoinError),

    #[error("Analyzer handle await errored: {0}")]
    AnalyzerHandleAwait(io::Error),

    #[error("Blocker unblock: {0}")]
    BlockerUnblock(io::Error),

    #[error("Blocker block: {0}")]
    BlockerBlock(io::Error),

    #[error("Shutdown broadcast: {0}")]
    Broadcast(#[from] broadcast::error::SendError<()>),

    #[error("Sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("Anlyze command error exit with code: {0:?}")]
    AnalyzeCommand(Option<i32>),
}

pub async fn run() -> Result<(), EstoError> {
    env::var("ESTO_JOURNAL_LOGGING")
        .map(|_| {
            systemd_journal_logger::init().expect("Failed to initialize systemd journal logger");
            log::set_max_level(log::LevelFilter::Debug);
        })
        .unwrap_or_else(|_| env_logger::init());
    log::info!("Starting up esto: {version}", version = env!("CARGO_PKG_VERSION"));
    let config = load_config().await?;
    log::debug!("config: {config:#?}");
    let pool = db::init(config.dbfile).await?;

    let service =
        BlockedIpService::<DefaultCommandService>::new(BlockedIpsRepository(pool.clone()));
    service
        .unblock_expired_stored_blocked_ips(
            time::Duration::new(config.block_time_sec as i64, 0),
            "INPUT",
        )
        .await?;
    service
        .unblock_expired_stored_blocked_ips(
            time::Duration::new(config.block_time_sec as i64, 0),
            "DOCKER",
        )
        .await?;

    let (btx, _) = broadcast::channel(1);
    // start backgroud task which listens termiante signals
    let btx2 = btx.clone();
    tokio::spawn(async { register_graceful_shutdown(btx2).await });

    let storage = Arc::new(Mutex::new(Storage::default()));
    let repository = BlockedIpsRepository(pool);
    let threshold_seconds = config.block_time_sec;

    let (default_blocker_sender, default_blocker) = create_blocker(
        storage.clone(),
        repository.clone(),
        BlockerConfig {
            threshold_seconds: if config.input.threshold_seconds == 0 {
                threshold_seconds
            } else {
                config.input.threshold_seconds
            },
            threshold_ips: config.input.threshold_ips,
            channel: "INPUT",
            block_time: threshold_seconds,
        },
        btx.subscribe(),
    )
    .await;

    let (kernel_blocker_sender, kernel_blocker) = create_blocker(
        storage,
        repository,
        BlockerConfig {
            threshold_seconds: if config.docker.threshold_seconds == 0 {
                threshold_seconds
            } else {
                config.docker.threshold_seconds
            },
            threshold_ips: config.docker.threshold_ips,
            channel: "DOCKER",
            block_time: threshold_seconds,
        },
        btx.subscribe(),
    )
    .await;

    let command_handlers = future::join_all(
        config
            .commands
            .into_iter()
            .map(|command| {
                let blocker = if command.matcher == Matcher::AuthLog {
                    default_blocker_sender.clone()
                } else {
                    kernel_blocker_sender.clone()
                };
                let analyzer: Analyser = command.into();
                let btx = btx.clone();
                tokio::spawn(async move {
                    #[async_recursion]
                    async fn run(
                        analyzer: Analyser,
                        blocker: mpsc::Sender<String>,
                        shutdown_sender: broadcast::Sender<()>,
                        mut max_attemts: i8,
                    ) -> Box<impl Future<Output = Result<(), EstoError>>> {
                        let result = analyzer
                            .run(blocker.clone(), shutdown_sender.subscribe())
                            .await;
                        max_attemts -= 1;

                        let get_result = |result| Box::new(async { result });
                        log::debug!("max attempts: {max_attemts}");
                        match result {
                            Err(_) if max_attemts > 0 => {
                                run(analyzer, blocker, shutdown_sender, max_attemts).await
                            }
                            _ => get_result(result),
                        }
                    }

                    run(analyzer, blocker, btx, 5).await
                })
            })
            .collect::<Vec<_>>(),
    );

    let (_, _, _) = tokio::join!(default_blocker, kernel_blocker, command_handlers);

    Ok(())
}

async fn load_config() -> Result<Config, EstoError> {
    let config_path = env::var(ESTO_CONFIG_PATH_KEY)?;
    let config_content = fs::read_to_string([&config_path].iter().collect::<PathBuf>()).await?;
    let config = toml::from_str::<Config>(&config_content)?;
    log::info!("Esto config loaded from: {config_path}");

    Ok(config)
}

async fn register_graceful_shutdown(shutdown: broadcast::Sender<()>) -> Result<(), EstoError> {
    let sighup = async {
        let mut sighup =
            unix::signal(SignalKind::hangup()).expect("Failed to listen SIGHUP signal");

        sighup.recv().await
    };
    let terminate = async {
        let mut terminate =
            unix::signal(SignalKind::terminate()).expect("Failed to listen SIGTERM signal");

        terminate.recv().await
    };
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    tokio::pin!(sighup);
    tokio::pin!(terminate);

    tokio::select! {
        _ = &mut ctrl_c => {
            log::debug!("Received ctrl_c");
            shutdown.send(())?;
        }
        _ = &mut sighup => {
            log::debug!("Received sighup");
            shutdown.send(())?;
        }
        _ = &mut terminate => {
            log::debug!("Received sigterm");
            shutdown.send(())?;
        }
    };

    Ok(())
}

async fn create_blocker(
    storage: Arc<Mutex<Storage>>,
    repository: BlockedIpsRepository,
    config: BlockerConfig,
    shutdown_receiver: broadcast::Receiver<()>,
) -> (mpsc::Sender<String>, JoinHandle<Result<(), EstoError>>) {
    let (tx, rx) = mpsc::channel::<String>(1024);

    let default_blocker = tokio::spawn(async move {
        let mut blocker = Blocker::<DefaultCommandService>::new(storage, repository, config);
        // let mut blocker = Blocker::<DefaultCommandService>::default();
        blocker.run(rx, shutdown_receiver).await
    });

    (tx, default_blocker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let _: Config =
            toml::from_str(include_str!("testdata/test-config.toml")).expect("Invalid toml format");
    }
}
