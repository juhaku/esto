use std::process::Stdio;

use async_trait::async_trait;
use regex::Regex;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::sync::{broadcast, OnceCell};

use crate::app::{self, EstoError, Matcher};

pub struct Analyser {
    command: String,
    contains: Vec<String>,
    matcher: Box<dyn IpMatcher>,
}

impl Analyser {
    pub(crate) async fn run(
        &self,
        blocker: Sender<String>,
        shutdown_receiver: broadcast::Receiver<()>,
    ) -> Result<(), EstoError> {
        log::info!(
            "Staring up esto Analyzer for: {command}",
            command = &self.command
        );
        log::debug!("Match conditions: {contains:#?}", contains = self.contains);
        if let Some((cmd, tail)) = self.command.split_once(' ') {
            let mut cmd = Command::new(cmd)
                .args(&tail.split(' ').collect::<Vec<_>>())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(EstoError::Io)?;
            let stdout = cmd.stdout.take().unwrap();
            let stderr = cmd.stderr.take().unwrap();

            let (_, _) = tokio::join!(
                self.listen_out(stdout, blocker.clone()),
                self.listen_out(stderr, blocker)
            );

            let handle = tokio::spawn(async move { cmd.wait().await });

            tokio::pin!(handle);
            tokio::pin!(shutdown_receiver);
            loop {
                tokio::select! {
                    result = &mut handle => {
                        match result? {
                            Ok(status) => {
                                log::debug!(
                                    "Command '{command}' exited with status: {status}",
                                    command = &self.command
                                );
                                if status.success() {
                                    break Ok(())
                                }
                                break Err(EstoError::AnalyzeCommand(status.code()));
                            }
                            Err(error) => break Err(EstoError::AnalyzerHandleAwait(error))
                        }
                    }
                    _ = shutdown_receiver.recv() => {
                        log::info!("Received close signal, aborting Analyzer handle");
                        handle.abort();
                    }
                    else => {
                        break Ok(())
                    }
                }
            }
        } else {
            Err(EstoError::InvalidAnalyzerCommand(self.command.clone()))
        }
    }

    async fn listen_out<T>(&self, out: T, blocker: Sender<String>) -> Result<(), EstoError>
    where
        T: AsyncRead + Unpin,
    {
        let mut lines = BufReader::new(out).lines();
        while let Some(line) = lines.next_line().await? {
            if self.contains.iter().all(|contains| line.contains(contains))
                && self.matcher.matches(&line).await
            {
                log::debug!(
                    "input line: {line}, matched with conditions: {:?}",
                    &self.contains
                );
                blocker
                    .send(self.parse_ip(line).await)
                    .await
                    .map_err(EstoError::SendBlocker)?;
            }
        }

        Ok(())
    }

    async fn parse_ip(&self, value: String) -> String {
        self.matcher.get_ip(&value).await
    }
}

impl From<app::Command> for Analyser {
    fn from(command: app::Command) -> Self {
        Self {
            command: command.command,
            contains: command.contains,
            matcher: if command.matcher == Matcher::AuthLog {
                Box::new(AuthIpMatcher)
            } else {
                Box::new(KernelLogIpMatcher)
            },
        }
    }
}

macro_rules! regex {
    ( $ident:ident for $format:expr ) => {
        $ident
            .get_or_init(|| async { Regex::new($format).expect("Invalid regex format") })
            .await
    };
}

#[async_trait]
pub trait IpMatcher: Send + Sync {
    async fn matches(&self, line: &str) -> bool;
    async fn get_ip(&self, line: &str) -> String;
}

static AUTH_IP: OnceCell<Regex> = OnceCell::const_new();

struct AuthIpMatcher;

impl AuthIpMatcher {
    const IP_REGEX_FORMAT: &'static str  = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}";
}

#[async_trait]
impl IpMatcher for AuthIpMatcher {
    async fn matches(&self, line: &str) -> bool {
        let regex = regex!(AUTH_IP for AuthIpMatcher::IP_REGEX_FORMAT);
        regex.is_match(line)
    }

    async fn get_ip(&self, line: &str) -> String {
        let regex = regex!(AUTH_IP for AuthIpMatcher::IP_REGEX_FORMAT);

        let matched_ip = regex
            .captures_iter(line)
            .next()
            .and_then(|capture| capture.get(0).map(|match_group| match_group.as_str()))
            .map(ToString::to_string)
            .map(|ip| ip.replace("SRC=", ""))
            .unwrap_or_else(String::new);

        matched_ip
    }
}

static KERNEL_IP: OnceCell<Regex> = OnceCell::const_new();

struct KernelLogIpMatcher;

impl KernelLogIpMatcher {
    const IP_REGEX_FORMAT: &'static str = r"SRC=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}";
}

#[async_trait]
impl IpMatcher for KernelLogIpMatcher {
    async fn matches(&self, line: &str) -> bool {
        let regex = regex!(KERNEL_IP for KernelLogIpMatcher::IP_REGEX_FORMAT);

        regex.is_match(line)
    }

    async fn get_ip(&self, line: &str) -> String {
        let regex = regex!(KERNEL_IP for KernelLogIpMatcher::IP_REGEX_FORMAT);

        let matched_ip = regex
            .captures_iter(line)
            .next()
            .and_then(|capture| capture.get(0).map(|match_group| match_group.as_str()))
            .map(ToString::to_string)
            .map(|ip| ip.replace("SRC=", ""))
            .unwrap_or_else(String::new);

        matched_ip
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn analyze_auth_log() {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder().is_test(true).try_init();
        let (tx, mut rx) = mpsc::channel::<String>(100);
        let (btx, brx) = broadcast::channel::<()>(1);
        let analyzer = Analyser::from(app::Command {
            command: "tail -n 50 ./src/testdata/authlog.out".to_string(),
            contains: vec!["Failed password for".to_string()],
            matcher: app::Matcher::AuthLog,
        });

        tokio::spawn(async move { analyzer.run(tx, brx).await });

        let mut ips: Vec<String> = vec![];
        while let Some(ip) = rx.recv().await {
            log::debug!("got {ip}");
            ips.push(ip);
        }
        let regex = OnceCell::new_with(Some(Regex::new(AuthIpMatcher::IP_REGEX_FORMAT).unwrap()));

        assert!(
            ips.iter().all(|ip| regex.get().unwrap().is_match(ip)),
            "expected all IPs to match ip rules"
        );
        assert_eq!(ips.len(), 21, "unexpected amount of IP addresses");
        if btx.send(()).is_err() {};
    }

    #[tokio::test]
    async fn find_ip_from_auth_log_line() {
        let line = "Dec 13 23:14:45 namelesspi sshd[7821]: Failed password for root from 61.177.173.16 port 52304 ssh2";
        let matcher = AuthIpMatcher;

        assert!(matcher.matches(line).await, "Expected to find IP from line");

        assert_eq!(
            matcher.get_ip(line).await,
            "61.177.173.16",
            "Did not find correct IP"
        );
    }

    #[tokio::test]
    async fn find_ip_from_kernel_log_line() {
        let line = "Apr 24 19:37:07 namelesspi kernel: [9452026.615270] HTTPS: IN=eth0 OUT=br-9fbcc63c574f MAC=b8:27:eb:05:5f:41:98:0d:67:27:99:38:08:00:45:00:00:3c:94:3e:40:00 SRC=1.1.2.89 DST=172.18.0.3 LEN=60 TOS=0x00 PREC=0x00 TTL=62 ID=37950 DF PROTO=TCP SPT=55742 DPT=8080 WINDOW=64240 RES=0x00 SYN URGP=0";
        let matcher = KernelLogIpMatcher;

        assert!(
            matcher.matches(line).await,
            "Expected to find SRC IP from line"
        );

        assert_eq!(
            matcher.get_ip(line).await,
            "1.1.2.89",
            "Did not find correct SRC IP"
        );
    }
}
