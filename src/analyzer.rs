use std::process::Stdio;

use regex::Regex;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::sync::{broadcast, OnceCell};

use crate::app::{self, EstoError};

static IP_REGEX: OnceCell<Regex> = OnceCell::const_new();

pub struct Analyser {
    command: String,
    contains: Vec<String>,
}

impl Analyser {
    const IP_REGEX_FORMAT: &str = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}";

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
                                } else {
                                    break Err(EstoError::AnalyzeCommand(status.code()));
                                }
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
            let is_match = self.contains.iter().all(|regex| line.contains(regex));

            if is_match {
                log::debug!(
                    "input line: {line}, matched with conditions: {:?}",
                    &self.contains
                );
                blocker
                    .send(Self::parse_ip(line).await)
                    .await
                    .map_err(EstoError::SendBlocker)?;
            }
        }

        Ok(())
    }

    async fn parse_ip(value: String) -> String {
        let ip_regex = IP_REGEX
            .get_or_init(|| async { Regex::new(Analyser::IP_REGEX_FORMAT).unwrap() })
            .await;

        let mut captures_iter = ip_regex.captures_iter(&value);

        captures_iter
            .next()
            .and_then(|capture| capture.get(0).map(|match_group| match_group.as_str()))
            .map(ToString::to_string)
            .unwrap_or_else(String::new)
    }
}

impl From<app::Command> for Analyser {
    fn from(command: app::Command) -> Self {
        Self {
            command: command.command,
            contains: command.contains,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use tokio::sync::mpsc;

    use super::*;

    #[test]
    fn find_ip_from_logline() {
        let line = "Dec 13 23:14:45 namelesspi sshd[7821]: Failed password for root from 61.177.173.16 port 52304 ssh2";
        let ip_regex = Regex::new(Analyser::IP_REGEX_FORMAT).unwrap();

        let actual = ip_regex
            .captures_iter(line)
            .next()
            .and_then(|capture| capture.get(0).map(|m| m.as_str()))
            .unwrap_or("");
        assert_eq!("61.177.173.16", actual, "invalid ip format");
    }

    #[tokio::test]
    async fn analyze_auth_log() {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder().is_test(true).try_init();
        let (tx, mut rx) = mpsc::channel::<String>(100);
        let (btx, brx) = broadcast::channel::<()>(1);
        let analyzer = Analyser::from(app::Command {
            command: "tail -n 50 ./src/testdata/authlog.out".to_string(),
            contains: vec!["Failed password for".to_string()],
        });

        tokio::spawn(async move { analyzer.run(tx, brx).await });

        let mut ips: Vec<String> = vec![];
        while let Some(ip) = rx.recv().await {
            ips.push(ip);
        }
        let regex = OnceCell::new_with(Some(Regex::new(Analyser::IP_REGEX_FORMAT).unwrap()));

        assert!(
            ips.iter().all(|ip| regex.get().unwrap().is_match(ip)),
            "expected all IPs to match ip rules"
        );
        assert_eq!(ips.len(), 21, "unexpected amount of IP addresses");
        if btx.send(()).is_err() {};
    }
}
