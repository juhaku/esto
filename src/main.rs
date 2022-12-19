use std::process;

mod analyzer;
mod app;
mod blocked_ip;
mod blocker;
mod db;

#[tokio::main]
async fn main() {
    if let Err(error) = app::run().await {
        eprintln!("{error}");
        process::exit(1);
    }
}
