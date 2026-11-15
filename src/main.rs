use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use log::LevelFilter;
use mio_rs::config::Config;
use mio_rs::crypto::generate_key_pair;
use mio_rs::{client, server, tls};
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode, WriteLogger};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[derive(Debug, Parser)]
#[command(
    name = "mio",
    version,
    about = "Rust implementation of the mio proxy protocol"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the SOCKS5 client or the camouflage server.
    Run {
        /// Path to the TOML configuration file.
        #[arg(short = 'c', long = "config")]
        config: PathBuf,
    },
    /// Print version and protocol information.
    Version,
    /// Generate a mio server X25519 key pair.
    Keygen,
    /// Capture a Chrome-compatible ClientHello and print its JA3/JA4 fingerprints.
    Fingerprint {
        /// TCP endpoint that receives the ClientHello.
        #[arg(long)]
        server: String,
        /// SNI / verification name used in the ClientHello.
        #[arg(long)]
        dest: String,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help().context("print help")?;
        println!();
        return Ok(());
    };
    match command {
        Command::Run { config } => run_service(config),
        Command::Version => {
            println!(
                "mio-rs {} (mio protocol {})",
                env!("CARGO_PKG_VERSION"),
                mio_rs::crypto::PROTOCOL_VERSION
            );
            println!(
                "TLS ClientHello profile: {} {}",
                tls::CHROME_PROFILE.name,
                tls::CHROME_PROFILE.browser_version
            );
            Ok(())
        }
        Command::Keygen => {
            let (private_key, public_key) = generate_key_pair();
            println!("PrivateKey: {private_key}");
            println!("PublicKey: {public_key}");
            Ok(())
        }
        Command::Fingerprint { server, dest } => {
            let summary = tls::probe_client_hello(&server, &dest)?;
            println!(
                "profile={} {}",
                tls::CHROME_PROFILE.name,
                tls::CHROME_PROFILE.browser_version
            );
            println!("ja4={}", summary.ja4);
            println!("ja3={}", summary.ja3);
            println!("ja3_md5={}", summary.ja3_md5);
            println!("canonical_ja3={}", summary.canonical_ja3);
            println!("canonical_ja3_md5={}", summary.canonical_ja3_md5);
            println!(
                "chrome_133_match={}",
                summary.canonical_ja3_md5 == tls::CHROME_133_CANONICAL_JA3_MD5
                    && summary.ja4 == tls::CHROME_133_JA4
            );
            println!(
                "cipher_suites={}",
                summary
                    .cipher_suites
                    .iter()
                    .map(|value| format!("{value:04x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!(
                "groups={}",
                summary
                    .groups
                    .iter()
                    .map(|value| format!("{value:04x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!(
                "sigalgs={}",
                summary
                    .sigalgs
                    .iter()
                    .map(|value| format!("{value:04x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!(
                "extensions={}",
                summary
                    .extensions
                    .iter()
                    .map(|value| format!("{value:04x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            Ok(())
        }
    }
}

fn run_service(path: PathBuf) -> Result<()> {
    let config = Config::load(&path)?;
    setup_logging(&config)?;
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = stop.clone();
    ctrlc::set_handler(move || signal_stop.store(true, std::sync::atomic::Ordering::Relaxed))
        .context("install signal handler")?;

    match (config.has_server(), config.has_client()) {
        (true, true) => {
            let server_stop = stop.clone();
            let inbound = config.inbounds;
            std::thread::spawn(move || {
                if let Err(error) = server::run(inbound, server_stop) {
                    log::error!("server stopped: {error:#}");
                }
            });
            client::run(config.outbounds, stop)
        }
        (true, false) => server::run(config.inbounds, stop),
        (false, true) => client::run(config.outbounds, stop),
        (false, false) => unreachable!("validated configuration has at least one service"),
    }
}

fn setup_logging(config: &Config) -> Result<()> {
    let level = match config.log.level.to_ascii_lowercase().as_str() {
        "off" => LevelFilter::Off,
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        other => bail!("invalid log level {other:?}"),
    };
    if !config.log.enable || level == LevelFilter::Off {
        log::set_max_level(LevelFilter::Off);
        return Ok(());
    }

    let mut builder = ConfigBuilder::new();
    if config.log.timestamp {
        builder.set_time_format_rfc3339();
    } else {
        builder.set_time_level(LevelFilter::Off);
    }
    let log_config = builder.build();
    if !config.log.output.is_empty() {
        let path = &config.log.output;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open log file {path}"))?;
        WriteLogger::init(level, log_config, file).context("initialize file logger")?;
    } else {
        TermLogger::init(level, log_config, TerminalMode::Stderr, ColorChoice::Auto)
            .context("initialize terminal logger")?;
    }
    Ok(())
}
