use anyhow::Result;
use boring_cache_cli::{cli, config, ui};
use clap::{CommandFactory, Parser};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|panic_info| {
        ui::error(&format!("Fatal error: {panic_info}"));
        ui::error("Please check your system resources and try again.");
        std::process::exit(1);
    }));

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error")),
        )
        .init();

    let mut args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        let mut cmd = cli::Cli::command();
        cmd.print_help().expect("failed to print help");
        println!();
        return Ok(());
    }
    args = cli::preprocess::prepare_args(args);

    let cli = match cli::Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    print!("{e}");
                    std::process::exit(0);
                }
                _ => {
                    ui::error(&e.to_string());
                    std::process::exit(1);
                }
            }
        }
    };

    let require_server_signature =
        cli.require_server_signature || config::env_bool("BORINGCACHE_REQUIRE_SERVER_SIGNATURE");

    let result = cli::dispatch::execute(cli, require_server_signature).await;
    cli::dispatch::handle_result(result)
}
