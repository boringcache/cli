use clap::Subcommand;

#[derive(Subcommand)]
pub enum ConfigSubcommand {
    Get {
        key: String,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    Set {
        key: String,
        value: String,
    },

    List {
        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },
}
