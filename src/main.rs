use crate::cli::Cli;
use crate::compress::initialize_compression;
use crate::decompress::initialize_decompression;
use crate::list::list_files;
use crate::verify::verify_archive;
use clap::Parser;
use std::error::Error;
use tracing::Level;
mod cli;
mod codec;
mod compress;
mod consts;
mod decompress;
mod errors;
mod filter;
mod format;
mod list;
mod loader;
mod path_safety;
mod reader;
mod verify;
mod writer;

fn main() {
    let cli = Cli::parse();
    let debug = cli.debug
        || matches!(&cli.command, cli::Command::Compress(a) if a.debug)
        || matches!(&cli.command, cli::Command::Decompress(a) if a.debug);
    if debug {
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_writer(std::io::stderr)
            .init();
    }
    let result = match cli.command {
        cli::Command::Compress(args) => initialize_compression(args),
        cli::Command::Decompress(args) => initialize_decompression(args),
        cli::Command::List(args) => list_files(args),
        cli::Command::Verify(args) => verify_archive(args),
    };
    if let Err(e) = result {
        eprintln!("\x1b[1;31merror:\x1b[0m {e}");
        let mut src: Option<&dyn Error> = e.source();
        while let Some(cause) = src {
            eprintln!("  \x1b[2mcaused by:\x1b[0m {cause}");
            src = cause.source();
        }
        std::process::exit(1);
    }
}
