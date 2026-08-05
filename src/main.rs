use crate::compression::initialize_compression;
use crate::decompress::initialize_decompression;
use crate::list::list_files;
use crate::verify::verify_archive;
use crate::{errors::CryoErrors, structs::*};
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use std::error::Error;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::Level;
mod compression;
mod consts;
mod decompress;
mod encryption;
mod errors;
mod filter;
mod list;
mod structs;
mod verify;
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(short = 'v', long, default_value_t = false)]
    debug: bool,
}
#[derive(Subcommand)]
enum Command {
    Compress(CompressArgs),
    Decompress(DecompressArgs),
    List(ListArgs),
    Verify(VerifyArgs),
}
#[derive(Args)]
struct CompressArgs {
    archive_name: String,
    #[arg(short = 'P', long = "path", default_value = "./")]
    path_to_compress: PathBuf,
    #[arg(short, long, default_value_t = false)]
    recursive: bool,
    #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(i32).range(-7..=22))]
    compression_level: i32,
    #[arg(short, long,value_enum,default_value_t = EncryptionType::None)]
    encryption_type: EncryptionType,
    #[arg(long="ep",value_enum,default_value_t= ParamsProfile::Balanced)]
    encryption_params: ParamsProfile,
    #[arg(long="bs",default_value = "64KiB",value_parser= parse_size)]
    bs: u64,
    #[arg(long = "debug", short = 'v', default_value_t = false)]
    debug: bool,
}
#[derive(Args)]
struct DecompressArgs {
    archive: PathBuf,
    #[arg(short, long, default_value = "./")]
    output: PathBuf,
    #[arg(long = "debug", short = 'v', default_value_t = false)]
    debug: bool,
    #[arg(long,value_parser = parse_size)]
    max_file_size: Option<u64>,
    #[arg(long,value_parser = parse_size)]
    max_block_size: Option<u64>,
    #[arg(long,value_parser = parse_size)]
    max_m_cost: Option<u64>,
    #[arg(long,value_parser = parse_size)]
    max_index_size: Option<u64>,
    #[arg(long,value_parser = parse_size)]
    max_header_size: Option<u64>,
    filter: Vec<String>,
}
#[derive(Args)]
struct ListArgs {
    archive: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Auto)]
    format: OutputFormat,
}
#[derive(Args)]
struct VerifyArgs {
    archive: PathBuf,
}
#[derive(clap::ValueEnum, Clone, Default)]
pub(crate) enum OutputFormat {
    #[default]
    Auto,
    Human,
    Plain,
    Json,
}

fn main() {
    let cli = Cli::parse();
    let debug = cli.debug
        || matches!(&cli.command, Command::Compress(a) if a.debug)
        || matches!(&cli.command, Command::Decompress(a) if a.debug);
    if debug {
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_writer(std::io::stderr)
            .init();
    }
    let result = match cli.command {
        Command::Compress(args) => initialize_compression(args),
        Command::Decompress(args) => initialize_decompression(args),
        Command::List(args) => list_files(args),
        Command::Verify(args) => verify_archive(args),
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
fn parse_size(size: &str) -> Result<Option<u64>, String> {
    bytesize::ByteSize::from_str(size)
        .map(|b| Some(b.as_u64()))
        .map_err(|e| format!("Invalid size: {e}"))
}
