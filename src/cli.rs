use crate::format::{EncryptionType, ParamsProfile};
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
    #[arg(short = 'v', long, default_value_t = false)]
    pub(crate) debug: bool,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Compress(CompressArgs),
    Decompress(DecompressArgs),
    List(ListArgs),
    Verify(VerifyArgs),
}

#[derive(Args)]
pub(crate) struct CompressArgs {
    pub(crate) archive_name: String,
    #[arg(short = 'P', long = "path", default_value = "./")]
    pub(crate) path_to_compress: PathBuf,
    #[arg(short, long, default_value_t = false)]
    pub(crate) recursive: bool,
    #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(i32).range(-7..=22))]
    pub(crate) compression_level: i32,
    #[arg(short, long,value_enum,default_value_t = EncryptionType::None)]
    pub(crate) encryption_type: EncryptionType,
    #[arg(long="ep",value_enum,default_value_t= ParamsProfile::Balanced)]
    pub(crate) encryption_params: ParamsProfile,
    #[arg(long="bs",default_value = "512KiB",value_parser= parse_size)]
    pub(crate) bs: u64,
    #[arg(long = "debug", short = 'v', default_value_t = false)]
    pub(crate) debug: bool,
}

#[derive(Args)]
pub(crate) struct DecompressArgs {
    pub(crate) archive: PathBuf,
    #[arg(short, long, default_value = "./")]
    pub(crate) output: PathBuf,
    #[arg(long = "debug", short = 'v', default_value_t = false)]
    pub(crate) debug: bool,
    #[arg(long,value_parser = parse_size)]
    pub(crate) max_file_size: Option<u64>,
    #[arg(long,value_parser = parse_size)]
    pub(crate) max_block_size: Option<u64>,
    #[arg(long,value_parser = parse_size)]
    pub(crate) max_m_cost: Option<u64>,
    #[arg(long,value_parser = parse_size)]
    pub(crate) max_index_size: Option<u64>,
    #[arg(long,value_parser = parse_size)]
    pub(crate) max_header_size: Option<u64>,
    pub(crate) filter: Vec<String>,
}

#[derive(Args)]
pub(crate) struct ListArgs {
    pub(crate) archive: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Auto)]
    pub(crate) format: OutputFormat,
}

#[derive(Args)]
pub(crate) struct VerifyArgs {
    pub(crate) archive: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Default)]
pub(crate) enum OutputFormat {
    #[default]
    Auto,
    Human,
    Plain,
    Json,
}

pub(crate) fn parse_size(size: &str) -> Result<u64, String> {
    bytesize::ByteSize::from_str(size)
        .map(|b| b.as_u64())
        .map_err(|e| format!("Invalid size: {e}"))
}
