use std::{fs::File, path::PathBuf, str::FromStr};

use crate::cli::VerifyArgs;
use crate::consts::Limits;
use crate::errors::CryoErrors;
use crate::list::check_read_only_args_for_errors;
use crate::reader::ArchiveReader;

pub(crate) fn verify_archive(args: VerifyArgs) -> Result<(), CryoErrors> {
    check_read_only_args_for_errors(&args.archive)?;
    let file = File::open(&args.archive).map_err(|e| CryoErrors::ReadFailed {
        p: args.archive.clone(),
        source: e,
    })?;
    let out = PathBuf::from_str("./")
        .map_err(|_| CryoErrors::InitializationError("Failed to fetch current dir".to_string()))?;
    let mut arch = ArchiveReader::new(file, &args.archive, out, Limits::default())?;
    arch.verify(&args.archive)?;
    println!("Succesfuly verified the archive!");

    Ok(())
}
