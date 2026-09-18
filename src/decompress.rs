use crate::cli::DecompressArgs;
use crate::consts::Limits;
use crate::errors::CryoErrors;
use crate::filter::build_matcher;
use crate::format::FileEntry;
use crate::reader::ArchiveReader;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::{fs::File, path::Path};
use tracing::{Level, event};

pub(crate) fn initialize_decompression(args: DecompressArgs) -> Result<(), CryoErrors> {
    let arv_name = args.archive;
    let output_dir = args.output;

    event!(
        Level::DEBUG,
        archive = %arv_name.display(),
        output = %output_dir.display(),
        "starting decompression"
    );
    let max_m_cost = args.max_m_cost.map(|max_m| (max_m / 1024) as u32);
    let max_header_size: Option<usize> = args.max_header_size.map(|max_h| (max_h / 1024) as usize);
    let filter = build_matcher(&args.filter)?;
    check_decompression_for_arg_err(&arv_name, &output_dir)?;
    let defaults = Limits::default();
    let limits = Limits {
        max_file_size: args.max_file_size.unwrap_or(defaults.max_file_size),
        max_block_size: args.max_block_size.unwrap_or(defaults.max_block_size),
        max_m_cost: max_m_cost.unwrap_or(defaults.max_m_cost),
        max_index_size: args.max_index_size.unwrap_or(defaults.max_index_size),
        max_header_size: max_header_size.unwrap_or(defaults.max_header_size),
    };

    let file = File::open(&arv_name).map_err(|e| CryoErrors::ReadFailed {
        p: arv_name.clone(),
        source: e,
    })?;
    let mut arch = ArchiveReader::new(file, &arv_name, output_dir, limits)?;
    arch.index.files = arch
        .index
        .files
        .into_iter()
        .filter(|f| args.filter.is_empty() || filter.is_match(&f.path))
        .collect::<Vec<FileEntry>>();

    event!(
        Level::DEBUG,
        file_count = arch.index.files.len(),
        block_count = arch.index.block.len(),
        "archive index loaded"
    );

    let show_progress = !tracing::enabled!(Level::DEBUG);
    let mp = MultiProgress::new();

    let pb_files = if show_progress {
        let pb = mp.add(ProgressBar::new(arch.index.files.len() as u64));
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{bar:40.green/dim}] {pos}/{len} files  {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    arch.handle_files(
        if show_progress { Some(&mp) } else { None },
        pb_files.as_ref(),
    )?;

    if let Some(pb) = pb_files {
        pb.finish_with_message("done");
    }

    event!(Level::DEBUG, archive = %arv_name.display(), "decompression finished");
    Ok(())
}

pub(crate) fn check_decompression_for_arg_err(arv: &Path, out: &Path) -> Result<(), CryoErrors> {
    out.parent().ok_or_else(|| {
        CryoErrors::InitializationError(String::from("Parent directory for output doesn't exist"))
    })?;
    if out.exists() && out.is_dir() {
        let out_dir = out.read_dir().map_err(|e| CryoErrors::ReadFailed {
            p: out.to_path_buf(),
            source: e,
        })?;
        if out_dir.count() != 0 {
            return Err(CryoErrors::InitializationError(String::from(
                "Output directory is not empty (empty directory or new path required)",
            )));
        }
    }
    if !arv.exists() {
        return Err(CryoErrors::InitializationError(format!(
            "Archive not found: {}",
            arv.display()
        )));
    }
    if !arv.is_file() {
        return Err(CryoErrors::InitializationError(format!(
            "'{}' exists but is not a file",
            arv.display()
        )));
    }

    Ok(())
}
