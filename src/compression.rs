use crate::{
    CompressArgs, FileType, Header, Path, PathBuf,
    errors::CryoErrors,
    structs::{ArchiveWriter, FileEntry},
};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::{
    fs::{self, File, read_dir},
    io::Read,
    os::unix::fs::MetadataExt,
};
use tracing::{Level, event};

pub(crate) fn initialize_compression(args: CompressArgs) -> Result<(), CryoErrors> {
    let (arv_name, path, com_level, enc_type, recursive, eparams, bs) = (
        args.archive_name,
        args.path_to_compress,
        args.compression_level,
        args.encryption_type,
        args.recursive,
        args.encryption_params,
        args.bs,
    );

    event!(
        Level::DEBUG,
        archive = %arv_name,
        path = %path.display(),
        compression_level = com_level,
        encryption = ?enc_type,
        block_size = bs,
        recursive,
        "starting compression"
    );

    check_compression_for_arg_err(&arv_name, path.as_path(), com_level, recursive)?;

    let mut files_to_compress: Vec<PathBuf> = vec![];
    if recursive {
        retrieve_all_files(&path, &mut files_to_compress)?;
    } else {
        files_to_compress.push(path.to_path_buf());
    }

    event!(
        Level::DEBUG,
        count = files_to_compress.len(),
        "Files queued for compression"
    );

    let show_progress = !tracing::enabled!(Level::DEBUG);

    let mp = MultiProgress::new();

    let pb_files = if show_progress {
        let pb = mp.add(ProgressBar::new(files_to_compress.len() as u64));
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{bar:40.green/dim}] {pos}/{len} files  {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        Some(pb)
    } else {
        None
    };

    let pb_file_style = ProgressStyle::with_template(
        "  [{bar:40.blue/dim}] {percent:>3}%  {bytes}/{total_bytes}  {msg}",
    )
    .unwrap()
    .progress_chars("=>-");

    let h = Header::new(eparams, com_level, bs, enc_type);
    let mut archive = ArchiveWriter::new(&arv_name, h.clone())?;

    for file in &files_to_compress {
        let name = file
            .file_name()
            .unwrap_or(file.as_os_str())
            .to_string_lossy()
            .into_owned();
        if let Some(pb) = &pb_files {
            pb.set_message(name.clone());
        }
        event!(Level::DEBUG, path = %file.display(), "compressing entry");

        let pb_bytes = if show_progress {
            let file_size = fs::metadata(file).map(|m| m.len()).unwrap_or(0);
            if file_size > 0 {
                let pb = mp.insert_after(pb_files.as_ref().unwrap(), ProgressBar::new(file_size));
                pb.set_style(pb_file_style.clone());
                pb.set_message(name);
                Some(pb)
            } else {
                None
            }
        } else {
            None
        };

        read_file_to_bytes(&mut archive, file.as_path(), pb_bytes.as_ref(), &path)?;

        if let Some(pb) = pb_bytes {
            pb.finish_and_clear();
        }
        if let Some(pb) = &pb_files {
            pb.inc(1);
        }
    }

    archive.finish().map_err(|_| CryoErrors::WriteError)?;
    if let Some(pb) = pb_files {
        pb.finish_with_message("done");
    }
    event!(Level::DEBUG, archive = %arv_name, "compression finished");
    Ok(())
}

pub fn read_file_to_bytes(
    arch: &mut ArchiveWriter,
    p: &Path,
    pb: Option<&ProgressBar>,
    root: &Path,
) -> Result<(), CryoErrors> {
    let fmetadata = fs::symlink_metadata(p).map_err(|e| CryoErrors::ReadFailed {
        p: p.to_path_buf(),
        source: e,
    })?;
    let ftype = if fmetadata.is_symlink() {
        FileType::Symlink
    } else if fmetadata.is_dir() {
        FileType::Dir
    } else {
        FileType::File
    };

    event!(Level::DEBUG, path = %p.display(), ftype = ?ftype, size = fmetadata.size(), "reading entry");
    match ftype {
        FileType::Symlink => {
            let target = std::fs::read_link(p).map_err(|e| CryoErrors::ReadFailed {
                p: p.to_path_buf(),
                source: e,
            })?;
            event!(Level::DEBUG, path = %p.display(), target = %target.display(), "symlink entry");
            let entry = FileEntry {
                path: p
                    .strip_prefix(&root)
                    .map_err(|_| CryoErrors::InvalidPath)?
                    .to_path_buf(),
                ftype,
                stream_offset: arch.stream_position,
                size: 0,
                symlink_target: Some(target),
                timestamp: fmetadata.mtime() as u64,
                permissions: fmetadata.mode(),
            };
            arch.index.files.push(entry);
            return Ok(());
        }
        FileType::Dir => {
            event!(Level::DEBUG, path = %p.display(), "directory entry");
            let entry = FileEntry {
                path: p
                    .strip_prefix(&root)
                    .map_err(|_| CryoErrors::InvalidPath)?
                    .to_path_buf(),
                ftype,
                stream_offset: arch.stream_position,
                size: 0,
                symlink_target: None,
                timestamp: fmetadata.mtime() as u64,
                permissions: fmetadata.mode(),
            };
            arch.index.files.push(entry);
            return Ok(());
        }
        FileType::File => {
            let entry = FileEntry {
                path: p
                    .strip_prefix(&root)
                    .map_err(|_| CryoErrors::InvalidPath)?
                    .to_path_buf(),
                ftype,
                stream_offset: arch.stream_position,
                size: fmetadata.size(),
                symlink_target: None,
                timestamp: fmetadata.mtime() as u64,
                permissions: fmetadata.mode(),
            };
            arch.index.files.push(entry);

            let mut file = File::open(p).map_err(|e| CryoErrors::ReadFailed {
                p: p.to_path_buf(),
                source: e,
            })?;

            let chunk_size = arch.header.block_size as usize;
            let mut chunk = vec![0u8; chunk_size];
            loop {
                let n = file
                    .read(&mut chunk)
                    .map_err(|e| CryoErrors::ReadFailed {
                        p: p.to_path_buf(),
                        source: e,
                    })?;
                if n == 0 {
                    break;
                }
                if let Some(pb) = pb {
                    pb.inc(n as u64);
                }
                arch.feed(&chunk[..n])?
            }
        }
    }

    Ok(())
}

fn retrieve_all_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), CryoErrors> {
    event!(Level::DEBUG, root = %root.display(), "scanning directory recursively");
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        event!(Level::DEBUG, dir = %dir.display(), "scanning dir");
        let mut names: Vec<_> = read_dir(&dir)
            .map_err(|e| CryoErrors::RecursiveLookupFailed {
                p: dir.clone(),
                source: e,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CryoErrors::RecursiveLookupFailed {
                p: dir.clone(),
                source: e,
            })?;
        names.sort_by_key(|e| e.file_name());

        for entry in names {
            let path = entry.path();
            let ft = entry
                .file_type()
                .map_err(|e| CryoErrors::RecursiveLookupFailed {
                    p: dir.clone(),
                    source: e,
                })?;
            if ft.is_dir() {
                event!(Level::DEBUG, path = %path.display(), "found dir");
                out.push(path.clone());
                stack.push(path);
            } else if ft.is_file() {
                event!(Level::DEBUG, path = %path.display(), "found file");
                out.push(path);
            } else if ft.is_symlink() {
                event!(Level::DEBUG, path = %path.display(), "found symlink");
                out.push(path);
            }
        }
    }
    Ok(())
}

fn check_compression_for_arg_err(s: &String, p: &Path, c: i32, r: bool) -> Result<(), CryoErrors> {
    if s.as_str() == "" {
        Err(CryoErrors::EmptyArchiveName)
    } else if !p.exists() || (!p.is_dir() && r) {
        Err(CryoErrors::InvalidPath)
    } else if c > 22 {
        Err(CryoErrors::InvalidCompressionLevel)
    } else {
        Ok(())
    }
}
