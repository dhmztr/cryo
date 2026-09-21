use std::{
    collections::HashSet,
    fs,
    io::{BufWriter, Seek, SeekFrom},
    path::PathBuf,
    sync::mpsc,
    thread,
    time::Duration,
};

use indicatif::{ProgressBar, ProgressStyle};
use tracing::{Level, event};

use crate::{
    cli::AppendArgs,
    compress::{read_file_to_bytes, retrieve_all_files, spawn_workers, writer},
    consts::Limits,
    errors::CryoErrors,
    loader::FileStructs,
    writer::{ArchiveWriter, RawBlock, WriterMessage},
};

pub fn append_file(args: AppendArgs) -> Result<(), CryoErrors> {
    let (arch_path, file_to_append_path) = (args.archive_path, args.file_to_append);
    let backup_path = check_for_tmp(&arch_path)?;
    let mut archive_file = fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(&arch_path)
        .map_err(|e| CryoErrors::ReadFailed {
            p: arch_path.clone(),
            source: e,
        })?;

    let structs = FileStructs::retrieve(&archive_file, &arch_path, &Limits::default())?;
    let offset = structs.footer.index_offset;

    archive_file
        .seek(SeekFrom::Start(offset))
        .map_err(|e| CryoErrors::ReadFailed {
            p: arch_path.clone(),
            source: e,
        })?;
    let bufwriter = BufWriter::new(archive_file);
    let mut stream_pos = structs.index.total_stream_size;
    let file_pos = structs.footer.index_offset;
    let mut files = structs.index.files.clone();
    let mut first_block_len = structs.index.block.len() as u64;
    let mut pending_buffer = Vec::new();
    let block_size = structs.header.block_size as usize;

    let (raw_tx, raw_rx) = mpsc::channel::<RawBlock>();
    let (reader_writer_tx, reader_writer_rx) = mpsc::channel::<WriterMessage>();

    let workers_tx = reader_writer_tx.clone();
    let workers_handle = thread::spawn(move || {
        spawn_workers(
            raw_rx,
            workers_tx,
            structs.cipher,
            structs.header.nonce_base,
            structs.header.archive_id,
            &structs.header.compression,
            structs.header.compression_level,
        )
    });
    let mut archive = ArchiveWriter {
        writer: bufwriter,
        index: structs.index,
        stream_position: stream_pos,
        file_position: file_pos,
        pending: vec![],
        cipher: structs.cipher,
        header: structs.header,
    };

    let writer_handle = thread::spawn(move || writer(reader_writer_rx, &mut archive));

    let mut seen: HashSet<PathBuf> = files.iter().map(|f| f.path.clone()).collect();

    let show_progress = !tracing::enabled!(Level::DEBUG);
    let pb_style = ProgressStyle::with_template(
        "  [{bar:40.blue/dim}] {percent:>3}%  {bytes}/{total_bytes}  {msg}",
    )
    .unwrap()
    .progress_chars("=>-");

    if file_to_append_path.is_dir() {
        let root = &file_to_append_path;
        let mut file_paths: Vec<PathBuf> = vec![];
        retrieve_all_files(root.as_path(), &mut file_paths)?;
        file_paths.retain(|path| match path.strip_prefix(root) {
            Ok(stripped) if !seen.insert(stripped.to_path_buf()) => {
                event!(
                    Level::INFO,
                    path = %stripped.display(),
                    "skipping duplicate entry already present in archive"
                );
                false
            }
            _ => true,
        });
        let total: u64 = file_paths
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum();
        let pb = new_byte_bar(show_progress, total, &pb_style);
        for path in file_paths {
            if let Some(pb) = &pb {
                pb.set_message(
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                );
            }
            read_file_to_bytes(
                &path,
                root,
                &mut files,
                &mut stream_pos,
                &mut first_block_len,
                &mut pending_buffer,
                block_size,
                &raw_tx,
                pb.as_ref(),
            )?;
        }
        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
    } else {
        let total = fs::metadata(&file_to_append_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let pb = new_byte_bar(show_progress, total, &pb_style);
        if let Some(pb) = &pb {
            pb.set_message(
                file_to_append_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            );
        }
        let root = file_to_append_path.parent().unwrap_or(&file_to_append_path);
        if let Ok(stripped) = file_to_append_path.strip_prefix(root)
            && !seen.insert(stripped.to_path_buf())
        {
            event!(
                Level::INFO,
                path = %stripped.display(),
                "skipping duplicate entry already present in archive"
            );
        } else {
            read_file_to_bytes(
                &file_to_append_path,
                root,
                &mut files,
                &mut stream_pos,
                &mut first_block_len,
                &mut pending_buffer,
                block_size,
                &raw_tx,
                pb.as_ref(),
            )?;
        }
        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
    }

    if !pending_buffer.is_empty() {
        let _ = raw_tx.send(RawBlock {
            id: first_block_len,
            raw_data: std::mem::take(&mut pending_buffer),
        });
    }
    drop(raw_tx);
    workers_handle
        .join()
        .map_err(|_| CryoErrors::ThreadError)??;
    let _ = reader_writer_tx.send(WriterMessage::Finalize {
        files,
        total_stream_size: stream_pos,
    });
    writer_handle
        .join()
        .map_err(|_| CryoErrors::ThreadError)??;
    std::fs::remove_file(&backup_path).map_err(|_| CryoErrors::BackupRemovalFailed(backup_path))?;

    Ok(())
}

fn new_byte_bar(show: bool, total: u64, style: &ProgressStyle) -> Option<ProgressBar> {
    if !show {
        return None;
    }
    let pb = ProgressBar::new(total);
    pb.set_style(style.clone());
    pb.enable_steady_tick(Duration::from_millis(100));
    Some(pb)
}

fn check_for_tmp(arch_path: &PathBuf) -> Result<PathBuf, CryoErrors> {
    let mut archive_name = arch_path
        .file_name()
        .ok_or(CryoErrors::InvalidPath)?
        .to_str()
        .ok_or(CryoErrors::InvalidPath)?
        .to_owned();
    let parent_path = arch_path.parent().ok_or(CryoErrors::InvalidPath)?;
    archive_name += ".bak";
    let backup_path = parent_path.join(PathBuf::from(archive_name));
    if backup_path.is_file() {
        std::fs::copy(&backup_path, arch_path).map_err(|_| CryoErrors::WriteError)?;
        Ok(backup_path)
    } else {
        std::fs::copy(arch_path, &backup_path).map_err(|_| CryoErrors::WriteError)?;
        Ok(backup_path)
    }
}
