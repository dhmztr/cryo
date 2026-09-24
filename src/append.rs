use std::{
    collections::HashSet,
    fs,
    io::{BufWriter, Seek, SeekFrom},
    path::{Path, PathBuf},
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
    let tmp_path = create_tmp_file(&arch_path)?;
    fs::copy(&arch_path, &tmp_path).map_err(|_| CryoErrors::WriteError)?;
    let result = (|| -> Result<(), CryoErrors> {
        let mut tmp_file = fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(&tmp_path)
            .map_err(|e| CryoErrors::ReadFailed {
                p: tmp_path.clone(),
                source: e,
            })?;
        let archive_file = fs::OpenOptions::new()
            .read(true)
            .open(&arch_path)
            .map_err(|e| CryoErrors::ReadFailed {
                p: arch_path.clone(),
                source: e,
            })?;

        let structs =
            FileStructs::retrieve(&archive_file, &arch_path, &Limits::default(), args.confirm)?;
        let offset = structs.footer.index_offset;

        tmp_file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| CryoErrors::ReadFailed {
                p: arch_path.clone(),
                source: e,
            })?;
        let bufwriter = BufWriter::new(tmp_file);
        let mut stream_pos = structs.index.total_stream_size;
        let file_pos = structs.footer.index_offset;
        let mut files = structs.index.files.clone();
        let mut first_block_len = structs.index.block.len() as u64;
        let mut pending_buffer = Vec::new();
        let block_size = structs.header.block_size as usize;

        let (raw_tx, raw_rx) = mpsc::channel::<RawBlock>();
        let (reader_writer_tx, reader_writer_rx) = mpsc::channel::<WriterMessage>();

        let workers_tx = reader_writer_tx.clone();
        let worker_cipher = structs.cipher.clone();
        let worker_archive_id = structs.header.archive_id;
        let worker_compression = structs.header.compression;
        let worker_level = structs.header.compression_level;
        let workers_handle = thread::spawn(move || {
            spawn_workers(
                raw_rx,
                workers_tx,
                &worker_cipher,
                worker_archive_id,
                &worker_compression,
                worker_level,
            )
        });
        let mut archive = ArchiveWriter {
            writer: bufwriter,
            index: structs.index,
            stream_position: stream_pos,
            file_position: file_pos,
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
        fs::rename(&tmp_path, &arch_path).map_err(|_| CryoErrors::WriteError)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
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

fn create_tmp_file(p: &Path) -> Result<PathBuf, CryoErrors> {
    let name = p.file_name().ok_or(CryoErrors::InvalidPath)?;
    let name = name.to_str().ok_or(CryoErrors::InvalidPath)?;
    let namesplit = name
        .rsplit("cryo")
        .last()
        .ok_or(CryoErrors::InvalidPath)?
        .to_owned();

    let new_name = namesplit + "tmp";
    let mut new_path = p.to_path_buf();
    new_path.set_file_name(new_name);
    Ok(new_path)
}
