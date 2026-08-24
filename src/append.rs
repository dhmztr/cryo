use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Seek, SeekFrom},
    path::PathBuf,
    ptr::copy,
    sync::mpsc::{self, Receiver},
    thread,
};

use crate::{
    cli::AppendArgs,
    compress::{read_file_to_bytes, retrieve_all_files, spawn_workers, writer},
    consts::Limits,
    errors::CryoErrors,
    format::Index,
    loader::FileStructs,
    writer::{ArchiveWriter, ProcessedBlock, RawBlock, WriterMessage},
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
            structs.header.compression,
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
    if file_to_append_path.is_dir() {
        let root = &file_to_append_path;
        let mut file_paths: Vec<PathBuf> = vec![];
        retrieve_all_files(root.as_path(), &mut file_paths)?;
        for path in file_paths {
            read_file_to_bytes(
                &path,
                root,
                &mut files,
                &mut stream_pos,
                &mut first_block_len,
                &mut pending_buffer,
                block_size,
                &raw_tx,
            )?;
        }
    } else {
        read_file_to_bytes(
            &file_to_append_path,
            &arch_path,
            &mut files,
            &mut stream_pos,
            &mut first_block_len,
            &mut pending_buffer,
            block_size,
            &raw_tx,
        )?;
    }

    if !pending_buffer.is_empty() {
        let _ = raw_tx.send(RawBlock {
            id: first_block_len,
            raw_data: std::mem::take(&mut pending_buffer),
        });
    }
    drop(raw_tx);
    workers_handle.join().unwrap()?;
    let _ = reader_writer_tx.send(WriterMessage::Finalize {
        files: files,
        total_stream_size: stream_pos,
    });
    writer_handle.join().unwrap()?;
    std::fs::remove_file(&backup_path).map_err(|_| CryoErrors::BackupRemovalFailed(backup_path))?;

    Ok(())
}

fn check_for_tmp(arch_path: &PathBuf) -> Result<PathBuf, CryoErrors> {
    let archive_name = arch_path
        .file_name()
        .ok_or(CryoErrors::InvalidPath)?
        .to_str()
        .ok_or(CryoErrors::InvalidPath)?;
    let archive_backup_path = format!("/tmp/{archive_name}");
    let backup_path = PathBuf::from(archive_backup_path);
    if backup_path.is_file() {
        std::fs::copy(&backup_path, arch_path).map_err(|_| CryoErrors::WriteError)?;
        Ok(backup_path)
    } else {
        std::fs::copy(arch_path, &backup_path).map_err(|_| CryoErrors::WriteError)?;
        Ok(backup_path)
    }
}
