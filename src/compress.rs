use crate::cli::CompressArgs;
use crate::codec::{Cipher, encrypt_block};
use crate::engine::{CompressingEngine, Compressor};
use crate::errors::CryoErrors;
use crate::format::{BlockEntry, EncryptedData, FileEntry, FileType, Header};
use crate::writer::{ArchiveWriter, RawBlock, archive_filename};
use crate::writer::{ProcessedBlock, WriterMessage};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand_core::{OsRng, RngCore};
use rayon::iter::{ParallelBridge, ParallelIterator};
use std::collections::BTreeMap;
use std::fs::Metadata;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::{
    fs::{self, File, read_dir},
    io::Read,
    os::unix::fs::MetadataExt,
};
use tracing::{Level, event};

pub(crate) fn initialize_compression(args: CompressArgs) -> Result<(), CryoErrors> {
    let (arv_name, path, compression, com_level, enc_type, recursive, eparams, bs) = (
        args.archive_name,
        args.path_to_compress,
        args.compression,
        args.compression_level,
        args.encryption_type,
        args.recursive,
        args.encryption_params,
        args.bs,
    );
    let (raw_tx, raw_rx) = mpsc::channel::<RawBlock>();
    let (reader_writer_tx, reader_writer_rx) = mpsc::channel::<WriterMessage>();

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

    check_compression_for_arg_err(&arv_name, path.as_path(), recursive)?;
    CompressingEngine::new(&compression, com_level)?;

    let mut files_to_compress: Vec<PathBuf> = vec![];
    let root = if recursive {
        retrieve_all_files(&path, &mut files_to_compress)?;
        path
    } else {
        if path.is_dir() {
            return Err(CryoErrors::DirNotRecursive);
        }
        files_to_compress.push(path.clone());
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
    };

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

    let h = Header::new(eparams, compression, com_level, bs, enc_type);
    let archive_path = PathBuf::from(archive_filename(&arv_name));
    let mut archive = ArchiveWriter::new(&arv_name, h.clone(), args.confirm)?;
    let mut files = Vec::new();
    let mut stream_position = 0u64;
    let mut block_id = 0u64;
    let mut pending_buffer = Vec::new();
    let block_size = args.bs as usize;
    let workers_tx = reader_writer_tx.clone();
    let worker_cipher = archive.cipher.clone();
    let worker_archive_id = archive.header.archive_id;
    let worker_compression = archive.header.compression;
    let worker_level = archive.header.compression_level;
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
    let writer_handle = thread::spawn(move || writer(reader_writer_rx, &mut archive));

    let mut read_result: Result<(), CryoErrors> = Ok(());
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

        read_result = read_file_to_bytes(
            file.as_path(),
            &root,
            &mut files,
            &mut stream_position,
            &mut block_id,
            &mut pending_buffer,
            block_size,
            &raw_tx,
            pb_bytes.as_ref(),
        );
        if read_result.is_err() {
            break;
        }

        if let Some(pb) = pb_bytes {
            pb.finish_and_clear();
        }
        if let Some(pb) = &pb_files {
            pb.inc(1);
        }
    }
    if read_result.is_ok() && !pending_buffer.is_empty() {
        let _ = raw_tx.send(RawBlock {
            id: block_id,
            raw_data: std::mem::take(&mut pending_buffer),
        });
    }
    drop(raw_tx);
    let finish = (|| -> Result<(), CryoErrors> {
        workers_handle
            .join()
            .map_err(|_| CryoErrors::ThreadError)??;
        read_result?;
        reader_writer_tx
            .send(WriterMessage::Finalize {
                files,
                total_stream_size: stream_position,
            })
            .map_err(|_| CryoErrors::ThreadError)?;
        writer_handle
            .join()
            .map_err(|_| CryoErrors::ThreadError)??;
        Ok(())
    })();
    if finish.is_err() {
        let _ = fs::remove_file(&archive_path);
    }
    finish?;

    event!(Level::DEBUG, archive = %arv_name, "compression finished");
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn read_file_to_bytes(
    p: &Path,
    root: &Path,
    files: &mut Vec<FileEntry>,
    stream_position: &mut u64,
    block_id: &mut u64,
    pending_buffer: &mut Vec<u8>,
    block_size: usize,
    raw_tx: &Sender<RawBlock>,
    pb: Option<&ProgressBar>,
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
    let stripped = p
        .strip_prefix(root)
        .map_err(|_| CryoErrors::InvalidPath)?
        .to_path_buf();

    event!(Level::DEBUG, path = %p.display(), ftype = ?ftype, size = fmetadata.size(), "reading entry");
    if !matches!(ftype, FileType::File) {
        return handle_non_regular_files(files, ftype, fmetadata, root, *stream_position, p);
    }
    let entry = FileEntry {
        path: stripped,
        ftype,
        stream_offset: *stream_position,
        size: fmetadata.size(),
        symlink_target: None,
        timestamp: fmetadata.mtime() as u64,
        permissions: fmetadata.mode(),
    };
    files.push(entry);

    let mut file = File::open(p).map_err(|e| CryoErrors::ReadFailed {
        p: p.to_path_buf(),
        source: e,
    })?;

    let chunk_size = block_size;
    let mut chunk = vec![0u8; chunk_size];
    loop {
        let n = file.read(&mut chunk).map_err(|e| CryoErrors::ReadFailed {
            p: p.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        pending_buffer.extend_from_slice(&chunk[..n]);
        *stream_position += n as u64;
        if let Some(pb) = pb {
            pb.inc(n as u64);
        }
        while pending_buffer.len() >= block_size {
            let block_data: Vec<u8> = pending_buffer.drain(..block_size).collect();
            let _ = raw_tx.send(RawBlock {
                id: *block_id,
                raw_data: block_data,
            });
            *block_id += 1;
        }
    }
    Ok(())
}

pub fn retrieve_all_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), CryoErrors> {
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

fn check_compression_for_arg_err(s: &str, p: &Path, r: bool) -> Result<(), CryoErrors> {
    if s.is_empty() {
        Err(CryoErrors::EmptyArchiveName)
    } else if !p.exists() || (!p.is_dir() && r) {
        Err(CryoErrors::InvalidPath)
    } else {
        Ok(())
    }
}
fn handle_non_regular_files(
    files: &mut Vec<FileEntry>,
    ftype: FileType,
    fmetadata: Metadata,
    root: &Path,
    stream_offset: u64,
    p: &Path,
) -> Result<(), CryoErrors> {
    match ftype {
        FileType::Symlink => {
            let target = std::fs::read_link(p).map_err(|e| CryoErrors::ReadFailed {
                p: p.to_path_buf(),
                source: e,
            })?;
            event!(Level::DEBUG, path = %p.display(), target = %target.display(), "symlink entry");
            let entry = FileEntry {
                path: p
                    .strip_prefix(root)
                    .map_err(|_| CryoErrors::InvalidPath)?
                    .to_path_buf(),
                ftype,
                stream_offset,
                size: 0,
                symlink_target: Some(target),
                timestamp: fmetadata.mtime() as u64,
                permissions: fmetadata.mode(),
            };
            files.push(entry);
            Ok(())
        }
        FileType::Dir => {
            event!(Level::DEBUG, path = %p.display(), "directory entry");
            let entry = FileEntry {
                path: p
                    .strip_prefix(root)
                    .map_err(|_| CryoErrors::InvalidPath)?
                    .to_path_buf(),
                ftype,
                stream_offset,
                size: 0,
                symlink_target: None,
                timestamp: fmetadata.mtime() as u64,
                permissions: fmetadata.mode(),
            };
            files.push(entry);
            Ok(())
        }
        FileType::File => unreachable!(),
    }
}

pub fn writer(rx: Receiver<WriterMessage>, arch: &mut ArchiveWriter) -> Result<(), CryoErrors> {
    let mut block_queue: BTreeMap<u64, ProcessedBlock> = BTreeMap::new();
    let mut expected_id: u64 = arch.index.block.len() as u64;
    while let Ok(data) = rx.recv() {
        match data {
            WriterMessage::Block(block) => {
                block_queue.insert(block.id, block);
                while let Some(block) = block_queue.remove(&expected_id) {
                    let size_stored = block.processed_data.len() as u32;
                    arch.writer
                        .write_all(&block.processed_data)
                        .map_err(|_| CryoErrors::WriteError)?;
                    arch.index.block.push(BlockEntry {
                        offset: arch.file_position,
                        size_stored,
                        size_plain: block.size_plain,
                        is_compressed: block.is_compressed,
                        nonce: block.nonce,
                        checksum: block.checksum,
                    });
                    expected_id += 1;
                    arch.file_position += size_stored as u64;
                }
            }
            WriterMessage::Finalize {
                files,
                total_stream_size,
            } => {
                arch.index.files = files;
                arch.stream_position = total_stream_size;
                arch.finish()?;

                break;
            }
        }
    }
    Ok(())
}
pub fn spawn_workers(
    raw_rx: Receiver<RawBlock>,
    writer_tx: Sender<WriterMessage>,
    cipher: &Cipher,
    archive_id: [u8; 16],
    compression: &Compressor,
    level: i32,
) -> Result<(), CryoErrors> {
    let writer_tx = Mutex::new(writer_tx);
    let engine_pool: Mutex<Vec<CompressingEngine>> = Mutex::new(vec![]);
    raw_rx
        .into_iter()
        .par_bridge()
        .try_for_each(|raw_block| -> Result<(), CryoErrors> {
            let mut single_engine = match engine_pool
                .lock()
                .map_err(|_| CryoErrors::ThreadError)?
                .pop()
            {
                Some(eng) => eng,
                None => CompressingEngine::new(compression, level)?,
            };
            let result = process_block(raw_block, cipher, &archive_id, &mut single_engine);
            engine_pool
                .lock()
                .map_err(|_| CryoErrors::ThreadError)?
                .push(single_engine);
            let processed = result?;
            writer_tx
                .lock()
                .map_err(|_| CryoErrors::ThreadError)?
                .send(WriterMessage::Block(processed))
                .map_err(|_| CryoErrors::ThreadError)?;
            Ok(())
        })
}

fn process_block(
    block: RawBlock,
    cipher: &Cipher,
    archive_id: &[u8; 16],
    compressor: &mut CompressingEngine,
) -> Result<ProcessedBlock, CryoErrors> {
    let checksum = blake3::hash(&block.raw_data);

    let size_plain = block.raw_data.len() as u32;
    let compressed = compressor.engine.compress(block.raw_data.as_slice())?;
    let (to_encrypt, is_compressed) = if compressed.len() < block.raw_data.len() {
        (compressed, true)
    } else {
        (block.raw_data, false)
    };
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = encrypt_block(
        block.id,
        &to_encrypt,
        EncryptedData::Block(nonce),
        archive_id,
        cipher,
    )?;
    Ok(ProcessedBlock {
        id: block.id,
        processed_data: encrypted,
        size_plain,
        is_compressed,
        nonce,
        checksum: checksum.into(),
    })
}
