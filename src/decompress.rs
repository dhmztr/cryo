use crate::consts::*;
use crate::structs::FileEntry;
use crate::{
    consts::Limits,
    encryption::block_nonce,
    structs::{Cipher, Footer, Index},
};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::{BufReader, Read, Seek, SeekFrom};
use tracing::{Level, event};
use zstd::Decoder;

use crate::{
    DecompressArgs,
    errors::CryoErrors,
    structs::{ArchiveReader, EncryptedData, Header},
};
use std::{fs::File, path::PathBuf};
pub(crate) struct FileStructs {
    pub(crate) header: Header,
    pub(crate) index: Index,
    pub(crate) cipher: Cipher,
}
impl FileStructs {
    pub(crate) fn retrieve(f: &File, p: &PathBuf, limits: &Limits) -> Result<Self, CryoErrors> {
        let mut header_size_bytes: [u8; 4] = [0u8; 4];
        let mut reader = BufReader::new(f);
        reader
            .read_exact(&mut header_size_bytes)
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.clone(),
                source: e,
            })?;
        let header_size = u32::from_le_bytes(header_size_bytes) as usize;
        let eff_max_header = if limits.max_header_size == 0 {
            MAX_HEADER_SIZE
        } else {
            limits.max_header_size
        };
        if header_size > eff_max_header {
            return Err(CryoErrors::HeaderTooLarge {
                size: header_size as u64,
                limit: eff_max_header as u64,
            });
        }
        event!(Level::DEBUG, "header size: {header_size}");
        let mut header_bytes = vec![0u8; header_size];
        reader
            .read_exact(&mut header_bytes)
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.clone(),
                source: e,
            })?;
        let header = rmp_serde::from_slice::<Header>(&header_bytes)
            .map_err(|_| CryoErrors::DeserializationFailed)?;
        event!(Level::DEBUG, "Header: {:#?}", header);
        let eff_max_block = if limits.max_block_size == 0 {
            MAX_BLOCK_SIZE
        } else {
            limits.max_block_size
        };
        if header.block_size > eff_max_block {
            return Err(CryoErrors::BlockTooLarge {
                size: header.block_size,
                limit: eff_max_block,
            });
        }
        let eff_max_m = if limits.max_m_cost == 0 {
            MAX_M_COST
        } else {
            limits.max_m_cost
        };
        if header.argon_params.0 > eff_max_m {
            return Err(CryoErrors::MCostTooLarge {
                size: header.argon_params.0 as u64 * 1024,
                limit: eff_max_m as u64 * 1024,
            });
        }
        reader
            .seek(SeekFrom::End(-17))
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.clone(),
                source: e,
            })?;
        let mut footer_bytes: [u8; 17] = [0u8; 17];
        reader
            .read_exact(&mut footer_bytes)
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.clone(),
                source: e,
            })?;
        let footer = Footer::deserialize(footer_bytes)?;
        let eff_max_index = if limits.max_index_size == 0 {
            MAX_INDEX_SIZE
        } else {
            limits.max_index_size
        };
        if footer.index_size_stored as u64 > eff_max_index {
            return Err(CryoErrors::IndexTooLarge {
                size: footer.index_size_stored as u64,
                limit: eff_max_index,
            });
        }
        let cipher = Cipher::new(&header)?;
        let mut index_bytes = vec![0u8; footer.index_size_stored as usize];
        event!(Level::DEBUG, "Index size: {}", index_bytes.len());
        reader
            .seek(SeekFrom::Start(footer.index_offset))
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.clone(),
                source: e,
            })?;

        reader
            .read_exact(&mut index_bytes)
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.clone(),
                source: e,
            })?;

        let mut index_bytes = if !matches!(cipher, Cipher::None) {
            decrypt_block(EncryptedData::Index, &cipher, &header, &index_bytes, 0)?
        } else {
            index_bytes
        };

        if footer.index_compressed {
            index_bytes = decompress_block(index_bytes, &header, limits.max_block_size)?;
        }
        let index = rmp_serde::from_slice::<Index>(&index_bytes)
            .map_err(|_| CryoErrors::DeserializationFailed)?;
        event!(Level::DEBUG, "Index: {:#?}", index);
        Ok(FileStructs {
            header,
            index,
            cipher,
        })
    }
}

pub(crate) fn initialize_decompression(args: DecompressArgs) -> Result<(), CryoErrors> {
    let arv_name = args.archive;
    let output_dir = args.output;

    event!(
        Level::DEBUG,
        archive = %arv_name.display(),
        output = %output_dir.display(),
        "starting decompression"
    );
    let max_m_cost = if let Some(max_m) = args.max_m_cost {
        Some((max_m / 1024) as u32)
    } else {
        None
    };
    let max_header_size: Option<usize> = if let Some(max_h) = args.max_header_size {
        Some((max_h / 1024) as usize)
    } else {
        None
    };
    let filter = build_matcher(&args.filter)?;
    check_decompression_for_arg_err(&arv_name, &output_dir)?;
    let defaults = Limits::default();
    let limits = Limits {
        max_file_size: args.max_file_size.unwrap_or(defaults.max_file_size),
        max_block_size: args.max_block_size.unwrap_or(defaults.max_block_size),
        max_m_cost: max_m_cost.unwrap_or(defaults.max_m_cost as u32),
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

pub(crate) fn check_decompression_for_arg_err(
    arv: &PathBuf,
    out: &PathBuf,
) -> Result<(), CryoErrors> {
    out.parent().ok_or_else(|| {
        CryoErrors::InitializationError(String::from("Parent directory for output doesn't exist"))
    })?;
    if out.exists() && out.is_dir() {
        let out_dir = out.read_dir().map_err(|e| CryoErrors::ReadFailed {
            p: out.clone(),
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
pub(crate) fn decrypt_block(
    encd: EncryptedData,
    c: &Cipher,
    h: &Header,
    payload: &[u8],
    block_num: usize,
) -> Result<Vec<u8>, CryoErrors> {
    if !matches!(c, Cipher::None) {
        let (nonce, aad) = match encd {
            EncryptedData::Index => {
                let block_num = u64::MAX;
                let nonce = block_nonce(&h.nonce_base, block_num);
                let aad: Vec<u8> = [&"index".as_bytes()[..], &h.archive_id].concat();
                (nonce, aad)
            }
            EncryptedData::Block => {
                let nonce = block_nonce(&h.nonce_base, block_num as u64);
                let aad: Vec<u8> = [&block_num.to_le_bytes()[..], &h.archive_id].concat();
                (nonce, aad)
            }
        };
        match c {
            Cipher::Aes(key) => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
                    CryoErrors::CryptographicError("AES initizalition failure".to_owned())
                })?;
                let aesnonce: aes_gcm::Nonce<_> = nonce.into();

                let ciphertext = cipher
                    .decrypt(
                        &aesnonce,
                        Payload {
                            msg: payload,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        CryoErrors::CryptographicError("AES encryption failure".to_owned())
                    })?;
                Ok(ciphertext.as_slice().to_owned())
            }

            Cipher::Chacha(k) => {
                let key = Key::from(*k);
                let cipher = ChaCha20Poly1305::new(&key);
                let chachanonce: Nonce = nonce.into();
                let ciphertext = cipher
                    .decrypt(
                        &chachanonce,
                        Payload {
                            msg: payload,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        CryoErrors::CryptographicError("CHACHA decrypt failure".to_owned())
                    })?;
                Ok(ciphertext.as_slice().to_owned())
            }
            Cipher::None => Ok(payload.to_owned()),
        }
    } else {
        Ok(payload.to_owned())
    }
}
pub(crate) fn decompress_block(
    block: Vec<u8>,
    h: &Header,
    max_size: u64,
) -> Result<Vec<u8>, CryoErrors> {
    let mut decoder = Decoder::new(block.as_slice()).map_err(|_| CryoErrors::DecompressionError)?;
    let mut out: Vec<u8> = Vec::with_capacity(h.block_size as usize);
    let mut buf: [u8; 8192] = [0u8; 8192];
    let mut total: u64 = 0;
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|_| CryoErrors::DecompressionError)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max_size {
            return Err(CryoErrors::BlockTooLarge {
                size: total,
                limit: max_size,
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}
fn build_matcher(patterns: &[String]) -> Result<GlobSet, CryoErrors> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p).map_err(|_| CryoErrors::InvalidPattern)?);
    }
    builder.build().map_err(|_| CryoErrors::InvalidPattern)
}
