use crate::codec::{Cipher, decrypt_block};
use crate::consts::{Limits, MAGIC, MAX_BLOCK_SIZE, MAX_HEADER_SIZE, MAX_INDEX_SIZE, MAX_M_COST};
use crate::engine::DecompressingEngine;
use crate::errors::CryoErrors;
use crate::format::{EncryptedData, Footer, Header, Index};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::{fs::File, path::Path};
use tracing::{Level, event};

pub(crate) struct FileStructs {
    pub(crate) header: Header,
    pub(crate) index: Index,
    pub(crate) cipher: Cipher,
    pub(crate) footer: Footer,
}

impl FileStructs {
    pub(crate) fn retrieve(
        f: &File,
        p: &Path,
        limits: &Limits,
        confirm: bool,
    ) -> Result<Self, CryoErrors> {
        let mut header_size_bytes: [u8; 4] = [0u8; 4];
        let mut reader = BufReader::new(f);
        reader
            .read_exact(&mut header_size_bytes)
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.to_path_buf(),
                source: e,
            })?;
        let header_size = u32::from_le_bytes(header_size_bytes) as usize;
        let eff_max_header = limits.max_header_size.unwrap_or(MAX_HEADER_SIZE);
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
                p: p.to_path_buf(),
                source: e,
            })?;
        let header = rmp_serde::from_slice::<Header>(&header_bytes)
            .map_err(|_| CryoErrors::DeserializationFailed)?;
        event!(Level::DEBUG, "Header: {:#?}", header);
        verify_metadata(&header)?;
        let eff_max_block = limits.max_block_size.unwrap_or(MAX_BLOCK_SIZE);

        if header.block_size > eff_max_block {
            return Err(CryoErrors::BlockTooLarge {
                size: header.block_size,
                limit: eff_max_block,
            });
        }
        let eff_max_m = limits.max_m_cost.unwrap_or(MAX_M_COST);
        if header.argon_params.0 > eff_max_m {
            return Err(CryoErrors::MCostTooLarge {
                size: header.argon_params.0 as u64 * 1024,
                limit: eff_max_m as u64 * 1024,
            });
        }
        reader
            .seek(SeekFrom::End(-29))
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.to_path_buf(),
                source: e,
            })?;
        let mut footer_bytes: [u8; 29] = [0u8; 29];
        reader
            .read_exact(&mut footer_bytes)
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.to_path_buf(),
                source: e,
            })?;
        let footer = Footer::deserialize(footer_bytes)?;
        let eff_max_index = limits.max_index_size.unwrap_or(MAX_INDEX_SIZE);
        if footer.index_size_stored as u64 > eff_max_index {
            return Err(CryoErrors::IndexTooLarge {
                size: footer.index_size_stored as u64,
                limit: eff_max_index,
            });
        }
        if footer.index_size_plain as u64 > eff_max_index {
            return Err(CryoErrors::IndexTooLarge {
                size: footer.index_size_plain as u64,
                limit: eff_max_index,
            });
        }
        let cipher = Cipher::new(&header, confirm)?;
        let mut index_bytes = vec![0u8; footer.index_size_stored as usize];
        event!(Level::DEBUG, "Index size: {}", index_bytes.len());
        reader
            .seek(SeekFrom::Start(footer.index_offset))
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.to_path_buf(),
                source: e,
            })?;

        reader
            .read_exact(&mut index_bytes)
            .map_err(|e| CryoErrors::ReadFailed {
                p: p.to_path_buf(),
                source: e,
            })?;

        let mut index_bytes = if !matches!(cipher, Cipher::None) {
            decrypt_block(
                EncryptedData::Index(footer.index_nonce),
                &cipher,
                &header,
                &index_bytes,
                0,
            )?
        } else {
            index_bytes
        };

        if footer.index_compressed {
            let mut engine = DecompressingEngine::new(&header.compression)?;
            index_bytes = engine
                .engine
                .decompress(&index_bytes, footer.index_size_plain as usize)?;
        }
        let index = rmp_serde::from_slice::<Index>(&index_bytes)
            .map_err(|_| CryoErrors::DeserializationFailed)?;
        event!(Level::DEBUG, "Index: {:#?}", index);
        Ok(FileStructs {
            header,
            index,
            cipher,
            footer,
        })
    }
}

pub fn verify_metadata(h: &Header) -> Result<(), CryoErrors> {
    if h.version != crate::consts::VERSION {
        return Err(CryoErrors::NotSupported);
    }
    if h.magic != MAGIC {
        return Err(CryoErrors::InvalidMagic);
    }
    Ok(())
}
