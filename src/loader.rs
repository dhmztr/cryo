use crate::codec::{Cipher, decompress_block, decrypt_block};
use crate::consts::{Limits, MAX_BLOCK_SIZE, MAX_HEADER_SIZE, MAX_INDEX_SIZE, MAX_M_COST};
use crate::errors::CryoErrors;
use crate::format::{EncryptedData, Footer, Header, Index};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::{fs::File, path::PathBuf};
use tracing::{Level, event};

pub(crate) struct FileStructs {
    pub(crate) header: Header,
    pub(crate) index: Index,
    pub(crate) cipher: Cipher,
    pub(crate) footer: Footer,
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
            footer,
        })
    }
}
