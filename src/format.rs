use crate::consts::{MAGIC, VERSION};
use crate::errors::CryoErrors;
use argon2::password_hash::rand_core::OsRng;
use clap::ValueEnum;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::path::PathBuf;
use uuid::Uuid;

pub enum EncryptedData {
    Index,
    Block,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct BlockEntry {
    pub(crate) offset: u64,
    pub(crate) size_stored: u32,
    pub(crate) size_plain: u32,
    pub(crate) is_compressed: bool,
    pub(crate) checksum: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct FileEntry {
    pub(crate) path: PathBuf,
    pub(crate) ftype: FileType,
    pub(crate) stream_offset: u64,
    pub(crate) size: u64,
    pub(crate) timestamp: u64,
    pub(crate) permissions: u32,
    pub(crate) symlink_target: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Index {
    pub files: Vec<FileEntry>,
    pub block: Vec<BlockEntry>,
    pub total_stream_size: u64,
}

impl Index {
    pub(crate) fn total_compressed_size(&self) -> u64 {
        self.block.iter().map(|b| b.size_stored as u64).sum()
    }

    pub(crate) fn file_compressed_size(&self, f: &FileEntry) -> u64 {
        if f.size == 0 {
            return 0;
        }
        let file_start = f.stream_offset;
        let file_end = file_start + f.size;
        let mut stream_pos = 0u64;
        let mut compressed = 0.0f64;
        for block in &self.block {
            let block_start = stream_pos;
            let block_end = block_start + block.size_plain as u64;
            stream_pos = block_end;
            if block_end <= file_start || block_start >= file_end {
                continue;
            }
            let overlap = file_end.min(block_end) - file_start.max(block_start);
            let fraction = overlap as f64 / block.size_plain as f64;
            compressed += fraction * block.size_stored as f64;
        }
        compressed as u64
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Header {
    pub magic: [u8; 8],
    pub version: u16,
    pub compression: i32,
    pub encryption: EncryptionType,
    pub argon_salt: [u8; 32],
    pub argon_params: (u32, u32, u32),
    pub archive_id: [u8; 16],
    pub block_size: u64,
    pub nonce_base: [u8; 12],
}

pub(crate) struct Footer {
    pub(crate) index_offset: u64,
    pub(crate) index_size_stored: u32,
    pub(crate) index_size_plain: u32,
    pub(crate) index_compressed: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum EncryptionType {
    AES,
    ChaCha,
    None,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FileType {
    File,
    Dir,
    Symlink,
}

#[derive(ValueEnum, Clone, Debug, Serialize, Deserialize)]
pub enum ParamsProfile {
    Fast,
    Balanced,
    Paranoid,
}

impl ParamsProfile {
    pub fn params(&self) -> (u32, u32, u32) {
        match self {
            Self::Fast => (19_456, 2, 1),
            Self::Balanced => (65_536, 3, 4),
            Self::Paranoid => (262_144, 4, 4),
        }
    }
}

impl Header {
    pub fn new(
        profile: ParamsProfile,
        compression: i32,
        bs: u64,
        encryption: EncryptionType,
    ) -> Self {
        let mut salt: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let archive_id = Uuid::new_v4().into_bytes();
        let mut nonce_base: [u8; 12] = [0; 12];
        OsRng.fill_bytes(&mut nonce_base);
        Header {
            magic: MAGIC,
            version: VERSION,
            encryption,
            compression,
            argon_salt: salt,
            argon_params: profile.params(),
            archive_id,
            block_size: bs,
            nonce_base,
        }
    }
}

impl Footer {
    pub fn serialize(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[0..8].copy_from_slice(&self.index_offset.to_le_bytes());
        out[8..12].copy_from_slice(&self.index_size_stored.to_le_bytes());
        out[12..16].copy_from_slice(&self.index_size_plain.to_le_bytes());
        out[16] = self.index_compressed as u8;
        out
    }
    pub fn deserialize(raw_data: [u8; 17]) -> Result<Self, CryoErrors> {
        if raw_data.len() != 17 {
            return Err(CryoErrors::DeserializationFailed);
        }

        let raw_index_offset: [u8; 8] = raw_data[0..8]
            .try_into()
            .map_err(|_| CryoErrors::DeserializationFailed)?;
        let raw_size_stored: [u8; 4] = raw_data[8..12]
            .try_into()
            .map_err(|_| CryoErrors::DeserializationFailed)?;
        let raw_size_plain: [u8; 4] = raw_data[12..16]
            .try_into()
            .map_err(|_| CryoErrors::DeserializationFailed)?;
        let raw_compressed: u8 = raw_data[16];
        let index_offset = u64::from_le_bytes(raw_index_offset);
        let index_size_stored = u32::from_le_bytes(raw_size_stored);
        let index_size_plain = u32::from_le_bytes(raw_size_plain);
        let index_compressed = raw_compressed != 0;
        Ok(Self {
            index_offset,
            index_size_stored,
            index_size_plain,
            index_compressed,
        })
    }
}

impl Display for EncryptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionType::AES => write!(f, "AES"),
            EncryptionType::ChaCha => write!(f, "ChaCha"),
            EncryptionType::None => write!(f, "None"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(size_plain: u32, size_stored: u32) -> BlockEntry {
        BlockEntry {
            offset: 0,
            size_stored,
            size_plain,
            is_compressed: false,
            checksum: [0u8; 32],
        }
    }

    fn make_file(stream_offset: u64, size: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from("f"),
            ftype: FileType::File,
            stream_offset,
            size,
            timestamp: 0,
            permissions: 0,
            symlink_target: None,
        }
    }

    #[test]
    fn footer_roundtrip() {
        let f = Footer {
            index_offset: 12345,
            index_size_stored: 678,
            index_size_plain: 999,
            index_compressed: true,
        };
        let bytes = f.serialize();
        let back = Footer::deserialize(bytes).unwrap();
        assert_eq!(f.index_offset, back.index_offset);
        assert_eq!(f.index_size_stored, back.index_size_stored);
        assert_eq!(f.index_size_plain, back.index_size_plain);
        assert_eq!(f.index_compressed, back.index_compressed);
    }

    #[test]
    fn footer_not_compressed_roundtrip() {
        let f = Footer {
            index_offset: 0,
            index_size_stored: 100,
            index_size_plain: 100,
            index_compressed: false,
        };
        let back = Footer::deserialize(f.serialize()).unwrap();
        assert!(!back.index_compressed);
    }

    #[test]
    fn file_compressed_size_empty_file() {
        let index = Index {
            files: vec![],
            block: vec![make_block(100, 50)],
            total_stream_size: 100,
        };
        assert_eq!(index.file_compressed_size(&make_file(0, 0)), 0);
    }

    #[test]
    fn file_compressed_size_full_single_block() {
        let index = Index {
            files: vec![],
            block: vec![make_block(100, 50)],
            total_stream_size: 100,
        };
        assert_eq!(index.file_compressed_size(&make_file(0, 100)), 50);
    }

    #[test]
    fn file_compressed_size_half_block() {
        let index = Index {
            files: vec![],
            block: vec![make_block(100, 100)],
            total_stream_size: 100,
        };
        assert_eq!(index.file_compressed_size(&make_file(0, 50)), 50);
    }

    #[test]
    fn file_compressed_size_second_block_only() {
        let index = Index {
            files: vec![],
            block: vec![make_block(100, 80), make_block(100, 60)],
            total_stream_size: 200,
        };
        assert_eq!(index.file_compressed_size(&make_file(100, 100)), 60);
    }

    #[test]
    fn total_compressed_size_sum() {
        let index = Index {
            files: vec![],
            block: vec![
                make_block(100, 40),
                make_block(100, 60),
                make_block(100, 20),
            ],
            total_stream_size: 300,
        };
        assert_eq!(index.total_compressed_size(), 120);
    }

    #[test]
    fn total_compressed_size_empty_index() {
        let index = Index {
            files: vec![],
            block: vec![],
            total_stream_size: 0,
        };
        assert_eq!(index.total_compressed_size(), 0);
    }
}
