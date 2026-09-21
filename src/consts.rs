use argon2::{Algorithm, Version};

/// Archive signature: the ASCII tag `CRYO` followed by DOS EOF, LF, CR and NUL,
/// so that text-mode transfers corrupt the file visibly instead of silently.
pub const MAGIC: [u8; 8] = [0x43, 0x52, 0x59, 0x4F, 0x1A, 0x0A, 0x0D, 0x00];
pub const VERSION: u16 = 1;
pub const ARGON2VERSION: Version = Version::V0x13;
pub const ARGON2ALGO: Algorithm = argon2::Algorithm::Argon2id;
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024;
pub const MAX_BLOCK_SIZE: u64 = 256 * 1024 * 1024;
pub const MAX_M_COST: u32 = 1024 * 1024;
pub const MAX_INDEX_SIZE: u64 = 100 * 1024 * 1024;
pub const MAX_HEADER_SIZE: usize = 64 * 1024;
pub const STORED_BLOCK_OVERHEAD: u64 = 1024;

pub struct Limits {
    pub(crate) max_block_size: u64,
    pub(crate) max_file_size: u64,
    pub(crate) max_m_cost: u32,
    pub(crate) max_index_size: u64,
    pub(crate) max_header_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_file_size: MAX_FILE_SIZE,
            max_block_size: MAX_BLOCK_SIZE,
            max_m_cost: MAX_M_COST,
            max_index_size: MAX_INDEX_SIZE,
            max_header_size: MAX_HEADER_SIZE,
        }
    }
}
