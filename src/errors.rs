use std::fmt::Display;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CryoErrors {
    EmptyArchiveName,
    CompressionError,
    DecompressionError,
    InvalidCompressionLevel,
    InvalidPath,
    SerializationFailed,
    DeserializationFailed,
    RecursiveLookupFailed { p: PathBuf, source: std::io::Error },
    ReadFailed { p: PathBuf, source: std::io::Error },
    UnsafePath(PathBuf),
    WriteError,
    CryptographicError(String),
    InitializationError(String),
    FileTooLarge { size: u64, limit: u64 },
    BlockTooLarge { size: u64, limit: u64 },
    MCostTooLarge { size: u64, limit: u64 },
    IndexTooLarge { size: u64, limit: u64 },
    HeaderTooLarge { size: u64, limit: u64 },
    ChecksumMismatch,
    InvalidPattern,
    ThreadError,
}

impl Display for CryoErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyArchiveName => write!(f, "Archive name cannot be empty"),
            Self::InvalidCompressionLevel => write!(
                f,
                "Compression level must be 0 (lowest, fastest) to 22 (highest, slowest)"
            ),
            Self::InvalidPath => write!(
                f,
                "Invalid path: path doesn't exist, or --recursive was used on a file (requires a directory)"
            ),
            Self::RecursiveLookupFailed { p, .. } => {
                write!(f, "Recursive directory scan failed at: {}", p.display())
            }
            Self::ReadFailed { p, source } => {
                write!(f, "Failed to read '{}': {}", p.display(), source)
            }
            Self::WriteError => write!(f, "Failed to write to disk"),
            Self::CryptographicError(s) => write!(f, "Cryptographic error: {s}"),
            Self::CompressionError => write!(f, "Failed to compress block"),
            Self::DecompressionError => write!(f, "Failed to decompress block"),
            Self::SerializationFailed => write!(f, "Failed to serialize file structure"),
            Self::DeserializationFailed => write!(f, "Failed to deserialize file structure"),
            Self::InitializationError(s) => write!(f, "Initialization error: {s}"),
            Self::UnsafePath(p) => write!(
                f,
                "Archive you are trying to decompress contains unsafe path traversal files!: {:?}",
                p
            ),
            Self::FileTooLarge { size, limit } => write!(
                f,
                "file too large: {} > {} (use --max-file-size SIZE to raise)",
                bytesize::ByteSize(*size),
                bytesize::ByteSize(*limit)
            ),
            Self::BlockTooLarge { size, limit } => write!(
                f,
                "block too large: {} > {} (use --max-block-size SIZE to raise)",
                bytesize::ByteSize(*size),
                bytesize::ByteSize(*limit)
            ),
            Self::MCostTooLarge { size, limit } => write!(
                f,
                "argon2 memory cost too large: {} > {} (use --max-m-cost SIZE to raise)",
                bytesize::ByteSize(*size),
                bytesize::ByteSize(*limit)
            ),
            Self::IndexTooLarge { size, limit } => write!(
                f,
                "archive index too large: {} > {} (use --max-index-size SIZE to raise)",
                bytesize::ByteSize(*size),
                bytesize::ByteSize(*limit)
            ),
            Self::HeaderTooLarge { size, limit } => write!(
                f,
                "archive header too large: {} > {} (use --max-header-size SIZE to raise)",
                bytesize::ByteSize(*size),
                bytesize::ByteSize(*limit)
            ),
            Self::ChecksumMismatch => write!(f, "Error checksum mismatched while veryfing!"),
            Self::InvalidPattern => write!(f, "You have provided invalid pattern for the files!"),
            Self::ThreadError => write!(
                f,
                "While using multithreading to process archive error has happened!"
            ),
        }
    }
}

impl std::error::Error for CryoErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RecursiveLookupFailed { source, .. } => Some(source),
            Self::ReadFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}
