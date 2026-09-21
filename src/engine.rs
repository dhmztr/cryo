use std::io::{Read, Write};

use crate::errors::CryoErrors;
use clap::ValueEnum;
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;

#[derive(Clone, Copy, ValueEnum, serde::Serialize, serde::Deserialize, Debug)]
pub enum Compressor {
    Zstd,
    Xz,
    Gzip,
    None,
}
impl std::fmt::Display for Compressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Compressor::Zstd => write!(f, "Zstd"),
            Compressor::None => write!(f, "None"),
            Compressor::Gzip => write!(f, "Gzip"),
            Compressor::Xz => write!(f, "Xz"),
        }
    }
}

pub struct CompressingEngine {
    pub engine: Box<dyn Compress>,
}

pub trait Compress {
    fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>, CryoErrors>;
}

struct ZstdCompress {
    inner: zstd::bulk::Compressor<'static>,
}
impl Compress for ZstdCompress {
    fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>, CryoErrors> {
        self.inner
            .compress(data)
            .map_err(|_| CryoErrors::CompressionError)
    }
}
struct GzipCompress {
    level: u32,
}

impl Compress for GzipCompress {
    fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>, CryoErrors> {
        let mut compressor = DeflateEncoder::new(vec![], Compression::new(self.level));
        compressor
            .write_all(data)
            .map_err(|_| CryoErrors::WriteError)?;
        compressor
            .finish()
            .map_err(|_| CryoErrors::CompressionError)
    }
}
struct XzCompress {
    level: u32,
}
impl Compress for XzCompress {
    fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>, CryoErrors> {
        let mut compressor = XzEncoder::new(vec![], self.level);
        compressor
            .write_all(data)
            .map_err(|_| CryoErrors::WriteError)?;
        compressor
            .finish()
            .map_err(|_| CryoErrors::CompressionError)
    }
}
struct NoneCompress;
impl Compress for NoneCompress {
    fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>, CryoErrors> {
        Ok(data.to_owned())
    }
}
impl CompressingEngine {
    pub fn new(engine: &Compressor, level: i32) -> Result<Self, CryoErrors> {
        let verify_level = |engine: &Compressor, level: i32| -> bool {
            match engine {
                Compressor::Gzip | Compressor::Xz => (0..=9).contains(&level),
                Compressor::Zstd => zstd::compression_level_range().contains(&level),
                Compressor::None => true,
            }
        };
        if !verify_level(engine, level) {
            return Err(CryoErrors::InvalidCompressionLevel);
        }
        match engine {
            Compressor::Zstd => {
                let engine = zstd::bulk::Compressor::new(level).map_err(|_| {
                    CryoErrors::InitializationError("Failed to initialzie zstd engine".into())
                })?;
                Ok(Self {
                    engine: Box::new(ZstdCompress { inner: engine }),
                })
            }
            Compressor::Xz => {
                let level = level as u32;
                Ok(Self {
                    engine: Box::new(XzCompress { level }),
                })
            }
            Compressor::Gzip => {
                let level = level as u32;
                Ok(Self {
                    engine: Box::new(GzipCompress { level }),
                })
            }
            Compressor::None => Ok(Self {
                engine: Box::new(NoneCompress),
            }),
        }
    }
}

pub struct DecompressingEngine {
    pub engine: Box<dyn Decompress>,
}

pub trait Decompress {
    fn decompress(&mut self, data: &[u8], max_size: usize) -> Result<Vec<u8>, CryoErrors>;
}
struct ZstdDecompress {
    inner: zstd::bulk::Decompressor<'static>,
}
impl Decompress for ZstdDecompress {
    fn decompress(&mut self, data: &[u8], max_size: usize) -> Result<Vec<u8>, CryoErrors> {
        self.inner
            .decompress(data, max_size)
            .map_err(|_| CryoErrors::DecompressionError)
    }
}
struct XzDecompress;
impl Decompress for XzDecompress {
    fn decompress(&mut self, data: &[u8], max_size: usize) -> Result<Vec<u8>, CryoErrors> {
        let decompressor = XzDecoder::new(data);
        let mut limit = decompressor.take(max_size as u64 + 1);
        let mut out = vec![];
        limit
            .read_to_end(&mut out)
            .map_err(|_| CryoErrors::DecompressionError)?;
        if out.len() > max_size {
            return Err(CryoErrors::PossibleZipBomb);
        }
        Ok(out)
    }
}
struct GzipDecompress;
impl Decompress for GzipDecompress {
    fn decompress(&mut self, data: &[u8], max_size: usize) -> Result<Vec<u8>, CryoErrors> {
        let decompressor = DeflateDecoder::new(data);
        let mut limit = decompressor.take(max_size as u64 + 1);
        let mut out = vec![];
        limit
            .read_to_end(&mut out)
            .map_err(|_| CryoErrors::DecompressionError)?;
        if out.len() > max_size {
            return Err(CryoErrors::PossibleZipBomb);
        }
        Ok(out)
    }
}
struct NoneDecompress;
impl Decompress for NoneDecompress {
    fn decompress(&mut self, data: &[u8], _: usize) -> Result<Vec<u8>, CryoErrors> {
        Ok(data.to_owned())
    }
}
impl DecompressingEngine {
    pub fn new(engine: &Compressor) -> Result<Self, CryoErrors> {
        match engine {
            Compressor::Zstd => {
                let inner = zstd::bulk::Decompressor::new().map_err(|_| {
                    CryoErrors::InitializationError(
                        "Failed to initialize zstd decompression engine".into(),
                    )
                })?;
                Ok(Self {
                    engine: Box::new(ZstdDecompress { inner }),
                })
            }
            Compressor::Gzip => Ok(Self {
                engine: Box::new(GzipDecompress),
            }),
            Compressor::None => Ok(Self {
                engine: Box::new(NoneDecompress),
            }),
            Compressor::Xz => Ok(Self {
                engine: Box::new(XzDecompress),
            }),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Returns highly repetitive bytes that every algorithm compresses well.
    fn compressible_data() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog. ".repeat(100)
    }

    /// Returns pseudorandom bytes that may grow when compressed.
    fn incompressible_data() -> Vec<u8> {
        (0..2000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
            .collect()
    }

    /// Asserts that compressing and decompressing `data` returns it unchanged.
    fn roundtrip(algo: &Compressor, level: i32, data: &[u8]) {
        let mut comp = CompressingEngine::new(algo, level).expect("compress engine");
        let compressed = comp.engine.compress(data).expect("compress");

        let mut decomp = DecompressingEngine::new(algo).expect("decompress engine");
        let out = decomp
            .engine
            .decompress(&compressed, data.len())
            .expect("decompress");

        assert_eq!(out, data, "round-trip mismatch");
    }

    #[test]
    fn zstd_roundtrip() {
        let data = compressible_data();
        roundtrip(&Compressor::Zstd, 3, &data);
    }

    #[test]
    fn gzip_roundtrip() {
        let data = compressible_data();
        roundtrip(&Compressor::Gzip, 6, &data);
    }

    #[test]
    fn xz_roundtrip() {
        let data = compressible_data();
        roundtrip(&Compressor::Xz, 6, &data);
    }

    #[test]
    fn none_roundtrip() {
        let data = compressible_data();
        roundtrip(&Compressor::None, 0, &data);
    }

    #[test]
    fn empty_input_roundtrip() {
        roundtrip(&Compressor::Zstd, 3, b"");
        roundtrip(&Compressor::Gzip, 6, b"");
        roundtrip(&Compressor::Xz, 6, b"");
        roundtrip(&Compressor::None, 0, b"");
    }

    #[test]
    fn incompressible_roundtrip() {
        let data = incompressible_data();
        roundtrip(&Compressor::Zstd, 3, &data);
        roundtrip(&Compressor::Gzip, 6, &data);
        roundtrip(&Compressor::Xz, 6, &data);
    }

    #[test]
    fn gzip_level_9_valid() {
        assert!(
            CompressingEngine::new(&Compressor::Gzip, 9).is_ok(),
            "level 9 must be valid"
        );
    }

    #[test]
    fn xz_level_9_valid() {
        assert!(
            CompressingEngine::new(&Compressor::Xz, 9).is_ok(),
            "level 9 must be valid"
        );
    }

    #[test]
    fn level_out_of_range_rejected() {
        assert!(
            CompressingEngine::new(&Compressor::Gzip, 10).is_err(),
            "level 10 invalid for gzip"
        );
        assert!(
            CompressingEngine::new(&Compressor::Gzip, -1).is_err(),
            "negative invalid"
        );
        assert!(
            CompressingEngine::new(&Compressor::Xz, 100).is_err(),
            "level 100 invalid"
        );
    }

    #[test]
    fn none_accepts_any_level() {
        assert!(CompressingEngine::new(&Compressor::None, 0).is_ok());
        assert!(CompressingEngine::new(&Compressor::None, 999).is_ok());
    }

    #[test]
    fn zstd_level_in_range() {
        assert!(CompressingEngine::new(&Compressor::Zstd, 1).is_ok());
        assert!(CompressingEngine::new(&Compressor::Zstd, 19).is_ok());
    }

    #[test]
    fn zip_bomb_rejected_gzip() {
        let big = vec![0u8; 1_000_000];
        let mut comp = CompressingEngine::new(&Compressor::Gzip, 9).unwrap();
        let compressed = comp.engine.compress(&big).unwrap();

        let mut decomp = DecompressingEngine::new(&Compressor::Gzip).unwrap();
        let result = decomp.engine.decompress(&compressed, 1000);
        assert!(
            result.is_err(),
            "decompression exceeding limit must be rejected"
        );
    }

    #[test]
    fn zip_bomb_rejected_xz() {
        let big = vec![0u8; 1_000_000];
        let mut comp = CompressingEngine::new(&Compressor::Xz, 9).unwrap();
        let compressed = comp.engine.compress(&big).unwrap();

        let mut decomp = DecompressingEngine::new(&Compressor::Xz).unwrap();
        let result = decomp.engine.decompress(&compressed, 1000);
        assert!(
            result.is_err(),
            "xz decompression exceeding limit must be rejected"
        );
    }

    #[test]
    fn zip_bomb_rejected_zstd() {
        let big = vec![0u8; 1_000_000];
        let mut comp = CompressingEngine::new(&Compressor::Zstd, 19).unwrap();
        let compressed = comp.engine.compress(&big).unwrap();

        let mut decomp = DecompressingEngine::new(&Compressor::Zstd).unwrap();
        let result = decomp.engine.decompress(&compressed, 1000);
        assert!(
            result.is_err(),
            "zstd decompression exceeding limit must be rejected"
        );
    }

    #[test]
    fn decompress_at_exact_limit_ok() {
        let data = vec![7u8; 5000];
        let mut comp = CompressingEngine::new(&Compressor::Gzip, 6).unwrap();
        let compressed = comp.engine.compress(&data).unwrap();

        let mut decomp = DecompressingEngine::new(&Compressor::Gzip).unwrap();
        let out = decomp
            .engine
            .decompress(&compressed, 5000)
            .expect("exact limit must pass");
        assert_eq!(out.len(), 5000);
    }

    #[test]
    fn compression_reduces_size() {
        let data = compressible_data();
        for algo in &[Compressor::Zstd, Compressor::Gzip, Compressor::Xz] {
            let level = 6.min(match algo {
                Compressor::Zstd => 19,
                _ => 9,
            });
            let mut comp = CompressingEngine::new(algo, level).unwrap();
            let compressed = comp.engine.compress(&data).unwrap();
            assert!(
                compressed.len() < data.len(),
                "compressed should be smaller for repetitive data"
            );
        }
    }
}
