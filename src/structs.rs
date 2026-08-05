use crate::consts::*;
use crate::decompress::decompress_block;

use crate::consts::{ARGON2ALGO, ARGON2VERSION};
use crate::decompress::{FileStructs, decrypt_block};
use crate::encryption::block_nonce;
use crate::{CryoErrors, OpenOptions};
use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{Argon2, Params, password_hash::rand_core::OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::ValueEnum;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs::{self, File, Permissions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};
use tracing::{Level, event};
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
pub struct ArchiveWriter {
    pub writer: BufWriter<File>,
    pub index: Index,
    pub stream_position: u64,
    pub file_position: u64,
    pub pending: Vec<u8>,
    pub(crate) cipher: Cipher,
    pub(crate) header: Header,
}
pub struct ArchiveReader {
    pub(crate) root: PathBuf,
    pub(crate) reader: BufReader<File>,
    pub(crate) index: Index,
    pub(crate) header: Header,
    pub(crate) cipher: Cipher,
    pub(crate) limits: Limits,
}
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Serialize, Deserialize)]
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
pub enum Cipher {
    None,
    Aes([u8; 32]),
    Chacha([u8; 32]),
}
impl Cipher {
    pub fn new(h: &Header) -> Result<Self, CryoErrors> {
        if h.encryption != EncryptionType::None {
            let params = Params::new(h.argon_params.0, h.argon_params.1, h.argon_params.2, None)
                .map_err(|_| {
                    CryoErrors::CryptographicError("Failed to initialize argon2 params".to_owned())
                })?;
            let arg2 = Argon2::new(ARGON2ALGO, ARGON2VERSION, params);
            let passwd_config = rpassword::ConfigBuilder::new()
                .password_feedback_mask('*')
                .build();
            let password = rpassword::prompt_password_with_config(
                "Provide encryption password for the archive:",
                passwd_config,
            )
            .map_err(|_| CryoErrors::CryptographicError("Failed to read password".to_owned()))?;
            let mut key: [u8; 32] = [0u8; 32];
            arg2.hash_password_into(password.as_bytes(), &h.argon_salt, &mut key)
                .map_err(|_| CryoErrors::CryptographicError("Argon2 failure".to_owned()))?;
            if h.encryption == EncryptionType::AES {
                Ok(Cipher::Aes(key))
            } else {
                Ok(Cipher::Chacha(key))
            }
        } else {
            Ok(Cipher::None)
        }
    }
}

impl ParamsProfile {
    pub fn params(&self) -> (u32, u32, u32) {
        match self {
            Self::Fast => (19_456, 2, 1),      // 19 MiB, ~0.1s
            Self::Balanced => (65_536, 3, 4),  // 64 MiB, ~0.5s
            Self::Paranoid => (262_144, 4, 4), // 256MiB, ~3.0s
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
            compression: compression,
            argon_salt: salt,
            argon_params: profile.params(),
            archive_id: archive_id,
            block_size: bs,
            nonce_base: nonce_base,
        }
    }
}

impl ArchiveWriter {
    pub fn new(arname: &str, h: Header) -> Result<ArchiveWriter, CryoErrors> {
        let archivename = if arname.ends_with("cryo") {
            arname.to_owned()
        } else {
            arname.to_owned() + ".cryo"
        };

        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .truncate(true)
            .create_new(true)
            .open(archivename)
            .map_err(|_| CryoErrors::InvalidPath)?;
        let mut writer = BufWriter::new(file);
        let index = Index {
            files: vec![],
            block: vec![],
            total_stream_size: 0u64,
        };
        let cipher = Cipher::new(&h)?;
        let header_bytes = rmp_serde::to_vec(&h).map_err(|_| CryoErrors::SerializationFailed)?;
        let header_bytes_len = header_bytes.len() as u32;
        let bytes_to_write = [
            header_bytes_len.to_le_bytes().as_slice(),
            header_bytes.as_slice(),
        ]
        .concat();

        writer
            .write_all(&bytes_to_write)
            .map_err(|_| CryoErrors::WriteError)?;

        Ok(ArchiveWriter {
            writer: writer,
            index: index,
            stream_position: 0,
            file_position: bytes_to_write.len() as u64,
            pending: vec![],
            cipher,

            header: h,
        })
    }
    pub fn feed(&mut self, data: &[u8]) -> Result<(), CryoErrors> {
        let mut input = data;
        while !input.is_empty() {
            let space = self.header.block_size as usize - self.pending.len();
            let take = space.min(input.len());
            self.pending.extend_from_slice(&input[..take]);
            self.stream_position += take as u64;
            input = &input[take..];

            if self.pending.len() >= self.header.block_size as usize {
                let block = std::mem::take(&mut self.pending);

                self.flush_block(&block)?;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), CryoErrors> {
        if !self.pending.is_empty() {
            let last_block = std::mem::take(&mut self.pending);
            self.flush_block(&last_block)?;
        }
        self.index.total_stream_size = self.stream_position;
        let index_bytes =
            rmp_serde::to_vec(&self.index).map_err(|_| CryoErrors::SerializationFailed)?;
        let compr_index_bytes = zstd::encode_all(index_bytes.as_slice(), self.header.compression)
            .map_err(|_| CryoErrors::CompressionError)?;
        let index_size_plain = index_bytes.len() as u32;
        let (smaller, index_compressed) = if index_size_plain as usize > compr_index_bytes.len() {
            (compr_index_bytes, true)
        } else {
            (index_bytes, false)
        };
        let encrypted_index = self.encrypt_block(&smaller, EncryptedData::Index)?;

        let footer = Footer {
            index_offset: self.file_position,
            index_size_stored: encrypted_index.len() as u32,
            index_size_plain,
            index_compressed,
        };
        self.writer
            .write_all(&encrypted_index)
            .map_err(|_| CryoErrors::WriteError)?;
        let footer_bytes = footer.serialize();
        self.writer
            .write_all(&footer_bytes)
            .map_err(|_| CryoErrors::WriteError)?;
        self.writer.flush().map_err(|_| CryoErrors::WriteError)?;
        Ok(())
    }

    fn flush_block(&mut self, raw_block: &[u8]) -> Result<(), CryoErrors> {
        let size_plain = raw_block.len() as u32;
        let block_compressed = zstd::encode_all(raw_block, self.header.compression)
            .map_err(|_| CryoErrors::CompressionError)?;

        let (payload, is_compressed): (&[u8], bool) = if block_compressed.len() < raw_block.len() {
            (&block_compressed, true)
        } else {
            (raw_block, false)
        };
        let enc_block = self.encrypt_block(payload, EncryptedData::Block)?;
        let size_stored = enc_block.len() as u32;

        self.writer
            .write_all(&enc_block)
            .map_err(|_| CryoErrors::WriteError)?;
        self.index.block.push(BlockEntry {
            offset: self.file_position,
            size_plain,
            size_stored,
            is_compressed,
            checksum: blake3::hash(&raw_block).into(),
        });
        self.file_position += enc_block.len() as u64;

        Ok(())
    }
    fn encrypt_block(&self, payload: &[u8], encd: EncryptedData) -> Result<Vec<u8>, CryoErrors> {
        let (nonce, aad) = match encd {
            EncryptedData::Block => {
                let block_num = self.index.block.len() as u64;
                let nonce = block_nonce(&self.header.nonce_base, block_num);
                let aad: Vec<u8> = [&block_num.to_le_bytes()[..], &self.header.archive_id].concat();
                (nonce, aad)
            }
            EncryptedData::Index => {
                let block_num = u64::MAX;
                let nonce = block_nonce(&self.header.nonce_base, block_num);
                let aad: Vec<u8> = [&"index".as_bytes()[..], &self.header.archive_id].concat();
                (nonce, aad)
            }
        };

        Ok(match self.cipher {
            Cipher::Aes(k) => {
                let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| {
                    CryoErrors::CryptographicError("AES initizalition failure".to_owned())
                })?;
                let aesnonce: aes_gcm::Nonce<_> = nonce.into();

                let ciphertext = cipher
                    .encrypt(
                        &aesnonce,
                        Payload {
                            msg: payload,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        CryoErrors::CryptographicError("AES encryption failure".to_owned())
                    })?;
                ciphertext.as_slice().to_owned()
            }
            Cipher::Chacha(k) => {
                let key = Key::from(k);
                let cipher = ChaCha20Poly1305::new(&key);
                let chachanonce: Nonce = nonce.into();
                let ciphertext = cipher
                    .encrypt(
                        &chachanonce,
                        Payload {
                            msg: payload,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        CryoErrors::CryptographicError("CHACHA encrypt failure".to_owned())
                    })?;
                ciphertext.as_slice().to_owned()
            }
            Cipher::None => payload.to_owned(),
        })
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
impl ArchiveReader {
    pub(crate) fn new(
        f: File,
        p: &PathBuf,
        out: PathBuf,
        limits: Limits,
    ) -> Result<Self, CryoErrors> {
        let structs = FileStructs::retrieve(&f, p, &limits)?;
        let reader = BufReader::new(f);

        Ok(ArchiveReader {
            root: out,
            reader,
            header: structs.header,
            cipher: structs.cipher,
            index: structs.index,
            limits,
        })
    }
    pub(crate) fn handle_files(
        &mut self,
        mp: Option<&MultiProgress>,
        pb_files: Option<&ProgressBar>,
    ) -> Result<(), CryoErrors> {
        let files = self.index.files.clone();
        event!(Level::DEBUG, count = files.len(), "extracting files");

        let pb_file_style = ProgressStyle::with_template(
            "  [{bar:40.blue/dim}] {percent:>3}%  {bytes}/{total_bytes}  {msg}",
        )
        .unwrap()
        .progress_chars("=>-");
        fs::create_dir_all(&self.root).map_err(|_| CryoErrors::WriteError)?;

        for f in &files {
            let name = f
                .path
                .file_name()
                .unwrap_or(f.path.as_os_str())
                .to_string_lossy()
                .into_owned();
            if let Some(pb) = pb_files {
                pb.set_message(name.clone());
            }
            event!(
                Level::DEBUG,
                path = %f.path.display(),
                ftype = ?f.ftype,
                size = f.size,
                "extracting entry"
            );

            let pb_file = if let (Some(mp), Some(pb_outer)) = (mp, pb_files) {
                if f.size > 0 && matches!(f.ftype, FileType::File) {
                    let pb = mp.insert_after(pb_outer, ProgressBar::new(f.size));
                    pb.set_style(pb_file_style.clone());
                    pb.set_message(name);
                    pb.enable_steady_tick(std::time::Duration::from_millis(100));
                    Some(pb)
                } else {
                    None
                }
            } else {
                None
            };
            let out_dir = safe_output_path(&self.root, f.path.as_path())?;
            let blocks = build_block_ranges(&self.index.block.as_slice());
            self.extract_file(f, out_dir.as_path(), &blocks, pb_file.as_ref())?;

            if let Some(pb) = pb_file {
                pb.finish_and_clear();
            }
            if let Some(pb) = pb_files {
                pb.inc(1);
            }
        }
        Ok(())
    }

    pub(crate) fn extract_file(
        &mut self,
        f: &FileEntry,
        out_dir: &Path,
        blocks: &[(u64, u64)],
        pb: Option<&ProgressBar>,
    ) -> Result<(), CryoErrors> {
        let eff_max_file = if self.limits.max_file_size == 0 {
            MAX_FILE_SIZE
        } else {
            self.limits.max_file_size
        };
        if f.size > eff_max_file {
            return Err(CryoErrors::FileTooLarge {
                size: f.size,
                limit: eff_max_file,
            });
        }
        let file_start = f.stream_offset;
        let file_end = file_start + f.size;
        if let Some(parent) = out_dir.parent() {
            fs::create_dir_all(parent).map_err(|_| CryoErrors::WriteError)?;
        }

        if matches!(f.ftype, FileType::Dir) {
            return fs::create_dir_all(out_dir).map_err(|_| CryoErrors::WriteError);
        }
        if matches!(f.ftype, FileType::Symlink) {
            let target = f.symlink_target.as_ref().ok_or(CryoErrors::WriteError)?;
            let link_dir = out_dir.parent().unwrap_or(Path::new(""));
            let resolved = normalize(&link_dir.join(target));
            let canonical_root = self
                .root
                .canonicalize()
                .map_err(|_| CryoErrors::InvalidPath)?;
            if !resolved.starts_with(&canonical_root) {
                return Err(CryoErrors::UnsafePath(target.clone()));
            }

            #[cfg(unix)]
            std::os::unix::fs::symlink(target, out_dir).map_err(|_| CryoErrors::WriteError)?;
            return Ok(());
        }
        let mut writer = File::create(&out_dir).map_err(|_| CryoErrors::WriteError)?;
        let system_time = UNIX_EPOCH + Duration::from_secs(f.timestamp);
        let first = blocks.partition_point(|(_, end)| *end <= file_start);

        event!(
            Level::DEBUG,
            path = %f.path.display(),
            file_start,
            file_end,
            first_block = first,
            total_blocks = blocks.len(),
            "extract filter"
        );

        for i in first..blocks.len() {
            let block = self.index.block[i].clone();
            let (start, end) = blocks[i];
            if end <= file_start || start >= file_end {
                event!(
                    Level::DEBUG,
                    block = i,
                    block_start = start,
                    block_end = end,
                    file_start,
                    file_end,
                    reason = if end <= file_start {
                        "block before file"
                    } else {
                        "block past file"
                    },
                    "block loop break"
                );
                break;
            }
            let take_start = file_start.saturating_sub(start) as usize;
            let take_end = (file_end.min(end) - start) as usize;
            event!(
                Level::DEBUG,
                block = i,
                block_start = start,
                block_end = end,
                take_start,
                take_end,
                bytes = take_end - take_start,
                "reading block slice"
            );
            let plain = self.read_block(&block, i)?;
            let calc_checksum = blake3::hash(&plain);
            if *calc_checksum.as_bytes() != block.checksum {
                return Err(CryoErrors::DecompressionError);
            }
            writer
                .write_all(&plain[take_start..take_end])
                .map_err(|_| CryoErrors::WriteError)?;
            if let Some(pb) = pb {
                pb.inc((take_end - take_start) as u64);
            }
        }

        match f.ftype {
            FileType::Dir | FileType::File => {
                fs::set_permissions(out_dir, Permissions::from_mode(f.permissions))
                    .map_err(|_| CryoErrors::WriteError)?;
            }
            FileType::Symlink => {}
        }

        writer
            .set_modified(system_time)
            .map_err(|_| CryoErrors::WriteError)?;
        Ok(())
    }
    pub(crate) fn read_block(
        &mut self,
        block: &BlockEntry,
        block_num: usize,
    ) -> Result<Vec<u8>, CryoErrors> {
        if block.size_plain as u64 > self.header.block_size {
            return Err(CryoErrors::BlockTooLarge {
                size: block.size_plain as u64,
                limit: self.header.block_size,
            });
        }
        self.reader
            .seek(SeekFrom::Start(block.offset))
            .map_err(|e| CryoErrors::ReadFailed {
                p: PathBuf::from("./"),
                source: e,
            })?;
        let mut stored = vec![0u8; block.size_stored as usize];
        self.reader
            .read_exact(&mut stored)
            .map_err(|e| CryoErrors::ReadFailed {
                p: PathBuf::from("./"),
                source: e,
            })?;
        let decrypted = if !matches!(self.cipher, Cipher::None) {
            decrypt_block(
                EncryptedData::Block,
                &self.cipher,
                &self.header,
                &stored,
                block_num,
            )?
        } else {
            stored
        };
        let plain = if block.is_compressed {
            let mut decoder = zstd::Decoder::new(decrypted.as_slice())
                .map_err(|_| CryoErrors::DecompressionError)?;
            let mut out = Vec::with_capacity(block.size_plain as usize);
            let mut buf = [0u8; 8192];
            let mut total = 0u64;
            loop {
                let n = decoder
                    .read(&mut buf)
                    .map_err(|_| CryoErrors::DecompressionError)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > self.header.block_size {
                    return Err(CryoErrors::BlockTooLarge {
                        size: total,
                        limit: self.header.block_size,
                    });
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        } else {
            decrypted
        };
        Ok(plain)
    }
    pub(crate) fn verify(&mut self, p: &PathBuf) -> Result<(), CryoErrors> {
        let blocks: Vec<BlockEntry> = self.index.block.clone();
        for (i, block) in blocks.iter().enumerate() {
            self.reader
                .seek(SeekFrom::Start(block.offset))
                .map_err(|e| CryoErrors::ReadFailed {
                    p: p.clone(),
                    source: e,
                })?;
            let mut stored = vec![0u8; block.size_stored as usize];
            self.reader
                .read_exact(&mut stored)
                .map_err(|e| CryoErrors::ReadFailed {
                    p: p.clone(),
                    source: e,
                })?;

            let decrypted =
                decrypt_block(EncryptedData::Block, &self.cipher, &self.header, &stored, i)?;

            let plain = if block.is_compressed {
                decompress_block(decrypted, &self.header, self.limits.max_block_size)?
            } else {
                decrypted
            };

            let calc = blake3::hash(&plain);
            if calc.as_bytes() != &block.checksum {
                return Err(CryoErrors::ChecksumMismatch);
            }
        }
        Ok(())
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

fn is_safe_path(p: &Path) -> bool {
    for component in p.components() {
        match component {
            Component::ParentDir => return false,
            Component::RootDir => return false,
            Component::Prefix(_) => return false,
            Component::Normal(_) => {}
            Component::CurDir => {}
        }
    }
    true
}

fn safe_output_path(root: &Path, relative: &Path) -> Result<PathBuf, CryoErrors> {
    if !is_safe_path(relative) {
        return Err(CryoErrors::UnsafePath(relative.to_path_buf().clone()));
    }

    let joined = root.join(relative);

    let canonical_root = root.canonicalize().map_err(|_| CryoErrors::InvalidPath)?;

    if let Some(parent) = joined.parent() {
        std::fs::create_dir_all(parent).map_err(|_| CryoErrors::WriteError)?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| CryoErrors::UnsafePath(canonical_root.clone()))?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err(CryoErrors::UnsafePath(relative.to_path_buf().clone()));
        }
    }

    Ok(joined)
}
fn normalize(path: &PathBuf) -> PathBuf {
    let mut stack: Vec<Component> = Vec::new();
    path.components().for_each(|c| match c {
        Component::Normal(_) => stack.push(c),
        Component::ParentDir => match stack.last() {
            Some(Component::Normal(_)) => {
                stack.pop();
            }
            _ => stack.push(c),
        },
        Component::CurDir => {}
        Component::RootDir => stack.push(c),
        Component::Prefix(_) => stack.push(c),
    });
    stack.iter().collect()
}

// Converts a slice of block metadata into stream offset ranges [start, end).
// The ranges are contiguous: end of block N == start of block N+1.
// Used to binary-search which blocks overlap a given file's byte range.
pub(crate) fn build_block_ranges(blocks: &[BlockEntry]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(blocks.len());
    let mut streampos = 0u64;

    for block in blocks {
        let start = streampos;
        let end = start + block.size_plain as u64;

        out.push((start, end));
        streampos = end;
    }
    out
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
    fn build_block_ranges_empty() {
        assert!(build_block_ranges(&[]).is_empty());
    }

    #[test]
    fn build_block_ranges_single() {
        let ranges = build_block_ranges(&[make_block(100, 80)]);
        assert_eq!(ranges, vec![(0, 100)]);
    }

    #[test]
    fn build_block_ranges_contiguous() {
        let blocks = [
            make_block(100, 80),
            make_block(200, 150),
            make_block(50, 50),
        ];
        let ranges = build_block_ranges(&blocks);
        assert_eq!(ranges, vec![(0, 100), (100, 300), (300, 350)]);
    }

    #[test]
    fn build_block_ranges_no_gaps() {
        let blocks = [make_block(64, 40), make_block(64, 60), make_block(64, 30)];
        let ranges = build_block_ranges(&blocks);
        for i in 1..ranges.len() {
            assert_eq!(ranges[i - 1].1, ranges[i].0);
        }
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

    #[test]
    fn is_safe_path_normal_relative() {
        assert!(is_safe_path(Path::new("a/b/c")));
    }

    #[test]
    fn is_safe_path_rejects_parent_traversal() {
        assert!(!is_safe_path(Path::new("a/../b")));
    }

    #[test]
    fn is_safe_path_rejects_absolute() {
        assert!(!is_safe_path(Path::new("/etc/passwd")));
    }

    #[test]
    fn is_safe_path_single_component() {
        assert!(is_safe_path(Path::new("file.txt")));
    }

    #[test]
    fn block_filter_finds_first_overlapping_block() {
        let blocks = [
            make_block(100, 80),
            make_block(100, 60),
            make_block(100, 50),
        ];
        let ranges = build_block_ranges(&blocks);
        // file starts at byte 150, which is inside block 1 (100..200)
        let first = ranges.partition_point(|(_, end)| *end <= 150);
        assert_eq!(first, 1);
    }

    #[test]
    fn block_filter_file_at_exact_block_boundary() {
        let blocks = [make_block(100, 80), make_block(100, 60)];
        let ranges = build_block_ranges(&blocks);
        let first = ranges.partition_point(|(_, end)| *end <= 100);
        assert_eq!(first, 1);
    }

    #[test]
    fn block_filter_file_at_start() {
        let blocks = [make_block(100, 80), make_block(100, 60)];
        let ranges = build_block_ranges(&blocks);
        let first = ranges.partition_point(|(_, end)| *end <= 0);
        assert_eq!(first, 0);
    }

    #[test]
    fn block_filter_file_in_last_block() {
        let blocks = [
            make_block(100, 80),
            make_block(100, 60),
            make_block(100, 40),
        ];
        let ranges = build_block_ranges(&blocks);
        let first = ranges.partition_point(|(_, end)| *end <= 250);
        assert_eq!(first, 2);
    }
}
