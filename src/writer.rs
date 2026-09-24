use crate::codec::Cipher;
use crate::engine::CompressingEngine;
use crate::errors::CryoErrors;
use crate::format::{EncryptedData, FileEntry, Footer, Header, Index};
use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};

pub struct RawBlock {
    pub id: u64,
    pub raw_data: Vec<u8>,
}
pub struct ProcessedBlock {
    pub id: u64,
    pub processed_data: Vec<u8>,
    pub size_plain: u32,
    pub is_compressed: bool,
    pub nonce: [u8; 12],
    pub checksum: [u8; 32],
}
pub enum WriterMessage {
    Block(ProcessedBlock),
    Finalize {
        files: Vec<FileEntry>,
        total_stream_size: u64,
    },
}
pub struct ArchiveWriter {
    pub writer: BufWriter<File>,
    pub index: Index,
    pub stream_position: u64,
    pub file_position: u64,
    pub(crate) cipher: Cipher,
    pub(crate) header: Header,
}

pub fn archive_filename(arname: &str) -> String {
    if arname.ends_with("cryo") {
        arname.to_owned()
    } else {
        arname.to_owned() + ".cryo"
    }
}

impl ArchiveWriter {
    pub fn new(arname: &str, h: Header, confirm: bool) -> Result<ArchiveWriter, CryoErrors> {
        let archivename = archive_filename(arname);

        let cipher = Cipher::new(&h, confirm)?;
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(archivename)
            .map_err(|_| CryoErrors::InvalidPath)?;
        let mut writer = BufWriter::new(file);
        let index = Index {
            files: vec![],
            block: vec![],
            total_stream_size: 0u64,
        };
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
            writer,
            index,
            stream_position: 0,
            file_position: bytes_to_write.len() as u64,
            cipher,

            header: h,
        })
    }

    pub(crate) fn finish(&mut self) -> Result<(), CryoErrors> {
        self.index.total_stream_size = self.stream_position;
        let index_bytes =
            rmp_serde::to_vec(&self.index).map_err(|_| CryoErrors::SerializationFailed)?;
        let mut engine =
            CompressingEngine::new(&self.header.compression, self.header.compression_level)?;
        let compr_index_bytes = engine.engine.compress(index_bytes.as_slice())?;
        let index_size_plain = index_bytes.len() as u32;
        let (smaller, index_compressed) = if index_size_plain as usize > compr_index_bytes.len() {
            (compr_index_bytes, true)
        } else {
            (index_bytes, false)
        };
        let mut index_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut index_nonce);
        let encrypted_index = self.encrypt_block(&smaller, EncryptedData::Index(index_nonce))?;

        let footer = Footer {
            index_offset: self.file_position,
            index_size_stored: encrypted_index.len() as u32,
            index_size_plain,
            index_compressed,
            index_nonce,
        };
        self.writer
            .write_all(&encrypted_index)
            .map_err(|_| CryoErrors::WriteError)?;
        let footer_bytes = footer.serialize();
        self.writer
            .write_all(&footer_bytes)
            .map_err(|_| CryoErrors::WriteError)?;
        self.writer.flush().map_err(|_| CryoErrors::WriteError)?;
        let final_len =
            self.file_position + encrypted_index.len() as u64 + footer_bytes.len() as u64;
        self.writer
            .get_ref()
            .set_len(final_len)
            .map_err(|_| CryoErrors::WriteError)?;
        Ok(())
    }

    fn encrypt_block(&self, payload: &[u8], encd: EncryptedData) -> Result<Vec<u8>, CryoErrors> {
        let (nonce, aad) = match encd {
            EncryptedData::Block(nonce) => {
                let block_num = self.index.block.len() as u64;
                let mut aad = [0u8; 24];
                aad[..8].copy_from_slice(&block_num.to_le_bytes());
                aad[8..].copy_from_slice(&self.header.archive_id);

                (nonce, aad)
            }
            EncryptedData::Index(nonce) => {
                let block_num = u64::MAX;
                let mut aad = [0u8; 24];
                aad[..8].copy_from_slice(&block_num.to_le_bytes());
                aad[8..].copy_from_slice(&self.header.archive_id);
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
