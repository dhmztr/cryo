use crate::errors::CryoErrors;
use crate::format::{EncryptedData, EncryptionType, Header};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{Argon2, Params};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::io::Read;
use zstd::Decoder;

pub(crate) fn block_nonce(base: &[u8; 12], block_num: u64) -> [u8; 12] {
    let mut nonce = *base;
    let counter = block_num.to_le_bytes();
    for i in 0..8 {
        nonce[i] ^= counter[i];
    }
    nonce
}

#[derive(Clone, Copy)]
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
            let arg2 = Argon2::new(
                crate::consts::ARGON2ALGO,
                crate::consts::ARGON2VERSION,
                params,
            );
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

pub fn encrypt_block(
    block_id: u64,
    nonce_base: &[u8; 12],
    payload: &[u8],
    encd: EncryptedData,
    archive_id: &[u8; 16],
    cipher: Cipher,
) -> Result<Vec<u8>, CryoErrors> {
    let (nonce, aad) = match encd {
        EncryptedData::Block => {
            let block_num = block_id;
            let nonce = block_nonce(nonce_base, block_num);
            let mut aad = [0u8; 24];
            aad[..8].copy_from_slice(&block_num.to_le_bytes());
            aad[8..].copy_from_slice(archive_id);

            (nonce, aad)
        }
        EncryptedData::Index => {
            let block_num = u64::MAX;
            let nonce = block_nonce(nonce_base, block_num);
            let mut aad = [0u8; 24];
            aad[..8].copy_from_slice(&block_num.to_le_bytes());
            aad[8..].copy_from_slice(archive_id);
            (nonce, aad)
        }
    };

    Ok(match cipher {
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
                .map_err(|_| CryoErrors::CryptographicError("AES encryption failure".to_owned()))?;
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
                .map_err(|_| CryoErrors::CryptographicError("CHACHA encrypt failure".to_owned()))?;
            ciphertext.as_slice().to_owned()
        }
        Cipher::None => payload.to_owned(),
    })
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
                let mut aad = [0u8; 24];
                aad[..8].copy_from_slice(&block_num.to_le_bytes());
                aad[8..].copy_from_slice(&h.archive_id);
                (nonce, aad)
            }
            EncryptedData::Block => {
                let nonce = block_nonce(&h.nonce_base, block_num as u64);
                let mut aad = [0u8; 24];
                aad[..8].copy_from_slice(&block_num.to_le_bytes());
                aad[8..].copy_from_slice(&h.archive_id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_counter_leaves_nonce_unchanged() {
        let base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert_eq!(block_nonce(&base, 0), base);
    }

    #[test]
    fn counter_one_flips_first_byte_only() {
        let base = [0u8; 12];
        let nonce = block_nonce(&base, 1);
        assert_eq!(nonce[0], 1);
        assert_eq!(&nonce[1..], &[0u8; 11]);
    }

    #[test]
    fn different_counters_produce_different_nonces() {
        let base = [0xAAu8; 12];
        assert_ne!(block_nonce(&base, 1), block_nonce(&base, 2));
        assert_ne!(block_nonce(&base, 0), block_nonce(&base, 1));
    }

    #[test]
    fn high_bytes_of_nonce_unchanged_by_counter() {
        let base = [0u8; 12];
        let nonce = block_nonce(&base, u64::MAX);
        assert_eq!(&nonce[8..], &[0u8; 4]);
    }

    #[test]
    fn index_sentinel_differs_from_block_zero() {
        let base = [0x55u8; 12];
        assert_ne!(block_nonce(&base, u64::MAX), block_nonce(&base, 0));
    }

    #[test]
    fn nonce_is_deterministic() {
        let base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert_eq!(block_nonce(&base, 42), block_nonce(&base, 42));
    }
}
