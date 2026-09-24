use crate::errors::CryoErrors;
use crate::format::{EncryptedData, EncryptionType, Header};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{Argon2, Params};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::ZeroizeOnDrop;

#[derive(Clone, ZeroizeOnDrop)]
pub enum Cipher {
    None,
    Aes([u8; 32]),
    Chacha([u8; 32]),
}

impl Cipher {
    pub fn new(h: &Header, confirm: bool) -> Result<Self, CryoErrors> {
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
            let first_password =
                prompt_for_password("Please provide password for encrypted archive")?;
            if confirm {
                let repeated_password = prompt_for_password("Please provide the password again")?;
                if first_password != repeated_password {
                    return Err(CryoErrors::CryptographicError(
                        "Passwords don't match".into(),
                    ));
                }
            }
            let mut key: [u8; 32] = [0u8; 32];
            arg2.hash_password_into(first_password.as_bytes(), &h.argon_salt, &mut key)
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
    payload: &[u8],
    encd: EncryptedData,
    archive_id: &[u8; 16],
    cipher: &Cipher,
) -> Result<Vec<u8>, CryoErrors> {
    let (nonce, aad) = match encd {
        EncryptedData::Block(nonce) => {
            let block_num = block_id;
            let mut aad = [0u8; 24];
            aad[..8].copy_from_slice(&block_num.to_le_bytes());
            aad[8..].copy_from_slice(archive_id);

            (nonce, aad)
        }
        EncryptedData::Index(nonce) => {
            let block_num = u64::MAX;
            let mut aad = [0u8; 24];
            aad[..8].copy_from_slice(&block_num.to_le_bytes());
            aad[8..].copy_from_slice(archive_id);
            (nonce, aad)
        }
    };

    Ok(match cipher {
        Cipher::Aes(k) => {
            let cipher = Aes256Gcm::new_from_slice(k).map_err(|_| {
                CryoErrors::CryptographicError("AES initialization failure".to_owned())
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
            let key = Key::from(*k);
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
    block_num: u64,
) -> Result<Vec<u8>, CryoErrors> {
    if !matches!(c, Cipher::None) {
        let (nonce, aad) = match encd {
            EncryptedData::Index(nonce) => {
                let block_num: u64 = u64::MAX;
                let mut aad = [0u8; 24];
                aad[..8].copy_from_slice(&block_num.to_le_bytes());
                aad[8..].copy_from_slice(&h.archive_id);
                (nonce, aad)
            }
            EncryptedData::Block(nonce) => {
                let mut aad = [0u8; 24];
                aad[..8].copy_from_slice(&block_num.to_le_bytes());
                aad[8..].copy_from_slice(&h.archive_id);
                (nonce, aad)
            }
        };
        match c {
            Cipher::Aes(key) => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
                    CryoErrors::CryptographicError("AES initialization failure".to_owned())
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
                        CryoErrors::CryptographicError("AES decryption failure".to_owned())
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
fn prompt_for_password(prompt: &str) -> Result<String, CryoErrors> {
    let passwd_config = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();
    rpassword::prompt_password_with_config(prompt, passwd_config)
        .map_err(|_| CryoErrors::CryptographicError("Failed to read password".to_owned()))
}
