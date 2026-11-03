mod text;

use cipher::{Block, BlockCipherDecBackend, BlockCipherEncBackend, InOut};
use des::{Des};
use des::cipher::{KeyInit};
use crate::errors::Errors;

fn pkcs7(plaintext: &mut Vec<u8>) {
    let padding = 8 - plaintext.len() % 8;
    plaintext.extend(vec![padding as u8; padding]);
}

fn encrypt_des(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, Errors> {
    let des = Des::new_from_slice(key)
        .map_err(|_| "Неверная длина ключа. Для DES нужно ровно 8 байт.")?;

    let mut data = plaintext.to_vec();
    pkcs7(&mut data);

    for chunk in data.chunks_exact_mut(8) {
        let mut block = Block::<Des>::clone_from_slice(chunk);

        des.encrypt_block(InOut::from(&mut block));

        chunk.copy_from_slice(&block);
    }

    Ok(data)
}

fn decrypt_des(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, Errors> {
    let des = Des::new_from_slice(key)
        .map_err(|_| "Неверная длина ключа. Для DES нужно ровно 8 байт.")?;

    let mut data = encrypted.to_vec();

    for chunk in data.chunks_exact_mut(8) {
        let mut block = Block::<Des>::clone_from_slice(chunk);

        des.decrypt_block(InOut::from(&mut block));

        chunk.copy_from_slice(&block);
    }

    let padding = *data.last().unwrap() as usize;

    if padding == 0 || padding > 8 {
        return Err("Некорректный padding".into());
    }

    if !data[data.len() - padding..]
        .iter()
        .all(|&byte| byte as usize == padding)
    {
        return Err("Некорректный padding".into());
    }

    data.truncate(data.len() - padding);

    Ok(data)
}


pub mod keygen {
    use crate::errors::Errors;

    pub fn des_keygen() -> Result<[u8; 64], Errors> {
        let mut key = [0u8; 64];
        getrandom::fill(&mut key)?;
        Ok(key)
    }

    pub fn triple_des_keygen() -> Result<[u8; 192], Errors> {
        let mut key = [0u8; 192];
        getrandom::fill(&mut key)?;
        Ok(key)
    }
}


pub mod triple_des_ecb {
    use super::*;

    pub struct TripleDesEcb;

    impl TripleDesEcb {
        pub fn new() -> TripleDesEcb {
            TripleDesEcb
        }

        pub fn encrypt(&self,
                       plaintext: &[u8],
                       key: &[u8]) -> Result<Vec<u8>, Errors> {
            let key1 = &key[..64];
            let key2 = &key[64..128];
            let key3 = &key[128..192];

            let mut cipher_text = encrypt_des(plaintext, key1)?;
            cipher_text = decrypt_des(&cipher_text, key2)?;
            cipher_text = encrypt_des(&cipher_text, key3)?;

            Ok(cipher_text)
        }

        pub fn decrypt(&self,
                       cipher_text: &[u8],
                       key: &[u8]) -> Result<Vec<u8>, Errors> {
            let key1 = &key[..64];
            let key2 = &key[64..128];
            let key3 = &key[128..192];

            let mut cipher_text = decrypt_des(cipher_text, key3)?;
            cipher_text = encrypt_des(&cipher_text, key2)?;
            let plaintext = decrypt_des(&cipher_text, key1)?;

            Ok(plaintext)
        }
    }
}

pub mod triple_des_cbc {
    use super::*;
    use crate::crypto::triple_des_ecb::TripleDesEcb;

    pub struct TripleDesCbcInner;
    pub struct TripleDesCbcOuter;

    impl TripleDesCbcInner {
        pub fn new() -> TripleDesCbcInner {
            TripleDesCbcInner
        }


        pub fn encrypt(
            &self,
            plaintext: &[u8],
            key: &[u8],
            iv: &[u8],
        ) -> Result<Vec<u8>, Errors> {
            if iv.len() != 8 {
                return Err("IV должен содержать 8 байт".into());
            }

            let triple_des_ecb = TripleDesEcb::new();

            let mut data = plaintext.to_vec();
            pkcs7(&mut data);

            let mut previous = iv.to_vec();

            for chunk in data.chunks_exact_mut(8) {
                for (a, b) in chunk.iter_mut().zip(previous.iter()) {
                    *a ^= *b;
                }

                let cipher_chunk = triple_des_ecb.encrypt(chunk, key)?;

                if cipher_chunk.len() != 8 {
                    return Err("Ожидался блок длиной 8 байт".into());
                }

                previous.copy_from_slice(&cipher_chunk);

                chunk.copy_from_slice(&cipher_chunk);
            }

            Ok(data)
        }


        pub fn decrypt(&self,
                       ciphertext: &[u8],
                       key: &[u8],
                       iv: &[u8]) -> Result<Vec<u8>, Errors> {
            todo!()
        }
    }

    impl TripleDesCbcOuter {
        pub fn new() -> TripleDesCbcOuter {
            TripleDesCbcOuter
        }
    }
}
