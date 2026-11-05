use crate::errors::Errors;
use crate::text::{Key, Text};
use cipher::{Block, BlockCipherDecBackend, BlockCipherEncBackend, InOut};
use des::Des;
use des::cipher::KeyInit;

fn encrypt_des(mut plaintext: Text, key: Key) -> Result<Text, Errors> {
    let des = Des::new_from_slice(key.get_key())
        .map_err(|_| "Неверная длина ключа. Для DES нужно ровно 8 байт.")?;

    for chunk in plaintext.get_mut_data() {
        let mut des_block = Block::<Des>::clone_from_slice(chunk.get_data());
        BlockCipherEncBackend::encrypt_block(&des, InOut::from(&mut des_block));
        chunk.get_mut_data().copy_from_slice(&des_block);
    }

    Ok(plaintext)
}

fn decrypt_des(mut ciphertext: Text, key: Key) -> Result<Text, Errors> {
    let des = Des::new_from_slice(key.get_key())
        .map_err(|_| "Неверная длина ключа. Для DES нужно ровно 8 байт.")?;

    for chunk in ciphertext.get_mut_data() {
        let mut des_block = Block::<Des>::clone_from_slice(chunk.get_data());
        BlockCipherDecBackend::decrypt_block(&des, InOut::from(&mut des_block));
        chunk.get_mut_data().copy_from_slice(&des_block);
    }

    Ok(ciphertext)
}

fn validate_text_len(text: &Text) -> bool {
    text.get_data().is_empty()
        || text
        .get_data()
        .iter()
        .any(|block| block.get_data().len() != 8)
}

pub mod keygen {
    use super::*;

    fn keygen(size: usize) -> Result<Key, Errors> {
        let mut key = vec![0u8; size];
        getrandom::fill(&mut key)?;
        Ok(Key::new(key.to_vec()))
    }

    pub fn des_keygen() -> Result<Key, Errors> {
        keygen(8)
    }

    pub fn triple_des_keygen() -> Result<Key, Errors> {
        keygen(24)
    }
}

pub mod triple_des_ecb {
    use super::*;

    pub struct TripleDesEcb;

    impl TripleDesEcb {
        pub fn new() -> TripleDesEcb {
            TripleDesEcb
        }

        pub fn encrypt(&self, mut plaintext: Text, key: Key) -> Result<Text, Errors> {
            if key.get_key().len() != 24 {
                return Err("Для Triple DES нужен ключ длиной 24 байта".into());
            }
            let (key1, key2, key3) = key.split_key();

            plaintext.fill_block();
            if plaintext
                .get_data()
                .iter()
                .any(|block| block.get_data().len() != 8)
            {
                return Err("Текст должен состоять из блоков по 8 байт".into());
            }

            let mut cipher_text = encrypt_des(plaintext, key1)?;
            cipher_text = decrypt_des(cipher_text, key2)?;
            cipher_text = encrypt_des(cipher_text, key3)?;

            Ok(cipher_text)
        }

        pub fn decrypt(&self, cipher_text: Text, key: Key) -> Result<Text, Errors> {
            if key.get_key().len() != 24 {
                return Err("Для Triple DES нужен ключ длиной 24 байта".into());
            }
            let (key1, key2, key3) = key.split_key();
            if validate_text_len(&cipher_text) {
                return Err("Шифртекст должен состоять из полных блоков по 8 байт".into());
            }

            let mut cipher_text = decrypt_des(cipher_text, key3)?;
            cipher_text = encrypt_des(cipher_text, key2)?;
            let plaintext = decrypt_des(cipher_text, key1)?;

            remove_padding(plaintext)
        }


    }

    pub fn remove_padding(plaintext: Text) -> Result<Text, Errors> {
        let mut data: Vec<u8> = plaintext
            .get_data()
            .iter()
            .flat_map(|block| block.get_data().iter().copied())
            .collect();
        let padding = *data.last().ok_or("Пустой шифртекст")? as usize;
        if !(1..=8).contains(&padding)
            || !data[data.len() - padding..]
                .iter()
                .all(|&byte| byte as usize == padding)
        {
            return Err("Некорректный padding".into());
        }
        data.truncate(data.len() - padding);
        Ok(Text::from(data))
    }

    pub(super) fn encrypt_block(block: &[u8; 8], key: &Key) -> Result<[u8; 8], Errors> {
        if key.get_key().len() != 24 {
            return Err("Для Triple DES нужен ключ длиной 24 байта".into());
        }
        let (key1, key2, key3) = key.split_key();
        let text = encrypt_des(Text::from(block.to_vec()), key1)?;
        let text = decrypt_des(text, key2)?;
        let text = encrypt_des(text, key3)?;

        let mut encrypted = [0u8; 8];
        encrypted.copy_from_slice(text.get_data()[0].get_data());
        Ok(encrypted)
    }

    pub(super) fn decrypt_block(block: &[u8; 8], key: &Key) -> Result<[u8; 8], Errors> {
        if key.get_key().len() != 24 {
            return Err("Для Triple DES нужен ключ длиной 24 байта".into());
        }
        let (key1, key2, key3) = key.split_key();
        let text = decrypt_des(Text::from(block.to_vec()), key3)?;
        let text = encrypt_des(text, key2)?;
        let text = decrypt_des(text, key1)?;

        let mut decrypted = [0u8; 8];
        decrypted.copy_from_slice(text.get_data()[0].get_data());
        Ok(decrypted)
    }
}

pub mod triple_des_cbc {
    use super::*;
    use crate::crypto::triple_des_ecb;
    use crate::text::IV;
    use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

    pub struct TripleDesCbcInner;
    pub struct TripleDesCbcOuter;

    impl TripleDesCbcInner {
        pub fn new() -> TripleDesCbcInner {
            TripleDesCbcInner
        }

        pub fn encrypt(&self, mut plaintext: Text, key: Key, iv: IV) -> Result<Text, Errors> {
            if key.get_key().len() != 24 {
                return Err("Для Triple DES нужен ключ длиной 24 байта".into());
            }
            plaintext.fill_block();
            if plaintext
                .get_data()
                .iter()
                .any(|block| block.get_data().len() != 8)
            {
                return Err("Текст должен состоять из блоков по 8 байт".into());
            }
            let mut previous: [u8; 8] = iv
                .get_iv()
                .as_slice()
                .try_into()
                .map_err(|_| "IV должен содержать 8 байт")?;

            for block in plaintext.get_mut_data() {
                let mut xor_block = [0u8; 8];
                for (i, byte) in block.get_data().iter().enumerate() {
                    xor_block[i] = byte ^ previous[i];
                }
                let encrypted = triple_des_ecb::encrypt_block(&xor_block, &key)?;
                block.get_mut_data().copy_from_slice(&encrypted);
                previous = encrypted;
            }

            Ok(plaintext)
        }

        pub fn decrypt(&self, mut ciphertext: Text, key: Key, iv: IV) -> Result<Text, Errors> {
            if key.get_key().len() != 24 {
                return Err("Для Triple DES нужен ключ длиной 24 байта".into());
            }

            if validate_text_len(&ciphertext) {
                return Err("Шифртекст должен состоять из полных блоков по 8 байт".into());
            }

            let blocks: Vec<[u8; 8]> = ciphertext
                .get_data()
                .iter()
                .map(|block| block.get_data().as_slice().try_into().unwrap())
                .collect();

            let decrypted: Vec<[u8; 8]> = blocks
                .par_iter()
                .map(|block| {
                    triple_des_ecb::decrypt_block(block, &key).map_err(|error| error.to_string())
                })
                .collect::<Result<_, String>>()
                .map_err(|error| -> Errors { error.into() })?;

            let iv_block: [u8; 8] = iv
                .get_iv()
                .as_slice()
                .try_into()
                .map_err(|_| "IV должен содержать 8 байт")?;

            for (i, block) in ciphertext.get_mut_data().iter_mut().enumerate() {
                let previous = if i == 0 { &iv_block } else { &blocks[i - 1] };
                let mut plain = decrypted[i];

                for j in 0..8 {
                    plain[j] ^= previous[j];
                }

                block.get_mut_data().copy_from_slice(&plain);
            }

            triple_des_ecb::remove_padding(ciphertext)
        }
    }

    impl TripleDesCbcOuter {
        pub fn new() -> TripleDesCbcOuter {
            TripleDesCbcOuter
        }
    }
}
