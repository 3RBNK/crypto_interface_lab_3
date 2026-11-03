use cipher::{Block, BlockCipherDecBackend, BlockCipherEncBackend, BlockCipherEncrypt, InOut};
use des::Des;
use des::cipher::KeyInit;
use crate::errors::Errors;
use crate::text::{Text, Key};


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

        pub fn encrypt(&self,
                       mut plaintext: Text,
                       key: Key) -> Result<Text, Errors> {
            if key.get_key().len() != 24 {
                return Err("Для Triple DES нужен ключ длиной 24 байта".into());
            }
            let (key1, key2, key3) = key.split_key();

            plaintext.fill_block();
            if plaintext.get_data().iter().any(|block| block.get_data().len() != 8) {
                return Err("Текст должен состоять из блоков по 8 байт".into());
            }

            let mut cipher_text = encrypt_des(plaintext, key1)?;
            cipher_text = decrypt_des(cipher_text, key2)?;
            cipher_text = encrypt_des(cipher_text, key3)?;

            Ok(cipher_text)
        }

        pub fn decrypt(&self,
                       cipher_text: Text,
                       key: Key) -> Result<Text, Errors> {
            if key.get_key().len() != 24 {
                return Err("Для Triple DES нужен ключ длиной 24 байта".into());
            }
            let (key1, key2, key3) = key.split_key();
            if cipher_text.get_data().is_empty()
                || cipher_text.get_data().iter().any(|block| block.get_data().len() != 8)
            {
                return Err("Шифртекст должен состоять из полных блоков по 8 байт".into());
            }

            let mut cipher_text = decrypt_des(cipher_text, key3)?;
            cipher_text = encrypt_des(cipher_text, key2)?;
            let plaintext = decrypt_des(cipher_text, key1)?;

            remove_padding(plaintext)
        }
    }

    fn remove_padding(plaintext: Text) -> Result<Text, Errors> {
        let mut data: Vec<u8> = plaintext.get_data().iter()
            .flat_map(|block| block.get_data().iter().copied())
            .collect();
        let padding = *data.last().ok_or("Пустой шифртекст")? as usize;
        if !(1..=8).contains(&padding)
            || !data[data.len() - padding..].iter().all(|&byte| byte as usize == padding)
        {
            return Err("Некорректный padding".into());
        }
        data.truncate(data.len() - padding);
        Ok(Text::from(data))
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
