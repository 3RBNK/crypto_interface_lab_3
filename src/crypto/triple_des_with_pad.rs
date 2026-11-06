use crate::crypto::{Cipher, DesCipher};
use crate::errors::Errors;
use crate::prelude::Text;
use crate::text::{Block, Key};

pub struct TripleDesWithPad {
    des1: DesCipher,
    des2: DesCipher,
    des3: DesCipher,
}

impl TripleDesWithPad {
    pub fn new(key: Key) -> Result<TripleDesWithPad, Errors> {
        if !key.is_triple_des_key() {
            return Err("Неверная длина ключа".into());
        }

        let (key1, key2, key3) = key.split_key();

        Ok(TripleDesWithPad {
            des1: DesCipher::new(key1)?,
            des2: DesCipher::new(key2)?,
            des3: DesCipher::new(key3)?,
        })
    }

    fn add_padding(text: Text) -> Result<Text, Errors> {
        let flat_text: Vec<u8> = text.to_u8_vec();

        let mut left_pad = Self::gen_pad()?;
        let right_pad = Self::gen_pad()?;

        left_pad.extend_from_slice(&flat_text);
        left_pad.extend_from_slice(&right_pad);

        Ok(Self::from_blocks(&left_pad))
    }

    fn remove_padding(text: Text) -> Result<Text, Errors> {
        let flat_text: Vec<u8> = text.to_u8_vec();

        if flat_text.len() < 8 {
            return Err("Текст короче случайного дополнения".into());
        }

        Ok(Self::from_blocks(&flat_text[4..flat_text.len() - 4]))
    }

    fn from_blocks(data: &[u8]) -> Text {
        let blocks = data
            .chunks_exact(8)
            .map(|chunk| Block::new(chunk.try_into().unwrap()))
            .collect();

        Text::new(blocks)
    }

    fn gen_pad() -> Result<Vec<u8>, Errors> {
        let mut pad = vec![0u8; 4];
        getrandom::fill(&mut pad)?;
        Ok(pad)
    }
}

impl Cipher for TripleDesWithPad {
    fn encrypt(&mut self, plaintext: Text) -> Result<Text, Errors> {
        let cipher = self.des1.encrypt(plaintext)?;
        let cipher = Self::add_padding(cipher)?;
        let cipher = self.des2.encrypt(cipher)?;
        let cipher = Self::add_padding(cipher)?;
        let cipher = self.des3.encrypt(cipher)?;

        Ok(cipher)
    }

    fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors> {
        if ciphertext.get_data().len() < 2 {
            return Err("Шифртекст короче двух случайных дополнений".into());
        }

        let plain = self.des3.decrypt(ciphertext)?;
        let plain = Self::remove_padding(plain)?;
        let plain = self.des2.decrypt(plain)?;
        let plain = Self::remove_padding(plain)?;
        let plain = self.des1.decrypt(plain)?;

        Ok(plain)
    }
}
