use crate::crypto::des::DesCipher;
use crate::errors::Errors;
use crate::text::Block as TextBlock;
use crate::text::{IV, Key, Text};
use rayon::prelude::*;

pub trait Cipher {
    fn encrypt(&mut self, plaintext: Text) -> Result<Text, Errors>;
    fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors>;
}

pub trait CipherBlock {
    fn encrypt_block(&self, plain_block: TextBlock) -> Result<TextBlock, Errors>;
    fn decrypt_block(&self, cipher_block: TextBlock) -> Result<TextBlock, Errors>;
}

pub struct Cbc<C: CipherBlock> {
    cipher: C,
    iv: IV,
}

impl<C: CipherBlock> Cbc<C> {
    pub fn new(cipher: C, iv: IV) -> Cbc<C> {
        Cbc { cipher, iv }
    }

    fn xor_block(block1: &TextBlock, block2: &TextBlock) -> TextBlock {
        let first = block1.get_data();
        let second = block2.get_data();

        TextBlock::new(std::array::from_fn(|i| first[i] ^ second[i]))
    }
}

impl<C: CipherBlock + Sync> Cipher for Cbc<C> {
    fn encrypt(&mut self, mut plaintext: Text) -> Result<Text, Errors> {
        let mut previous = *self.iv.get_iv();

        for chunk in plaintext.get_mut_data() {
            let xor_block = Self::xor_block(&previous, chunk);
            let cipher = self.cipher.encrypt_block(xor_block)?;

            previous = cipher;
            *chunk = cipher;
        }

        Ok(plaintext)
    }

    fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors> {
        let blocks = ciphertext.get_data();
        let cipher = &self.cipher;
        let iv = self.iv.get_iv();
        let plaintext = blocks
            .par_iter()
            .enumerate()
            .map(|(i, &current)| {
                let previous = if i == 0 { iv } else { &blocks[i - 1] };
                let plain = cipher.decrypt_block(current)?;

                Ok(Self::xor_block(previous, &plain))
            })
            .collect::<Result<Vec<TextBlock>, Errors>>()?;

        Ok(Text::new(plaintext))
    }
}

pub struct TripleDesEde {
    des1: DesCipher,
    des2: DesCipher,
    des3: DesCipher,
}

impl TripleDesEde {
    pub fn new(key: Key) -> Result<TripleDesEde, Errors> {
        if !key.is_triple_des_key() {
            return Err("Неверная длина ключа".into());
        }

        let (key1, key2, key3) = key.split_key();

        Ok(TripleDesEde {
            des1: DesCipher::new(key1)?,
            des2: DesCipher::new(key2)?,
            des3: DesCipher::new(key3)?,
        })
    }
}

impl CipherBlock for TripleDesEde {
    fn encrypt_block(&self, plain_block: TextBlock) -> Result<TextBlock, Errors> {
        let cipher = self.des1.encrypt_block(plain_block)?;
        let cipher = self.des2.decrypt_block(cipher)?;
        self.des3.encrypt_block(cipher)
    }

    fn decrypt_block(&self, cipher_block: TextBlock) -> Result<TextBlock, Errors> {
        let plain = self.des3.decrypt_block(cipher_block)?;
        let plain = self.des2.encrypt_block(plain)?;
        self.des1.decrypt_block(plain)
    }
}
