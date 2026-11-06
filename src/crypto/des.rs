use crate::crypto::crypto_traits::{Cipher, CipherBlock};
use crate::errors::Errors;
use crate::text::Block as TextBlock;
use crate::text::{Key, Text};
use cipher::{Block, BlockCipherDecBackend, BlockCipherEncBackend, InOut, KeyInit};
use des::Des;

pub struct DesCipher {
    des: Des,
}

impl DesCipher {
    pub fn new(key: Key) -> Result<DesCipher, Errors> {
        let des = Des::new_from_slice(&key.get_key())
            .map_err(|_| "Неверная длина ключа. Для DES нужно ровно 8 байт.")?;

        Ok(DesCipher { des })
    }
}

impl Cipher for DesCipher {
    fn encrypt(&mut self, mut plaintext: Text) -> Result<Text, Errors> {
        for chunk in plaintext.get_mut_data() {
            let mut des_block = Block::<Des>::clone_from_slice(chunk.get_data());
            BlockCipherEncBackend::encrypt_block(&self.des, InOut::from(&mut des_block));
            chunk.get_mut_data().copy_from_slice(&des_block);
        }

        Ok(plaintext)
    }

    fn decrypt(&mut self, mut ciphertext: Text) -> Result<Text, Errors> {
        for chunk in ciphertext.get_mut_data() {
            let mut des_block = Block::<Des>::clone_from_slice(chunk.get_data());
            BlockCipherDecBackend::decrypt_block(&self.des, InOut::from(&mut des_block));
            chunk.get_mut_data().copy_from_slice(&des_block);
        }

        Ok(ciphertext)
    }
}

impl CipherBlock for DesCipher {
    fn encrypt_block(&self, mut plain_block: TextBlock) -> Result<TextBlock, Errors> {
        let mut des_block = Block::<Des>::clone_from_slice(plain_block.get_data());
        BlockCipherEncBackend::encrypt_block(&self.des, InOut::from(&mut des_block));
        plain_block.get_mut_data().copy_from_slice(&des_block);
        Ok(plain_block)
    }

    fn decrypt_block(&self, mut cipher_block: TextBlock) -> Result<TextBlock, Errors> {
        let mut des_block = Block::<Des>::clone_from_slice(cipher_block.get_data());
        BlockCipherDecBackend::decrypt_block(&self.des, InOut::from(&mut des_block));
        cipher_block.get_mut_data().copy_from_slice(&des_block);
        Ok(cipher_block)
    }
}
