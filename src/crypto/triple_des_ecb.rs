use crate::crypto::crypto_traits::{Cipher, CipherBlock, TripleDesEde};
use crate::errors::Errors;
use crate::text::{Key, Text};

pub struct TripleDesEcb {
    cipher: TripleDesEde,
}

impl TripleDesEcb {
    pub fn new(key: Key) -> Result<TripleDesEcb, Errors> {
        Ok(TripleDesEcb {
            cipher: TripleDesEde::new(key)?,
        })
    }
}

impl Cipher for TripleDesEcb {
    fn encrypt(&mut self, mut plaintext: Text) -> Result<Text, Errors> {
        for chunk in plaintext.get_mut_data() {
            *chunk = self.cipher.encrypt_block(*chunk)?;
        }

        Ok(plaintext)
    }

    fn decrypt(&mut self, mut ciphertext: Text) -> Result<Text, Errors> {
        for chunk in ciphertext.get_mut_data() {
            *chunk = self.cipher.decrypt_block(*chunk)?;
        }

        Ok(ciphertext)
    }
}
