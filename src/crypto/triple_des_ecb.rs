use crate::crypto::crypto_traits::{Cipher, CipherBlock, TripleDesEde};
use crate::errors::Errors;
use crate::text::{Key, Text};
use rayon::prelude::*;

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
        let cipher = &self.cipher;
        plaintext
            .get_mut_data()
            .par_iter_mut()
            .try_for_each(|chunk| -> Result<(), Errors> {
                *chunk = cipher.encrypt_block(*chunk)?;
                Ok(())
            })?;

        Ok(plaintext)
    }

    fn decrypt(&mut self, mut ciphertext: Text) -> Result<Text, Errors> {
        let cipher = &self.cipher;
        ciphertext
            .get_mut_data()
            .par_iter_mut()
            .try_for_each(|chunk| -> Result<(), Errors> {
                *chunk = cipher.decrypt_block(*chunk)?;
                Ok(())
            })?;

        Ok(ciphertext)
    }
}
