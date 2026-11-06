use crate::crypto::Cipher;
use crate::crypto::crypto_traits::{Cbc, TripleDesEde};
use crate::crypto::des::DesCipher;
use crate::errors::Errors;
use crate::text::{IV, Key, Text};

pub struct TripleDesCbcOuter {
    inner: Cbc<TripleDesEde>,
}

impl TripleDesCbcOuter {
    pub fn new(key: Key, iv: IV) -> Result<TripleDesCbcOuter, Errors> {
        let cipher = TripleDesEde::new(key)?;

        Ok(TripleDesCbcOuter {
            inner: Cbc::new(cipher, iv),
        })
    }
}

impl Cipher for TripleDesCbcOuter {
    fn encrypt(&mut self, plaintext: Text) -> Result<Text, Errors> {
        self.inner.encrypt(plaintext)
    }

    fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors> {
        self.inner.decrypt(ciphertext)
    }
}

pub struct TripleDesCbcInner {
    stage1: Cbc<DesCipher>,
    stage2: Cbc<DesCipher>,
    stage3: Cbc<DesCipher>,
}

impl TripleDesCbcInner {
    pub fn new(key: Key, iv1: IV, iv2: IV, iv3: IV) -> Result<TripleDesCbcInner, Errors> {
        if !key.is_triple_des_key() {
            return Err("Неверная длина ключа".into());
        }

        let (key1, key2, key3) = key.split_key();

        Ok(TripleDesCbcInner {
            stage1: Cbc::new(DesCipher::new(key1)?, iv1),
            stage2: Cbc::new(DesCipher::new(key2)?, iv2),
            stage3: Cbc::new(DesCipher::new(key3)?, iv3),
        })
    }
}

impl Cipher for TripleDesCbcInner {
    fn encrypt(&mut self, plaintext: Text) -> Result<Text, Errors> {
        let cipher = self.stage1.encrypt(plaintext)?;
        let cipher = self.stage2.decrypt(cipher)?;
        self.stage3.encrypt(cipher)
    }

    fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors> {
        let plain = self.stage3.decrypt(ciphertext)?;
        let plain = self.stage2.encrypt(plain)?;
        self.stage1.decrypt(plain)
    }
}
