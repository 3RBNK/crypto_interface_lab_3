use crate::cli::CipherMode;
use crate::crypto::{Cipher, TripleDesCbcInner, TripleDesCbcOuter, TripleDesEcb, TripleDesWithPad};
use crate::errors::Errors;
use crate::text::{IV, Key, Text};

pub struct CipherWithMode {
    cipher: Box<dyn Cipher>,
}

impl CipherWithMode {
    pub fn new(key: Key, iv: Option<Vec<IV>>, mode: CipherMode) -> Result<CipherWithMode, Errors> {
        let iv = iv.as_deref().unwrap_or(&[]);
        let cipher: Box<dyn Cipher> = match mode {
            CipherMode::ECB => Box::new(TripleDesEcb::new(key)?),
            CipherMode::InnerCBC => {
                let [iv1, iv2, iv3] = iv else {
                    return Err("Для inner CBC нужны три IV".into());
                };
                Box::new(TripleDesCbcInner::new(
                    key,
                    iv1.clone(),
                    iv2.clone(),
                    iv3.clone(),
                )?)
            }
            CipherMode::OuterCBC => {
                let [iv] = iv else {
                    return Err("Для outer CBC нужен один IV".into());
                };
                Box::new(TripleDesCbcOuter::new(key, iv.clone())?)
            }
            CipherMode::Pad => Box::new(TripleDesWithPad::new(key)?),
        };

        Ok(CipherWithMode { cipher })
    }
}

impl Cipher for CipherWithMode {
    fn encrypt(&mut self, plaintext: Text) -> Result<Text, Errors> {
        self.cipher.encrypt(plaintext)
    }

    fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors> {
        self.cipher.decrypt(ciphertext)
    }
}
