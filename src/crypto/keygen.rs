use crate::errors::Errors;
use crate::text::Key;

pub struct Keygen;

impl Keygen {
    pub fn new() -> Keygen {
        Keygen
    }

    pub fn keygen(&self, size: usize) -> Result<Key, Errors> {
        let mut key = vec![0u8; size];
        getrandom::fill(&mut key)?;
        Ok(Key::new(key.to_vec()))
    }

    pub fn des_keygen(&self) -> Result<Key, Errors> {
        self.keygen(8)
    }

    pub fn triple_des_keygen(&self) -> Result<Key, Errors> {
        self.keygen(24)
    }
}
