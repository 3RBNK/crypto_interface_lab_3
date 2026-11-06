use crate::cli::{CipherMode, ConfigCLI, WorkMode};
use crate::crypto::{Cipher, CipherWithMode, Keygen};
use crate::errors::Errors;
use crate::iofile::FileStream;
use crate::text::{Block, IV, Key, Text, ToVec};

pub struct Application {
    config: ConfigCLI,
}

impl Application {
    pub fn new(config: ConfigCLI) -> Application {
        Application { config }
    }

    pub fn get_work_mode(&self) -> WorkMode {
        self.config.get_work_mode()
    }

    pub fn keygen(&self) -> Result<(), Errors> {
        let keygen = Keygen::new();
        let key = keygen.triple_des_keygen()?;
        Self::write_file(self.config.get_key_file(), &key.to_vec())
    }

    pub fn encrypt(&self) -> Result<(), Errors> {
        let mut cipher = self.read_cipher()?;
        let input_path = self
            .config
            .get_input_file()
            .ok_or("Не указан входной файл")?;
        let output_path = self
            .config
            .get_output_file()
            .ok_or("Не указан выходной файл")?;
        let plaintext = Text::from(Self::read_file(input_path)?);
        let ciphertext = cipher.encrypt(plaintext)?;

        Self::write_file(output_path, &ciphertext.to_vec())
    }

    pub fn decrypt(&self) -> Result<(), Errors> {
        let mut cipher = self.read_cipher()?;
        let input_path = self
            .config
            .get_input_file()
            .ok_or("Не указан входной файл")?;
        let output_path = self
            .config
            .get_output_file()
            .ok_or("Не указан выходной файл")?;
        let data = Self::read_file(input_path)?;

        if data.is_empty() || data.len() % 8 != 0 {
            return Err("Шифртекст должен состоять из полных блоков по 8 байт".into());
        }
        let blocks = data
            .chunks_exact(8)
            .map(|chunk| Block::new(chunk.try_into().unwrap()))
            .collect();
        let ciphertext = Text::new(blocks);
        let plaintext = cipher.decrypt(ciphertext)?.into_unpadded_bytes()?;

        Self::write_file(output_path, &plaintext)
    }

    fn read_cipher(&self) -> Result<CipherWithMode, Errors> {
        let mode = self
            .config
            .get_cipher_mode()
            .ok_or("Не указан режим шифрования")?;
        let key = Self::read_file(self.config.get_key_file())?;
        if key.len() != 24 {
            return Err("Ключ 3DES должен содержать 24 байта".into());
        }

        CipherWithMode::new(Key::new(key), self.read_iv(mode)?, mode)
    }

    fn read_iv(&self, mode: CipherMode) -> Result<Option<Vec<IV>>, Errors> {
        let size = match mode {
            CipherMode::InnerCBC => 24,
            CipherMode::OuterCBC => 8,
            CipherMode::ECB | CipherMode::Pad => return Ok(None),
        };
        let path = self.config.get_iv_file().ok_or("Не указан файл IV")?;
        let data = Self::read_file(path)?;
        if data.len() != size {
            return Err(format!("Файл IV должен содержать {size} байт").into());
        }
        let iv = data
            .chunks_exact(8)
            .map(|chunk| IV::new(chunk.try_into().unwrap()))
            .collect();

        Ok(Some(iv))
    }

    fn read_file(path: &str) -> Result<Vec<u8>, Errors> {
        FileStream::new(&path.to_string()).read_bin_file()
    }

    fn write_file(path: &str, data: &Vec<u8>) -> Result<(), Errors> {
        FileStream::new(&path.to_string()).write_bin_file(data)
    }
}
