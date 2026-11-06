use std::fs::File;
use std::io::{Read, Write};
use crate::errors::Errors;

pub struct FileStream {
    path: String,
}

impl FileStream {
    pub fn new(path: &String) -> FileStream {
        FileStream { path: path.into() }
    }

    pub fn get_path(&self) -> &String {
        &self.path
    }

    pub fn read_bin_file(&self) -> Result<Vec<u8>, Errors> {
        let mut file = File::open(&self.path)?;
        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer)?;

        Ok(buffer)
    }

    pub fn write_bin_file(&self, buffer: &Vec<u8>) -> Result<(), Errors> {
        let mut file = File::create(&self.path)?;
        file.write_all(&buffer)?;
        Ok(())
    }
}