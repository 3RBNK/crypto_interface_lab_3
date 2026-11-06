use rayon::prelude::IntoParallelIterator;

pub trait ToVec {
    fn to_vec(&self) -> Vec<u8>;
}

#[derive(Clone, Copy)]
pub struct Block {
    data: [u8; 8],
}

impl Block {
    pub fn new(data: [u8; 8]) -> Block {
        Block { data }
    }

    pub fn get_data(&self) -> &[u8; 8] {
        &self.data
    }

    pub fn get_mut_data(&mut self) -> &mut [u8; 8] {
        &mut self.data
    }
}

impl IntoParallelIterator for Block {
    type Iter = rayon::array::IntoIter<u8, 8>;
    type Item = u8;

    fn into_par_iter(self) -> Self::Iter {
        self.data.into_par_iter()
    }
}

impl ToVec for Block {
    fn to_vec(&self) -> Vec<u8> {
        self.data.to_vec()
    }
}

pub struct Text {
    data: Vec<Block>,
}

impl Text {
    pub fn into_unpadded_bytes(self) -> Result<Vec<u8>, crate::errors::Errors> {
        let mut bytes: Vec<u8> = self.data.into_iter().flat_map(|block| block.data).collect();
        let padding = *bytes.last().ok_or("Отсутствует PKCS#7 padding")? as usize;

        if !(1..=8).contains(&padding)
            || !bytes[bytes.len() - padding..]
                .iter()
                .all(|&byte| byte as usize == padding)
        {
            return Err("Некорректный PKCS#7 padding".into());
        }

        bytes.truncate(bytes.len() - padding);
        Ok(bytes)
    }

    pub fn new(data: Vec<Block>) -> Text {
        Text { data }
    }

    pub fn get_data(&self) -> &Vec<Block> {
        &self.data
    }

    pub fn get_mut_data(&mut self) -> &mut Vec<Block> {
        &mut self.data
    }

    pub fn to_u8_vec(&self) -> Vec<u8> {
        self.data
            .clone()
            .iter()
            .flat_map(|block| block.get_data().clone())
            .collect()
    }
}

impl From<Vec<u8>> for Text {
    fn from(mut data: Vec<u8>) -> Text {
        let padding = 8 - data.len() % 8;
        data.resize(data.len() + padding, padding as u8);

        let blocks = data
            .chunks_exact(8)
            .map(|chunk| Block::new(chunk.try_into().unwrap()))
            .collect::<Vec<Block>>();

        Text { data: blocks }
    }
}

impl From<Text> for Vec<u8> {
    fn from(data: Text) -> Vec<u8> {
        data.into_unpadded_bytes()
            .expect("Ошибка удаления PKCS#7 padding")
    }
}

impl ToVec for Text {
    fn to_vec(&self) -> Vec<u8> {
        self.data.iter().flat_map(|block| block.to_vec()).collect()
    }
}

#[derive(Clone)]
pub struct Key {
    key: Vec<Block>,
}

impl Key {
    pub fn new(key: Vec<u8>) -> Key {
        if key.len() != 8 && key.len() != 24 {
            panic!("Длина ключа 8 либо 24 байта");
        }

        let key = key
            .chunks_exact(8)
            .map(|chunk| Block::new(chunk.try_into().unwrap()))
            .collect();
        Key { key }
    }

    pub fn get_key(&self) -> Vec<u8> {
        self.key.iter().flat_map(|block| block.data).collect()
    }

    pub fn is_des_key(&self) -> bool {
        self.key.len() == 1
    }

    pub fn is_triple_des_key(&self) -> bool {
        self.key.len() == 3
    }

    pub fn split_key(&self) -> (Key, Key, Key) {
        if self.key.len() != 3 {
            panic!("Размер ключа должен быть 24 байта")
        }

        let key1 = Key {
            key: vec![self.key[0]],
        };
        let key2 = Key {
            key: vec![self.key[1]],
        };
        let key3 = Key {
            key: vec![self.key[2]],
        };

        (key1, key2, key3)
    }
}

impl ToVec for Key {
    fn to_vec(&self) -> Vec<u8> {
        self.key.iter().flat_map(|block| block.to_vec()).collect()
    }
}

#[derive(Clone)]
pub struct IV {
    iv: Block,
}

impl IV {
    pub fn new(iv: [u8; 8]) -> IV {
        IV { iv: Block::new(iv) }
    }

    pub fn get_iv(&self) -> &Block {
        &self.iv
    }
}

impl ToVec for IV {
    fn to_vec(&self) -> Vec<u8> {
        self.iv.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip_preserves_all_bytes_and_block_boundaries() {
        for len in 0..=256 {
            let original: Vec<u8> = (0..len).map(|byte| byte as u8).collect();
            assert_eq!(Vec::<u8>::from(Text::from(original.clone())), original);
        }
    }

    #[test]
    #[should_panic(expected = "Отсутствует PKCS#7 padding")]
    fn text_without_blocks_is_rejected() {
        let _ = Vec::<u8>::from(Text::new(vec![]));
    }

    #[test]
    fn invalid_padding_is_rejected() {
        for block in [[0; 8], [9; 8], [1, 2, 3, 4, 5, 6, 1, 2]] {
            assert!(
                std::panic::catch_unwind(|| {
                    Vec::<u8>::from(Text::new(vec![Block::new(block)]))
                })
                .is_err()
            );
        }
    }

    #[test]
    fn text_padding_handles_every_block_boundary() {
        for len in 0..=24 {
            let original = vec![42; len];
            let text = Text::from(original.clone());
            let bytes: Vec<u8> = text.data.iter().flat_map(|block| block.data).collect();
            let padding = 8 - len % 8;
            assert_eq!(&bytes[..len], original.as_slice());
            assert_eq!(&bytes[len..], vec![padding as u8; padding]);
        }
    }

    #[test]
    fn triple_des_key_splits_into_three_des_keys() {
        let bytes: Vec<u8> = (0..24).collect();
        let key = Key::new(bytes.clone());
        assert_eq!(key.get_key(), bytes);
        let (first, second, third) = key.split_key();
        assert_eq!(first.get_key(), bytes[..8]);
        assert_eq!(second.get_key(), bytes[8..16]);
        assert_eq!(third.get_key(), bytes[16..]);
    }
}
