use crate::errors::Errors;
use crate::text::Block as TextBlock;
use crate::text::{Key, Text};
use cipher::{Block, BlockCipherDecBackend, BlockCipherEncBackend, InOut};
use des::Des;
use des::cipher::KeyInit;

trait Cipher {
    fn encrypt(&mut self, plaintext: Text) -> Result<Text, Errors>;
    fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors>;
}

trait CipherBlock {
    fn encrypt_block(&self, plain_block: TextBlock) -> Result<TextBlock, Errors>;
    fn decrypt_block(&self, cipher_block: TextBlock) -> Result<TextBlock, Errors>;
}

struct DesCipher {
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

pub mod keygen {
    use super::*;

    fn keygen(size: usize) -> Result<Key, Errors> {
        let mut key = vec![0u8; size];
        getrandom::fill(&mut key)?;
        Ok(Key::new(key.to_vec()))
    }

    pub fn des_keygen() -> Result<Key, Errors> {
        keygen(8)
    }

    pub fn triple_des_keygen() -> Result<Key, Errors> {
        keygen(24)
    }
}

pub mod triple_des_ecb {
    use super::*;

    pub struct TripleDesEcb {
        des1: DesCipher,
        des2: DesCipher,
        des3: DesCipher,
    }

    impl TripleDesEcb {
        pub fn new(key: Key) -> Result<TripleDesEcb, Errors> {
            if !key.is_triple_des_key() {
                return Err("Неверная длина ключа".into());
            }

            let (key1, key2, key3) = key.split_key();

            Ok(TripleDesEcb {
                des1: DesCipher::new(key1)?,
                des2: DesCipher::new(key2)?,
                des3: DesCipher::new(key3)?,
            })
        }
    }

    impl Cipher for TripleDesEcb {
        fn encrypt(&mut self, plaintext: Text) -> Result<Text, Errors> {
            let cipher = self.des1.encrypt(plaintext)?;
            let cipher = self.des2.decrypt(cipher)?;
            let cipher = self.des3.encrypt(cipher)?;
            Ok(cipher)
        }

        fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors> {
            let plain = self.des3.decrypt(ciphertext)?;
            let plain = self.des2.encrypt(plain)?;
            let plain = self.des1.decrypt(plain)?;
            Ok(plain)
        }
    }
}

pub mod triple_des_cbc {
    use super::*;
    use crate::text;
    use crate::text::IV;
    use rayon::prelude::*;

    pub struct TripleDesCbcInner {
        des1: DesCipher,
        des2: DesCipher,
        des3: DesCipher,
        iv: IV,
    }

    impl TripleDesCbcInner {
        pub fn new(key: Key, iv: IV) -> Result<TripleDesCbcInner, Errors> {
            if !key.is_triple_des_key() {
                return Err("Неверная длина ключа".into());
            }

            let (key1, key2, key3) = key.split_key();

            Ok(TripleDesCbcInner {
                des1: DesCipher::new(key1)?,
                des2: DesCipher::new(key2)?,
                des3: DesCipher::new(key3)?,
                iv,
            })
        }

        fn xor_block(block1: &text::Block, block2: &text::Block) -> text::Block {
            let first = block1.get_data();
            let second = block2.get_data();

            text::Block::new(std::array::from_fn(|i| first[i] ^ second[i]))
        }
    }

    impl Cipher for TripleDesCbcInner {
        fn encrypt(&mut self, mut plaintext: Text) -> Result<Text, Errors> {
            let mut previous = self.iv.get_iv().clone();

            for chunk in plaintext.get_mut_data() {
                let xor_block = Self::xor_block(&previous, chunk);

                let cipher = self.des1.encrypt_block(xor_block)?;
                let cipher = self.des2.decrypt_block(cipher)?;
                let cipher = self.des3.encrypt_block(cipher)?;

                previous = cipher.clone();

                chunk.get_mut_data().copy_from_slice(cipher.get_data());
            }

            Ok(plaintext)
        }

        fn decrypt(&mut self, ciphertext: Text) -> Result<Text, Errors> {
            let blocks = ciphertext.get_data();
            let plaintext = blocks
                .par_iter()
                .enumerate()
                .map(|(i, &current)| {
                    let previous = if i == 0 {
                        self.iv.get_iv()
                    } else {
                        &blocks[i - 1]
                    };

                    let plain = self.des3.decrypt_block(current)?;
                    let plain = self.des2.encrypt_block(plain)?;
                    let plain = self.des1.decrypt_block(plain)?;

                    Ok(Self::xor_block(previous, &plain))
                })
                .collect::<Result<Vec<TextBlock>, Errors>>()?;

            Ok(Text::new(plaintext))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use des::TdesEde3;

        #[test]
        fn parallel_decryption_matches_reference_cbc() {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(4)
                .build()
                .unwrap();

            pool.install(|| {
                let key: Vec<u8> = (0..24).collect();
                let iv = [0xA5; 8];
                let reference = TdesEde3::new_from_slice(&key).unwrap();
                let mut cipher = TripleDesCbcInner::new(Key::new(key), IV::new(iv)).unwrap();

                for len in [0, 1, 7, 8, 9, 16, 31, 8193] {
                    let original: Vec<u8> = (0..len).map(|i| i as u8).collect();
                    let padded = Text::from(original.clone());
                    let mut previous = iv;
                    let mut encrypted = Vec::new();

                    for block in padded.get_data() {
                        let input: [u8; 8] =
                            std::array::from_fn(|i| block.get_data()[i] ^ previous[i]);
                        let mut output = Block::<TdesEde3>::from(input);
                        BlockCipherEncBackend::encrypt_block(&reference, InOut::from(&mut output));
                        previous.copy_from_slice(&output);
                        encrypted.push(TextBlock::new(previous));
                    }

                    let decrypted = cipher.decrypt(Text::new(encrypted)).unwrap();
                    let actual: Vec<_> = decrypted
                        .get_data()
                        .iter()
                        .flat_map(|block| block.get_data().iter().copied())
                        .collect();
                    let expected: Vec<_> = padded
                        .get_data()
                        .iter()
                        .flat_map(|block| block.get_data().iter().copied())
                        .collect();
                    assert_eq!(actual, expected, "length {len}");
                    assert_eq!(Vec::<u8>::from(decrypted), original);
                }
            });
        }
    }
}
