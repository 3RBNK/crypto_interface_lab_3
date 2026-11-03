pub struct Block {
    data: Vec<u8>,
}

impl Block {
    pub fn new(data: Vec<u8>) -> Block {
        Block { data: data }
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn pkcs7_up(mut self) {
        let padding = 8 - self.data.len() % 8;
        self.data.extend(vec![padding as u8; padding]);
    }

    pub fn pkcs7_down(mut self) {

    }
}