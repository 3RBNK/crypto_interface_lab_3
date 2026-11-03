pub struct Block {
    data: Vec<u8>,
    fill: bool
}

impl Block {
    pub fn new(data: Vec<u8>) -> Block {
        if data.len() > 8 {
            panic!("data is too long");
        }

        Block { data, fill: false }
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn get_fill(&self) -> bool {
        self.fill
    }

    pub fn get_mut_data(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    pub fn fill_block(&mut self) {
        let padding = 8 - self.data.len() % 8;
        self.data.extend(vec![padding as u8; padding]);
        self.fill = true;
    }

    pub fn unfill_block(&mut self) {
        if self.fill {
            let padding = self.data.last().unwrap().clone() as usize;
            self.data.truncate(8 - padding);
            self.fill = false;
        }
    }
}


pub struct Text {
    data: Vec<Block>,
    fill: bool
}

impl Text {
    pub fn new(data: Vec<Block>) -> Text {
        Text { data, fill: false }
    }

    pub fn get_data(&self) -> &Vec<Block> {
        &self.data
    }

    pub fn get_mut_data(&mut self) -> &mut Vec<Block> {
        &mut self.data
    }

    pub fn fill_block(&mut self) {
        self.data.last_mut().unwrap().fill_block();
    }

    pub fn unfill_block(&mut self) {
        if self.fill {
            self.data.last_mut().unwrap().unfill_block();
        }
    }
}


impl From<Vec<u8>> for Text {
    fn from(data: Vec<u8>) -> Text {
        let blocks = data
            .chunks(8)
            .map(|chunk| Block::new(chunk.to_vec()))
            .collect::<Vec<Block>>();

        Text { data: blocks, fill: false }
    }
}
