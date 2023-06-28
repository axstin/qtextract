use std::io::Read;

pub struct BinaryReader<'a> {
    position: usize,
    stream: &'a [u8]
}

impl<'a> BinaryReader<'a> {
    pub fn new(stream: &'a [u8]) -> Self {
        Self { position: 0, stream }
    }

    pub fn new_at(stream: &'a [u8], position: usize) -> Self {
        Self { position, stream }
    }

    pub fn seek(&mut self, offset: usize) {
        self.position = offset;
    }

    pub fn skip(&mut self, num: isize) {
        self.position = self.position.wrapping_add_signed(num);
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> Option<()> {
        let mut slice = self.stream.get(self.position..).unwrap_or_default();
        slice.read_exact(buffer).ok()?;
        self.position += buffer.len();
        Some(())
    }

    pub fn read_bytes(&mut self, count: usize) -> Option<&[u8]> {
        let result = self.stream.get(self.position..self.position + count)?;
        self.position += count;
        Some(result)
    }

    pub fn read_byte(&mut self) -> Option<u8> {
        if self.position < self.stream.len() {
            let byte = self.stream[self.position];
            self.position += 1;
            Some(byte)
        } else {
            None
        }
    }

    pub fn read_u16<const BE: bool>(&mut self) -> Option<u16> {
        let mut bytes = [0u8; 2];
        self.read(&mut bytes)?;
        if BE {
            Some(u16::from_be_bytes(bytes))
        } else {
            Some(u16::from_le_bytes(bytes))
        }
    }

    pub fn read_i16<const BE: bool>(&mut self) -> Option<i16> {
        let mut bytes = [0u8; 2];
        self.read(&mut bytes)?;
        if BE {
            Some(i16::from_be_bytes(bytes))
        } else {
            Some(i16::from_le_bytes(bytes))
        }
    }

    pub fn read_u32<const BE: bool>(&mut self) -> Option<u32> {
        let mut bytes = [0u8; 4];
        self.read(&mut bytes)?;
        if BE {
            Some(u32::from_be_bytes(bytes))
        } else {
            Some(u32::from_le_bytes(bytes))
        }
    }

    pub fn read_i32<const BE: bool>(&mut self) -> Option<i32> {
        let mut bytes = [0u8; 4];
        self.read(&mut bytes)?;
        if BE {
            Some(i32::from_be_bytes(bytes))
        } else {
            Some(i32::from_le_bytes(bytes))
        }
    }

    pub fn read_u64<const BE: bool>(&mut self) -> Option<u64> {
        let mut bytes = [0u8; 8];
        self.read(&mut bytes)?;
        if BE {
            Some(u64::from_be_bytes(bytes))
        } else {
            Some(u64::from_le_bytes(bytes))
        }
    }

    pub fn read_i64<const BE: bool>(&mut self) -> Option<i64> {
        let mut bytes = [0u8; 8];
        self.read(&mut bytes)?;
        if BE {
            Some(i64::from_be_bytes(bytes))
        } else {
            Some(i64::from_le_bytes(bytes))
        }
    }

    pub fn read_u16_string<const BE: bool>(&mut self, size: usize) -> Option<String> {
        let mut chars = Vec::with_capacity(size);
        for _ in 0..size {
            chars.push(self.read_u16::<BE>()?);
        }
        Some(String::from_utf16_lossy(&chars))
    }
}