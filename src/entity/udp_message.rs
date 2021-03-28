use std::fmt;

pub struct Message {
    pub src_addr: String,
    pub size: usize,
    pub buf : Vec<u8>
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} - {} - {:02X?} - {}", &self.src_addr, self.size, &self.buf, String::from_utf8_lossy(&self.buf))
    }
}