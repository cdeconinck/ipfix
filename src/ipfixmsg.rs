#[derive(Debug)]
pub struct IpfixMsg {
    pub src_addr: String,
    pub dst_addr: String,
    pub octets: u32,
    pub packets: u32,
    pub port_src: u16,
    pub dst_port: u16, 
}

impl Default for IpfixMsg {
    fn default() -> Self { 
        IpfixMsg {
            src_addr: String::from("unknown"),
            dst_addr: String::from("unknown"),
            octets: 0,
            packets: 0,
            port_src: 0,
            dst_port: 0, 
        } 
    }
}