#[derive(Debug)]
#[repr(C)]
pub struct Header {
    pub first: i32,
    pub last : i32
}


fn test() {
    let mut buf: [i8; 8] = [0; 8];
    buf[0] = 1;
    buf[1] = 1;

    println!("{:?}", buf);

    let header: Header;
    unsafe {
        header = mem::transmute::<[i8; 8], Header>(buf);
    }

    println!("{:?}", header);
}