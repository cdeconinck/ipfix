pub mod ipfix;
pub mod v5;

pub trait NetflowMsg: Send {
    fn print(&self) -> String;
}
