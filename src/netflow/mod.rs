pub mod ipfix;
pub mod v5;
use std::fmt::Display;

pub trait NetflowMsg: Send + Display {}
