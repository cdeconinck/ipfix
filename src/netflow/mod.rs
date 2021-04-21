use std::fmt::Display;

pub mod ipfix;
pub mod v5;

// common structure for each netflow data message
pub trait NetflowMsg: Send + Display {}

pub enum Template {
    IpfixDataSet(ipfix::DataSetTemplate),
    IpfixOptionDataSet(ipfix::OptionDataSetTemplate),
}
