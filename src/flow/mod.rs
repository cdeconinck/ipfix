use std::fmt::Display;

pub mod ipfix;
pub mod netflow5;

// common structure for each netflow data message
pub trait Flow: Send + Display {}

pub enum Template {
    IpfixDataSet(ipfix::DataSetTemplate),
    IpfixOptionDataSet(ipfix::OptionDataSetTemplate),
}
