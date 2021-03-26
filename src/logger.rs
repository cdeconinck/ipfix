use log::LevelFilter;
use std::str::FromStr;

pub fn init(level: &str) {
    std::env::set_var("RUST_LOG", level);

    let mut logger = env_logger::Builder::new();
    logger.format_timestamp_millis();
    logger.filter(None, LevelFilter::from_str("info").unwrap());
    logger.init();
}