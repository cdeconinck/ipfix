use log::{LevelFilter};

pub fn init_logger(level: &LevelFilter) {
    let mut logger = env_logger::Builder::new();
    logger.format_timestamp_millis();
    logger.filter(None, *level);
    logger.init();
}