use config::{ConfigError, Config, File};
use log::{LevelFilter};
use std::str::FromStr;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Listener {
    pub host: String,
}

#[derive(Debug, Deserialize)]
pub struct Log {
    pub level: String,
}

#[derive(Debug, Deserialize)]
pub struct Prometheus {
    pub enable: bool,
    pub host: String
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub log: Log,
    pub listener: Listener,
    pub prometheus: Prometheus
}

impl Settings {
    pub fn init(config_file: Option<PathBuf>) -> Result<Self, ConfigError> {
        let mut s = Config::new();

        // surcharge the default config with the user config
        if config_file == None {
            println!("No config provided, launching the app with the default configuration");
        }
        else {
            s.merge(File::from(config_file.unwrap()))?;
        }

        // freeze the configuration
        s.try_into()
    }
}

pub fn init_logger(level: &str) {
    let mut logger = env_logger::Builder::new();
    logger.format_timestamp_millis();
    logger.filter(None, LevelFilter::from_str(level).unwrap());
    logger.init();
}