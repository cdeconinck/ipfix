use std::env;
use config::{ConfigError, Config, File, Environment};
use log::LevelFilter;
use std::str::FromStr;

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
    pub fn init() -> Result<Self, ConfigError> {
        let mut s = Config::new();

        // Start off by merging in the "default" configuration file
        s.merge(File::with_name("config/default"))?;

        // Add in the current environment file
        // Default to 'development' env
        // Note that this file is _optional_
        let env = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        s.merge(File::with_name(&format!("config/{}", env)).required(false))?;

        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        s.merge(Environment::with_prefix("app"))?;

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