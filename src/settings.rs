use config;

pub fn load_config() -> config::Config {
    // read config from file
    let mut config = config::Config::new();
    config.merge(config::File::with_name("./config/default.ini")).unwrap()
          .merge(config::Environment::with_prefix("APP")).unwrap();

    return config;
}