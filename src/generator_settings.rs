extern crate config;
extern crate serde;

use config::{Config, ConfigError, Environment, File, FileFormat};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct GeneratorSettings {
    pub chain_id: char,
    pub initial_balance: i64,
    pub base_target: i64,
    pub average_block_delay: i64,
    pub timestamp: Option<i64>,
    pub distribution: HashMap<String, i64>,
}

impl GeneratorSettings {
    pub fn load(config_file_path: &str) -> Result<Self, ConfigError> {
        let mut conf = Config::new();

        conf.merge(File::new(config_file_path, FileFormat::Yaml))?;
        conf.merge(Environment::with_prefix("GG"))?;

        conf.try_into()
    }
}
