use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::Deserialize;
use tokio::fs;

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub ssh_key: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct UserConfig {
    /// set of clients that this user can acess
    pub clients: HashSet<String>,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubConfig {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// ClientName: Config
    pub clients: HashMap<String, ClientConfig>,
    /// Username: Config
    pub users: HashMap<String, UserConfig>,
    pub github: GitHubConfig,
}

pub async fn load<P>(path: P) -> anyhow::Result<Config>
where
    P: AsRef<Path>,
{
    toml::from_str(
        &fs::read_to_string(path)
            .await
            .context("Reading config file")?,
    )
    .context("Parsing config file")
}
