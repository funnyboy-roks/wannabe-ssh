use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::Deserialize;
use ssh_key::PrivateKey;
use tokio::fs;

#[derive(Clone, Debug, Deserialize)]
pub struct Action {
    pub name: String,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub priv_ssh_key: PathBuf,
    pub url: String,
    pub name: String,
    pub actions: Vec<Action>,
}

impl Config {
    pub async fn priv_key(&self) -> anyhow::Result<PrivateKey> {
        let privkey = fs::read_to_string(&self.priv_ssh_key).await?;
        privkey.parse().context("parsing private ssh key")
    }
}

pub async fn load<P>(path: P) -> anyhow::Result<Config>
where
    P: AsRef<Path>,
{
    toml::from_str(&fs::read_to_string(path).await.context("reading config")?)
        .context("Parsing config")
}
