use std::{
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::Context;
use fast_websocket_client::OpCode;
use serde::Deserialize;
use ssh_key::PrivateKey;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead},
    process::Command,
};
use tracing::{debug, error, info, span, warn, Level};
use tracing_subscriber::prelude::*;

mod config;

#[derive(Debug, Clone, Deserialize)]
struct ActionCall {
    pub action: String,
    pub caller: String,
}

fn sign(s: &str, privkey: &PrivateKey) -> anyhow::Result<String> {
    let signed = privkey.sign("wannabe_ssh", ssh_key::HashAlg::Sha256, s.as_bytes())?;
    Ok(signed.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wannabe_daemon=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = dbg!(config::load(std::env::args().nth(1).unwrap_or("config.toml".into())).await?);
    let priv_key = config.priv_key().await?;
    let started_at = Instant::now();
    let url = format!("http://{}/ws", config.url);

    let mut has_connected_before = false;
    'reconnect_loop: loop {
        if has_connected_before {
            // timeout since we are trying to reconnect
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        has_connected_before = true;

        // In the example this is done manually for _every_ thing, which is awful
        // (attempt ~ try)
        macro_rules! attempt {
            ($ex: expr) => {
                match $ex {
                    Ok(f) => f,
                    Err(err) => {
                        error!(?err, "Reconnecting from an Error");
                        continue 'reconnect_loop;
                    }
                }
            };
        }

        let mut client = fast_websocket_client::client::Offline::new();

        debug!("connecting to {}", url);

        let mut client = attempt!(client.connect(&url).await);

        debug!("connected");

        debug!(name = &config.name, "Sending name");

        attempt!(client.send_string(&config.name).await);

        // wait for id
        let message = attempt!(client.receive_frame().await);
        let id = match message.opcode {
            OpCode::Text => String::from_utf8(message.payload.into())
                .context("OpCode::Text should always be valid utf-8")?,
            OpCode::Close => break,
            _ => continue,
        };

        debug!(id, "Recieved ID from server");

        // send signed key
        let signed = sign(&id, &priv_key)?;
        attempt!(client.send_string(&signed).await);

        debug!(id, "Sent signed id");

        debug!(id, "Waiting for success message");

        // wait for "success"
        let message = attempt!(client.receive_frame().await);
        match message.opcode {
            OpCode::Text => {
                let s = String::from_utf8(message.payload.into())
                    .expect("OpCode::Text should always be valid utf-8");
                if s != "success" {
                    debug!("Expected \"success\", found {:?}", s);
                    continue;
                }
            }
            OpCode::Close => {
                error!("Unexpected close frame: {:?}", message.payload);
                break;
            }
            _ => continue,
        };

        // send possible actions
        let actions: Vec<_> = config.actions.iter().map(|a| &a.name).collect();
        attempt!(client.send_json(actions).await);

        debug!(id, "Sent actions");

        debug!(id, "Waiting for action call");

        // message processing loop
        loop {
            let message = attempt!(client.receive_frame().await);

            match message.opcode {
                OpCode::Text => {
                    let call: ActionCall = attempt!(serde_json::from_slice(&message.payload));
                    notify_rust::Notification::new()
                        .summary(&format!(
                            "Command {} executed by {}",
                            call.action, call.caller
                        ))
                        .show()?;

                    let child = Command::new("sh")
                        .arg("-c")
                        .arg(
                            config
                                .actions
                                .iter()
                                .find_map(|a| (a.name == call.action).then_some(&a.command))
                                .unwrap(),
                        )
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()?;

                    tokio::join! {
                        print_to_trace(&call, true, child.stdout),
                        print_to_trace(&call, false, child.stderr),
                    };

                    debug!(?call, "Got action call");
                }
                OpCode::Close => {
                    debug!("{:?}", String::from_utf8_lossy(message.payload.as_ref()));
                    break 'reconnect_loop;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

async fn print_to_trace<R>(call: &ActionCall, stdout: bool, mut r: Option<R>)
where
    R: AsyncRead + std::marker::Unpin,
{
    if let Some(r) = r.as_mut() {
        let mut r = tokio::io::BufReader::new(r).lines();
        loop {
            match r.next_line().await {
                Ok(Some(line)) => {
                    if stdout {
                        info!("[{}] [STDOUT] {}", call.action, line)
                    } else {
                        warn!("[{}] [STDERR] {}", call.action, line)
                    }
                }
                Err(_) | Ok(None) => return,
            }
        }
    }
}
