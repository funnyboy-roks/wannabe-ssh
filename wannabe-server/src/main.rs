use std::{collections::HashMap, env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use once_cell::sync::OnceCell;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssh_key::{PublicKey, SshSig};
use tokio::{
    fs,
    sync::{mpsc, Mutex},
    time::timeout,
};
use tower::ServiceBuilder;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies, Key};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::{debug, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;

#[derive(Debug, Clone)]
struct Client {
    pub send: mpsc::UnboundedSender<Message>,
    // Action Name: Action
    pub actions: Vec<String>,
}

#[derive(Debug, Clone)]
struct Session {
    pub name: String,
    // pub expires: tower_cookies::cookie::time::OffsetDateTime, // TODO
}

#[derive(Debug)]
struct AppState {
    // Name: Client
    pub clients: Mutex<HashMap<String, Client>>, // Web socket clients
    // Token: Session
    pub sessions: Mutex<HashMap<String, Session>>, // Web Sessions
    pub config: config::Config,
}

async fn handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    eprintln!("Client connect");
    ws.on_upgrade(move |ws| async {
        if let Err(e) = handle_socket(ws, state).await {
            debug!("error => {}", e);
        }
    })
}

async fn handle_socket(mut ws: WebSocket, state: Arc<AppState>) -> anyhow::Result<()> {
    debug!("Client fresh");
    let id = ulid::Generator::new()
        .generate_from_datetime(std::time::SystemTime::now())
        .unwrap()
        .to_string();

    // Check name (timeout of 60s)
    let (name, pubkey) = match timeout(Duration::from_secs(60), ws.recv()).await {
        Ok(Some(Ok(Message::Text(name)))) => {
            if let Some(cfg) = state.config.clients.get(&name) {
                (
                    name,
                    fs::read_to_string(&cfg.ssh_key)
                        .await?
                        .parse::<PublicKey>()?,
                )
            } else {
                return Ok(());
            }
        }
        _ => {
            debug!("Disconnecting client because of no initial message");
            return Ok(());
        }
    };

    debug!(name, "Confirmed client name");

    ws.send(Message::Text(id.clone())).await?;

    debug!(name, id, "Client pending verification");
    let msg = ws.recv().await;
    if let Some(Ok(Message::Text(msg))) = msg {
        let Ok(sig) = msg.parse::<SshSig>() else {
            warn!(id, msg, "Invalid ssh signature");
            return Ok(());
        };

        let verify = pubkey.verify("wannabe_ssh", id.as_bytes(), &sig);

        if let Err(e) = verify {
            debug!("Kicking Client for bad verification: {:?}", e);

            ws.send(Message::Close(Some(CloseFrame {
                code: 1002,
                reason: "bad verification".into(),
            })))
            .await?;

            return Ok(());
        }
    } else {
        return Ok(());
    }

    debug!(name, id, "Successfully connected.");
    ws.send(Message::Text("success".into())).await?;

    let (tx, mut rx) = mpsc::unbounded_channel();

    // /// Update _from_ the client
    // #[derive(Deserialize)]
    // #[serde(tag = "type")]
    // enum ClientAction {
    //     SetActions { actions: Vec<String> },
    //     AddAction { action: String },
    // }

    let actions = serde_json::from_str(
        ws.recv()
            .await
            .context("Did not get actions from server")??
            .to_text()?,
    )?;

    debug!(name, id, ?actions, "Got client actions");

    let mut clients = state.clients.lock().await;
    clients.insert(name.clone(), Client { send: tx, actions });
    drop(clients);
    dbg!(&state);

    //debug!("Waiting for the stuff or soemthign");
    //while let Some(msg) = ws.recv().await {
    //    let msg = if let Ok(msg) = msg {
    //        debug!(name, id, "Got message: {:?}", msg);
    //        msg
    //    } else {
    //        debug!(name, id, "Client disconnect");
    //        return Ok(());
    //    };

    //    if let Err(err) = ws.send(msg).await {
    //        debug!(name, id, "Client disconnect: {:?}", err);
    //        return Ok(());
    //    }
    //}
    while let Some(msg) = rx.recv().await {
        debug!(name, id, "sending message: {:?}", msg);
        if let Err(e) = ws.send(msg).await {
            state.clients.lock().await.remove(&name);
            Err(e)?
        }
    }
    Ok(())
}

async fn auth_callback(
    Query(params): Query<HashMap<String, String>>,
    cookies: Cookies,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Some(code) = params.get("code") {
        #[derive(Serialize)]
        struct Request {
            client_id: String,
            client_secret: String,
            code: String,
        }

        let client = reqwest::Client::new();
        let res = client
            .post("https://github.com/login/oauth/access_token")
            .json(&json!({
                "client_id": state.config.github.client_id,
                "client_secret": state.config.github.client_secret,
                "code": code
            }))
            .header("accept", "application/json")
            .send()
            .await;
        if let Ok(res) = res {
            if let Ok(res) = res.json::<serde_json::Value>().await {
                dbg!(&res);
                if let Some(tok) = res.get("access_token") {
                    if let Some(tok) = tok.as_str() {
                        let privcooks = cookies.private(KEY.get().unwrap());
                        let mut cookie = Cookie::new("auth", tok.to_string());
                        cookie.set_max_age(tower_cookies::cookie::time::Duration::days(2));
                        privcooks.add(cookie.clone());

                        let res = client
                            .get("https://api.github.com/user/emails")
                            .header("User-Agent", "Wannabe-Ssh")
                            .header("Authorization", format!("Bearer {}", tok))
                            .send()
                            .await
                            .unwrap();
                        dbg!(&res);
                        //dbg!(res.text().await).unwrap();

                        #[derive(Deserialize)]
                        struct EmailRes {
                            email: String,
                            primary: bool,
                        }

                        let res: Vec<EmailRes> = match res.json().await {
                            Ok(res) => res,
                            Err(e) => {
                                dbg!(e);
                                return Redirect::to("/"); // TODO
                            }
                        };

                        let email = res
                            .iter()
                            .find_map(|v| v.primary.then(|| v.email.clone()))
                            .unwrap();

                        let mut name = None;
                        for (n, user) in &state.config.users {
                            if user.email == email {
                                name = Some(n.clone());
                                break;
                            }
                        }

                        dbg!(&email);

                        let Some(name) = name else {
                            return Redirect::to("/?authorised=0");
                        };

                        eprintln!("Authing {} with {}", name, email);

                        let session = Session {
                            name,
                            //expires: cookie.expires().unwrap(),
                        };
                        state.sessions.lock().await.insert(tok.to_string(), session);

                        return Redirect::to("/?authorised=1");
                    }
                }
            }
        }
    }
    Redirect::to("/?authorised=0")
}

async fn validate(cookies: Cookies, state: &Arc<AppState>) -> Option<Session> {
    let privcooks = cookies.private(KEY.get().unwrap());
    //privcooks.add(Cookie::new("auth", tok.to_string()));
    let Some(cookie) = privcooks.get("auth") else {
        return None;
    };

    // TODO: check for expired cookie

    let tok = cookie.value();

    let session_lock = state.sessions.lock().await;
    session_lock.get(tok).cloned()
}

async fn commands(
    cookies: Cookies,
    State(state): State<Arc<AppState>>,
) -> Result<Response, StatusCode> {
    let Some(session) = validate(cookies, &state).await else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let clients = state.clients.lock().await;

    let map: HashMap<_, _> = state.config.users[&session.name]
        .clients
        .iter()
        .map(|c| (c, &clients[c].actions))
        .collect();

    Ok(Json(map).into_response())
}

#[derive(Clone, Debug, Deserialize)]
struct ExecReq {
    pub client: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize)]
struct ActionCall<'a> {
    pub action: &'a str,
    pub caller: &'a str,
}

async fn exec(
    cookies: Cookies,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ExecReq>,
) -> Result<StatusCode, StatusCode> {
    let Some(session) = validate(cookies, &state).await else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let clients = state.clients.lock().await;

    let Some(client) = clients.get(&req.client) else {
        return Err(StatusCode::NOT_FOUND);
    };

    if !client.actions.contains(&req.action) {
        return Err(StatusCode::NOT_FOUND);
    }

    match client.send.send(Message::Text(
        serde_json::to_string(&ActionCall {
            action: &req.action,
            caller: &state.config.users[&session.name].email,
        })
        .map_err(|_| StatusCode::BAD_REQUEST)?,
    )) {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(StatusCode::GONE),
    }
}

static KEY: OnceCell<Key> = OnceCell::new();

#[tokio::main]
async fn main() {
    KEY.set(Key::from(&[0; 64])).ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wannabe_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let config = dbg!(config::load("config.toml").await.unwrap());
    let client_id = config.github.client_id.clone();

    // build our application with a single route
    let app = Router::new()
        .route("/ws", get(handler))
        .route(
            "/clients",
            get(|State(state): State<Arc<AppState>>| async move {
                for client in state.clients.lock().await.values() {
                    client.send.send(Message::Text("hallo".into())).unwrap();
                }
                format!("{}", state.clients.lock().await.len())
            }),
        )
        .route("/api/auth", get(auth_callback))
        .route(
            "/api/is_authed",
            get(
                |cookies: Cookies, State(state): State<Arc<AppState>>| async move {
                    if validate(cookies, &state).await.is_some() {
                        "1"
                    } else {
                        "0"
                    }
                },
            ),
        )
        .route(
            "/api/auth/gh",
            get(|| async move {
                Redirect::to(&format!(
                    "https://github.com/login/oauth/authorize?scope=user:email&client_id={}",
                    client_id
                ))
            }),
        )
        .route("/api/commands", get(commands))
        .route("/api/exec", post(exec))
        .layer(CookieManagerLayer::new())
        .fallback_service(
            ServeDir::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("site"))
                .append_index_html_on_directories(true),
        )
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(Arc::new(AppState {
            clients: Default::default(),
            config,
            sessions: Default::default(),
        }));

    let mut addr = "0.0.0.0:3000".parse::<SocketAddr>().unwrap();

    addr.set_port(
        env::var("PORT")
            .ok()
            .map(|v| v.parse().unwrap())
            .unwrap_or(3000),
    );

    println!("Listening at http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
