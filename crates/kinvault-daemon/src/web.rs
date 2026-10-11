//! Web interface (`kinvaultd --web <addr>`): serves the desktop app's UI over
//! HTTP for headless machines such as a NAS, with the Tauri bridge replaced by
//! `web/web.js`. Everything except the static files needs a session from
//! signing in with the web password.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::extract::{Json, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, broadcast};

use crate::Daemon;
use crate::api::{Event, Request};

const SESSION_COOKIE: &str = "kv_session";
const SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(1);
const MAX_DIR_ENTRIES: usize = 5000;

macro_rules! ui_file {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../kinvault-gui/ui/",
            $name
        ))
    };
}
macro_rules! web_file {
    ($name:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/", $name))
    };
}

/// The desktop app's page, loading the web bridge before the app.
static INDEX: LazyLock<String> = LazyLock::new(|| {
    let page = std::str::from_utf8(ui_file!("index.html")).expect("index.html is UTF-8");
    let css = r#"<link rel="stylesheet" href="style.css">"#;
    let app = r#"<script src="app.js"></script>"#;
    assert!(
        page.contains(css) && page.contains(app),
        "index.html changed"
    );
    page.replace(
        css,
        &format!(r#"{css}<link rel="stylesheet" href="web.css">"#),
    )
    .replace(app, &format!(r#"<script src="web.js"></script>{app}"#))
});

struct Web {
    daemon: Daemon,
    password: blake3::Hash,
    sessions: std::sync::Mutex<HashMap<String, Instant>>,
    /// Held during a password check, so guesses are made one at a time.
    login: Mutex<()>,
}

type Shared = State<Arc<Web>>;
type Rejection = (StatusCode, &'static str);

/// Serves the web interface on `listener` until the daemon shuts down.
pub async fn serve(daemon: Daemon, listener: TcpListener, password: &str) -> Result<()> {
    let web = Arc::new(Web {
        daemon,
        password: blake3::hash(password.as_bytes()),
        sessions: Default::default(),
        login: Mutex::new(()),
    });
    axum::serve(listener, router(web)).await?;
    Ok(())
}

fn router(web: Arc<Web>) -> Router {
    let file = |body: &'static [u8], kind: &'static str| {
        get(move || async move { ([(header::CONTENT_TYPE, kind)], body) })
    };
    Router::new()
        .route("/", get(index))
        .route("/app.js", file(ui_file!("app.js"), "text/javascript"))
        .route("/style.css", file(ui_file!("style.css"), "text/css"))
        .route("/logo.png", file(ui_file!("logo.png"), "image/png"))
        .route("/web.js", file(web_file!("web.js"), "text/javascript"))
        .route("/web.css", file(web_file!("web.css"), "text/css"))
        .route("/login.js", file(web_file!("login.js"), "text/javascript"))
        .route("/api/session", get(session))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/call", post(call))
        .route("/api/list-dir", post(list_dir))
        .route("/api/events", get(events))
        .layer(middleware::map_response(security_headers))
        .with_state(web)
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             frame-ancestors 'none'; form-action 'self'",
        ),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(SESSION_COOKIE)?.strip_prefix('='))
}

impl Web {
    fn signed_in(&self, headers: &HeaderMap) -> bool {
        let Some(token) = session_token(headers) else {
            return false;
        };
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(expires) if *expires > Instant::now() => true,
            Some(_) => {
                sessions.remove(token);
                false
            }
            None => false,
        }
    }

    /// Checks the session, and for state-changing requests the custom header
    /// that a cross-site form or script can't send without CORS approval.
    fn check(&self, headers: &HeaderMap, changes_state: bool) -> Result<(), Rejection> {
        if changes_state && headers.get("x-kinvault").is_none_or(|v| v != "1") {
            return Err((StatusCode::FORBIDDEN, "missing X-KinVault header"));
        }
        if !self.signed_in(headers) {
            return Err((StatusCode::UNAUTHORIZED, "sign in first"));
        }
        Ok(())
    }
}

async fn index(State(web): Shared, headers: HeaderMap) -> Response {
    let page: &[u8] = if web.signed_in(&headers) {
        INDEX.as_bytes()
    } else {
        web_file!("login.html")
    };
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response()
}

async fn session(State(web): Shared, headers: HeaderMap) -> StatusCode {
    if web.signed_in(&headers) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::UNAUTHORIZED
    }
}

#[derive(Deserialize)]
struct Login {
    password: String,
}

async fn login(State(web): Shared, headers: HeaderMap, Json(req): Json<Login>) -> Response {
    if headers.get("x-kinvault").is_none_or(|v| v != "1") {
        return (StatusCode::FORBIDDEN, "missing X-KinVault header").into_response();
    }
    let _one_at_a_time = web.login.lock().await;
    // blake3::Hash compares in constant time.
    if blake3::hash(req.password.as_bytes()) != web.password {
        tokio::time::sleep(FAILED_LOGIN_DELAY).await;
        return (StatusCode::UNAUTHORIZED, "Wrong password.").into_response();
    }
    let Ok(token) = kinvault_core::crypto::random_bytes::<32>() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let token = hex::encode(token);
    {
        let mut sessions = web.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, expires| *expires > now);
        sessions.insert(token.clone(), now + SESSION_TTL);
    }
    // Secure only behind an HTTPS proxy; plain-HTTP LAN access must still work.
    let secure = headers
        .get("x-forwarded-proto")
        .is_some_and(|v| v == "https");
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        SESSION_TTL.as_secs(),
        if secure { "; Secure" } else { "" }
    );
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response()
}

async fn logout(State(web): Shared, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&headers) {
        web.sessions.lock().unwrap().remove(token);
    }
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response()
}

/// Same request/reply JSON as the desktop app's `daemon_call` command.
async fn call(
    State(web): Shared,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if let Err(res) = web.check(&headers, true) {
        return res.into_response();
    }
    let req: Request = match serde_json::from_value(req) {
        Ok(Request::Subscribe) => {
            return (StatusCode::BAD_REQUEST, "use /api/events").into_response();
        }
        Ok(req) => req,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad request: {e}")).into_response(),
    };
    match web.daemon.handle(req).await {
        Ok(reply) => Json(reply).into_response(),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, e).into_response(),
    }
}

#[derive(Deserialize)]
struct ListDir {
    path: String,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct DirListing {
    path: PathBuf,
    parent: Option<PathBuf>,
    dirs: Vec<String>,
}

/// Lists the folders inside a directory, for choosing what to back up or
/// where to restore on the server.
async fn list_dir(State(web): Shared, headers: HeaderMap, Json(req): Json<ListDir>) -> Response {
    if let Err(res) = web.check(&headers, true) {
        return res.into_response();
    }
    let path = match req.path.trim() {
        "" => PathBuf::from("/"),
        p => PathBuf::from(p),
    };
    match tokio::task::spawn_blocking(move || read_dirs(&path)).await {
        Ok(Ok(listing)) => Json(listing).into_response(),
        Ok(Err(e)) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{e:#}")).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn read_dirs(path: &Path) -> Result<DirListing> {
    anyhow::ensure!(path.is_absolute(), "enter a full path, starting with /");
    let path =
        std::fs::canonicalize(path).with_context(|| format!("can't open {}", path.display()))?;
    let mut dirs: Vec<String> = std::fs::read_dir(&path)
        .with_context(|| format!("can't open {}", path.display()))?
        .filter_map(|entry| entry.ok())
        // Follows symlinks, so linked folders show up too.
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .take(MAX_DIR_ENTRIES)
        .collect();
    dirs.sort_by_key(|d| d.to_lowercase());
    Ok(DirListing {
        parent: path.parent().map(Path::to_path_buf),
        path,
        dirs,
    })
}

/// The daemon's live events as server-sent events.
async fn events(State(web): Shared, headers: HeaderMap) -> Response {
    if let Err(res) = web.check(&headers, false) {
        return res.into_response();
    }
    let rx = web.daemon.subscribe();
    let stream: std::pin::Pin<Box<dyn Stream<Item = Result<SseEvent, Infallible>> + Send>> =
        Box::pin(stream::unfold(rx, |mut rx| async move {
            let event = match rx.recv().await {
                Ok(event) => event,
                // Missed some: have the page reload everything.
                Err(broadcast::error::RecvError::Lagged(_)) => Event::SetsChanged,
                Err(broadcast::error::RecvError::Closed) => return None,
            };
            let data = serde_json::to_string(&event).unwrap_or_default();
            Some((Ok(SseEvent::default().data(data)), rx))
        }));
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// The web password: `KINVAULT_WEB_PASSWORD` if set, otherwise one generated
/// on first use and kept in `<state>/web-password`.
pub fn password(state_dir: &Path) -> Result<String> {
    if let Ok(password) = std::env::var("KINVAULT_WEB_PASSWORD")
        && !password.is_empty()
    {
        return Ok(password);
    }
    let path = state_dir.join("web-password");
    match std::fs::read_to_string(&path) {
        Ok(password) if !password.trim().is_empty() => return Ok(password.trim().to_string()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    let password = data_encoding::BASE32_NOPAD
        .encode(&kinvault_core::crypto::random_bytes::<15>()?)
        .to_ascii_lowercase();
    crate::config::write_private(&path, password.as_bytes())?;
    tracing::warn!(
        "generated a password for the web interface: {password} (kept in {}; \
         set KINVAULT_WEB_PASSWORD to choose your own)",
        path.display()
    );
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_loads_the_web_bridge_first() {
        let web = INDEX.find("web.js").unwrap();
        let app = INDEX.find("app.js").unwrap();
        assert!(web < app);
        assert!(INDEX.contains("web.css"));
    }

    #[test]
    fn reads_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; kv_session=abc123; other=1"),
        );
        assert_eq!(session_token(&headers), Some("abc123"));
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("kv_sessionx=1"));
        assert_eq!(session_token(&headers), None);
    }

    #[test]
    fn lists_only_folders() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("b")).unwrap();
        std::fs::create_dir(tmp.path().join("A")).unwrap();
        std::fs::write(tmp.path().join("file.txt"), b"x").unwrap();
        let listing = read_dirs(tmp.path()).unwrap();
        assert_eq!(listing.dirs, ["A", "b"]);
        assert_eq!(
            listing.parent.as_deref(),
            std::fs::canonicalize(tmp.path()).unwrap().parent()
        );
        assert!(read_dirs(Path::new("relative")).is_err());
    }
}
