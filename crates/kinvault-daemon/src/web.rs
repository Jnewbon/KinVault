//! Web interface (`kinvaultd --web <addr>`): serves the desktop app's UI over
//! HTTP for headless machines such as a NAS, with the Tauri bridge replaced by
//! `web/web.js`. Everything except the static files needs a session from
//! signing in with the web password.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::extract::{ConnectInfo, Json, Request as HttpRequest, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast};

use crate::Daemon;
use crate::api::{Event, Request};

const SESSION_COOKIE: &str = "kv_session";
/// A session ends this long after signing in, or after this long unused.
const SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const SESSION_IDLE: Duration = Duration::from_secs(24 * 60 * 60);
/// Sessions kept at once; signing in again ends the least recently used.
const MAX_SESSIONS: usize = 32;
/// Wrong passwords from one address make it wait longer each time, up to
/// this long; forgotten after an hour without tries.
const MAX_LOGIN_BACKOFF: Duration = Duration::from_secs(15 * 60);
const FORGET_FAILURES_AFTER: Duration = Duration::from_secs(60 * 60);
/// Addresses whose failed tries are remembered at once.
const MAX_TRACKED_ADDRESSES: usize = 4096;
/// Password checks running at once (each takes ~20 MiB and some CPU).
const CONCURRENT_CHECKS: usize = 2;
/// Shortest `KINVAULT_WEB_PASSWORD` accepted.
pub const MIN_PASSWORD_LEN: usize = 12;
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

/// How the web interface is reached.
#[derive(Clone, Debug, Default)]
pub struct WebOptions {
    /// It's only reached through an HTTPS reverse proxy: session cookies
    /// are marked `Secure`.
    pub behind_https: bool,
    /// Host names (as in the `Host` header, without the port) it may be
    /// reached by. Empty: any. Setting it stops DNS-rebinding pages.
    pub allowed_hosts: Vec<String>,
}

struct Web {
    daemon: Daemon,
    password: PasswordHash,
    sessions: std::sync::Mutex<HashMap<String, Session>>,
    /// Wrong passwords, per address they came from.
    failures: std::sync::Mutex<HashMap<IpAddr, Failures>>,
    checks: Semaphore,
    options: WebOptions,
}

struct Session {
    created: Instant,
    last_used: Instant,
}

#[derive(Default)]
struct Failures {
    count: u32,
    /// No more tries from that address before this.
    next_try: Option<Instant>,
}

/// An Argon2id hash of the web password, made at start.
struct PasswordHash {
    salt: [u8; 16],
    hash: blake3::Hash,
}

impl PasswordHash {
    fn new(password: &str) -> Result<Self> {
        let salt = kinvault_core::crypto::random_bytes::<16>()?;
        let hash = Self::derive(password, &salt)?;
        Ok(Self { salt, hash })
    }

    fn derive(password: &str, salt: &[u8; 16]) -> Result<blake3::Hash> {
        let params = argon2::Params::new(19 * 1024, 2, 1, Some(32))
            .map_err(|e| anyhow::anyhow!("argon2 parameters: {e}"))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(password.as_bytes(), salt, &mut out)
            .map_err(|e| anyhow::anyhow!("hashing the password: {e}"))?;
        // blake3::Hash compares in constant time.
        Ok(blake3::Hash::from(out))
    }

    fn matches(&self, password: &str) -> bool {
        Self::derive(password, &self.salt).is_ok_and(|h| h == self.hash)
    }
}

type Shared = State<Arc<Web>>;
type Rejection = (StatusCode, &'static str);

/// Serves the web interface on `listener` until the daemon shuts down.
pub async fn serve(
    daemon: Daemon,
    listener: TcpListener,
    password: &str,
    options: WebOptions,
) -> Result<()> {
    let web = Arc::new(Web::new(daemon, password, options)?);
    axum::serve(
        listener,
        router(web).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
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
        .layer(middleware::from_fn_with_state(web.clone(), check_origin))
        .layer(middleware::map_response(security_headers))
        .with_state(web)
}

/// Refuses requests for a host name not allowed (see
/// [`WebOptions::allowed_hosts`]), and state-changing requests a browser
/// sent from a page of another origin.
async fn check_origin(State(web): Shared, req: HttpRequest, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !web.options.allowed_hosts.is_empty() {
        let name = host_name(host);
        if !web
            .options
            .allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
        {
            return (StatusCode::MISDIRECTED_REQUEST, "unknown host name").into_response();
        }
    }
    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        // Browsers send Origin with every such request; tools may not.
        if let Some(origin) = req.headers().get(header::ORIGIN) {
            let same = origin
                .to_str()
                .ok()
                .and_then(|o| o.split_once("://"))
                .is_some_and(|(_, authority)| authority.eq_ignore_ascii_case(host));
            if !same {
                return (StatusCode::FORBIDDEN, "cross-origin request").into_response();
            }
        }
    }
    next.run(req).await
}

/// `host[:port]` without the port (and without brackets for IPv6).
fn host_name(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
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
    fn new(daemon: Daemon, password: &str, options: WebOptions) -> Result<Self> {
        Ok(Self {
            daemon,
            password: PasswordHash::new(password)?,
            sessions: Default::default(),
            failures: Default::default(),
            checks: Semaphore::new(CONCURRENT_CHECKS),
            options,
        })
    }

    fn signed_in(&self, headers: &HeaderMap) -> bool {
        let Some(token) = session_token(headers) else {
            return false;
        };
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        match sessions.get_mut(token) {
            Some(s) if live(s, now) => {
                s.last_used = now;
                true
            }
            Some(_) => {
                sessions.remove(token);
                false
            }
            None => false,
        }
    }

    /// Counts a try at the password from `ip`, unless it must wait first;
    /// then returns how long.
    fn take_try(&self, ip: IpAddr) -> Result<(), Duration> {
        let now = Instant::now();
        let mut failures = self.failures.lock().unwrap();
        failures.retain(|_, f| f.next_try.is_some_and(|t| t + FORGET_FAILURES_AFTER > now));
        if failures.len() >= MAX_TRACKED_ADDRESSES && !failures.contains_key(&ip) {
            // Forget whoever may try again soonest.
            if let Some(oldest) = failures
                .iter()
                .min_by_key(|(_, f)| f.next_try)
                .map(|(ip, _)| *ip)
            {
                failures.remove(&oldest);
            }
        }
        let f = failures.entry(ip).or_default();
        if let Some(next) = f.next_try
            && next > now
        {
            return Err(next - now);
        }
        // Counted before checking, so tries sent at once can't all go ahead.
        f.count += 1;
        f.next_try = Some(now + login_backoff(f.count));
        Ok(())
    }

    fn forget_failures(&self, ip: IpAddr) {
        self.failures.lock().unwrap().remove(&ip);
    }
}

fn live(s: &Session, now: Instant) -> bool {
    now < s.created + SESSION_TTL && now < s.last_used + SESSION_IDLE
}

/// How long to wait after the `count`th try: a second at first, doubling
/// after the second wrong one.
fn login_backoff(count: u32) -> Duration {
    let secs = 1u64 << count.saturating_sub(2).min(20);
    Duration::from_secs(secs).min(MAX_LOGIN_BACKOFF)
}

impl Web {
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

async fn login(
    State(web): Shared,
    ConnectInfo(from): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<Login>,
) -> Response {
    if headers.get("x-kinvault").is_none_or(|v| v != "1") {
        return (StatusCode::FORBIDDEN, "missing X-KinVault header").into_response();
    }
    // Per address, so someone guessing doesn't hold up anyone else.
    if let Err(wait) = web.take_try(from.ip()) {
        let secs = wait.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, secs.to_string())],
            format!("Too many tries. Wait {secs} seconds and try again."),
        )
            .into_response();
    }
    let matches = {
        let Ok(_slot) = web.checks.acquire().await else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let web = web.clone();
        tokio::task::spawn_blocking(move || web.password.matches(&req.password))
            .await
            .unwrap_or(false)
    };
    if !matches {
        return (StatusCode::UNAUTHORIZED, "Wrong password.").into_response();
    }
    web.forget_failures(from.ip());
    let Ok(token) = kinvault_core::crypto::random_bytes::<32>() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let token = hex::encode(token);
    {
        let mut sessions = web.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, s| live(s, now));
        while sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, s)| s.last_used)
                .map(|(t, _)| t.clone())
            else {
                break;
            };
            sessions.remove(&oldest);
        }
        sessions.insert(
            token.clone(),
            Session {
                created: now,
                last_used: now,
            },
        );
    }
    // Secure only when configured as behind an HTTPS proxy (a header from
    // the client can't be trusted for that); plain-HTTP LAN access must
    // still work.
    let secure = web.options.behind_https;
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

fn check_password_len(password: &str) -> Result<()> {
    anyhow::ensure!(
        password.chars().count() >= MIN_PASSWORD_LEN,
        "KINVAULT_WEB_PASSWORD must be at least {MIN_PASSWORD_LEN} characters"
    );
    Ok(())
}

/// The web password: `KINVAULT_WEB_PASSWORD` if set, otherwise one generated
/// on first use and kept in `<state>/web-password`.
pub fn password(state_dir: &Path) -> Result<String> {
    if let Ok(password) = std::env::var("KINVAULT_WEB_PASSWORD")
        && !password.is_empty()
    {
        check_password_len(&password)?;
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
    // Not the password itself: logs are often kept or shipped elsewhere,
    // readable by more people than the state folder.
    tracing::warn!(
        "generated a password for the web interface; read it from {} \
         (or set KINVAULT_WEB_PASSWORD to choose your own)",
        path.display()
    );
    Ok(password)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use tower::ServiceExt;

    use super::*;

    const PASSWORD: &str = "correct horse battery";

    async fn test_web(options: WebOptions) -> (Arc<Web>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .clear_ip_transports()
            .bind_addr(("127.0.0.1", 0))
            .unwrap()
            .bind()
            .await
            .unwrap();
        let daemon = Daemon::start(crate::DaemonOptions {
            state_dir: tmp.path().to_path_buf(),
            endpoint: Some(endpoint),
            nearby: Default::default(),
            reachability: Default::default(),
        })
        .await
        .unwrap();
        (Arc::new(Web::new(daemon, PASSWORD, options).unwrap()), tmp)
    }

    /// The router as seen from `ip`.
    fn from(web: &Arc<Web>, ip: [u8; 4]) -> Router {
        router(web.clone()).layer(MockConnectInfo(SocketAddr::from((ip, 50000))))
    }

    fn login_request(password: &str) -> HttpRequest {
        axum::http::Request::post("/api/login")
            .header(header::HOST, "nas.lan:8080")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-kinvault", "1")
            .body(Body::from(
                serde_json::json!({ "password": password }).to_string(),
            ))
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_passwords_slow_down_only_their_sender() {
        let (web, _tmp) = test_web(WebOptions::default()).await;
        let (attacker, user) = (from(&web, [10, 0, 0, 66]), from(&web, [10, 0, 0, 2]));
        let res = attacker
            .clone()
            .oneshot(login_request("guess"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        // The next guess must wait, and is refused at once rather than queued.
        let started = Instant::now();
        let res = attacker
            .clone()
            .oneshot(login_request(PASSWORD))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(res.headers().contains_key(header::RETRY_AFTER));
        // Someone else signs in straight away.
        let res = user.clone().oneshot(login_request(PASSWORD)).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(started.elapsed() < LOGIN_BUDGET);
        let cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(
            cookie.contains("HttpOnly") && !cookie.contains("Secure"),
            "{cookie}"
        );
    }

    /// How long a successful sign-in may take, Argon2 included.
    const LOGIN_BUDGET: Duration = Duration::from_secs(5);

    #[test]
    fn waits_grow_after_repeated_failures() {
        assert_eq!(login_backoff(1), Duration::from_secs(1));
        assert_eq!(login_backoff(2), Duration::from_secs(1));
        assert_eq!(login_backoff(3), Duration::from_secs(2));
        assert_eq!(login_backoff(6), Duration::from_secs(16));
        assert_eq!(login_backoff(1000), MAX_LOGIN_BACKOFF);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cross_origin_and_unknown_hosts_are_refused() {
        let (web, _tmp) = test_web(WebOptions {
            allowed_hosts: vec!["nas.lan".into()],
            ..Default::default()
        })
        .await;
        let app = from(&web, [10, 0, 0, 2]);
        let mut req = login_request(PASSWORD);
        req.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("http://evil.example"),
        );
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // A DNS-rebinding page: same origin as far as the browser knows,
        // but not a host name this server answers to.
        let mut req = login_request(PASSWORD);
        req.headers_mut()
            .insert(header::HOST, HeaderValue::from_static("evil.example:8080"));
        req.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("http://evil.example:8080"),
        );
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::MISDIRECTED_REQUEST);

        let mut req = login_request(PASSWORD);
        req.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("http://nas.lan:8080"),
        );
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn secure_cookies_follow_the_setting_not_a_header() {
        let (web, _tmp) = test_web(WebOptions::default()).await;
        let mut req = login_request(PASSWORD);
        req.headers_mut()
            .insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let res = from(&web, [10, 0, 0, 2]).oneshot(req).await.unwrap();
        let cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(!cookie.contains("Secure"), "{cookie}");

        let (web, _tmp) = test_web(WebOptions {
            behind_https: true,
            ..Default::default()
        })
        .await;
        let res = from(&web, [10, 0, 0, 2])
            .oneshot(login_request(PASSWORD))
            .await
            .unwrap();
        let cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.contains("; Secure"), "{cookie}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sessions_end_when_idle_and_are_capped() {
        let (web, _tmp) = test_web(WebOptions::default()).await;
        let app = from(&web, [10, 0, 0, 2]);
        let mut tokens = Vec::new();
        for _ in 0..=MAX_SESSIONS {
            let res = app.clone().oneshot(login_request(PASSWORD)).await.unwrap();
            let cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
            let token = cookie.split(';').next().unwrap().to_string();
            tokens.push(token);
        }
        assert_eq!(web.sessions.lock().unwrap().len(), MAX_SESSIONS);
        let headers = |token: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::COOKIE, HeaderValue::from_str(token).unwrap());
            h
        };
        // The least recently used made way.
        assert!(!web.signed_in(&headers(&tokens[0])));
        let newest = tokens.last().unwrap();
        assert!(web.signed_in(&headers(newest)));
        // Unused for a day: signed out.
        let key = newest.strip_prefix("kv_session=").unwrap();
        web.sessions.lock().unwrap().get_mut(key).unwrap().last_used =
            Instant::now() - SESSION_IDLE - Duration::from_secs(1);
        assert!(!web.signed_in(&headers(newest)));
    }

    #[test]
    fn generated_passwords_are_not_logged() {
        use std::io::Write;
        #[derive(Clone, Default)]
        struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .finish();
        let tmp = tempfile::tempdir().unwrap();
        // Assumes KINVAULT_WEB_PASSWORD isn't set where tests run.
        let password =
            tracing::subscriber::with_default(subscriber, || super::password(tmp.path()).unwrap());
        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("web-password"), "{logged}");
        assert!(!logged.contains(&password), "{logged}");
    }

    #[test]
    fn short_passwords_are_refused() {
        assert!(check_password_len("short").is_err());
        assert!(check_password_len(&"x".repeat(MIN_PASSWORD_LEN)).is_ok());
    }

    #[test]
    fn host_names_drop_the_port() {
        assert_eq!(host_name("nas.lan:8080"), "nas.lan");
        assert_eq!(host_name("nas.lan"), "nas.lan");
        assert_eq!(host_name("[::1]:8080"), "::1");
        assert_eq!(host_name("192.0.2.1:80"), "192.0.2.1");
    }

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
