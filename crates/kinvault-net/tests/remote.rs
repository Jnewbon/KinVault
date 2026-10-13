//! Two real iroh endpoints talking over localhost (no relays or DNS discovery).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use kinvault_core::{Backend, Index, MasterKey, PackId, Repository};
use kinvault_net::{Grant, NetError, Receiver, RemoteBackend, serve};

const MARKER: &[u8] = b"KINVAULT-REMOTE-PLAINTEXT-MARKER";

async fn local_endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

struct Host {
    router: Router,
    receiver: Receiver,
    store: PathBuf,
}

impl Host {
    async fn start(store: PathBuf) -> Self {
        let receiver = Receiver::new(&store);
        let router = serve(local_endpoint().await, receiver.clone());
        Self {
            router,
            receiver,
            store,
        }
    }

    fn addr(&self) -> EndpointAddr {
        let ep = self.router.endpoint();
        EndpointAddr::new(ep.id()).with_ip_addr(ep.bound_sockets()[0])
    }
}

async fn client(host: &Host, repo: &str) -> (Endpoint, Arc<RemoteBackend>) {
    let ep = local_endpoint().await;
    let backend = RemoteBackend::new(
        ep.clone(),
        host.addr(),
        repo,
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    (ep, Arc::new(backend))
}

/// `Arc<RemoteBackend>` so the test can keep a handle while the repo owns one.
struct Shared(Arc<RemoteBackend>);

impl Backend for Shared {
    fn put_pack(&self, id: &PackId, data: &[u8]) -> kinvault_core::Result<()> {
        self.0.put_pack(id, data)
    }
    fn get_pack(&self, id: &PackId) -> kinvault_core::Result<Vec<u8>> {
        self.0.get_pack(id)
    }
    fn get_pack_tail(&self, id: &PackId, max_len: u64) -> kinvault_core::Result<(u64, Vec<u8>)> {
        self.0.get_pack_tail(id, max_len)
    }
    fn list_packs(&self) -> kinvault_core::Result<Vec<PackId>> {
        self.0.list_packs()
    }
    fn delete_pack(&self, id: &PackId) -> kinvault_core::Result<()> {
        self.0.delete_pack(id)
    }
    fn put_snapshot(
        &self,
        id: &kinvault_core::SnapshotId,
        data: &[u8],
    ) -> kinvault_core::Result<()> {
        self.0.put_snapshot(id, data)
    }
    fn get_snapshot(&self, id: &kinvault_core::SnapshotId) -> kinvault_core::Result<Vec<u8>> {
        self.0.get_snapshot(id)
    }
    fn list_snapshots(&self) -> kinvault_core::Result<Vec<kinvault_core::SnapshotId>> {
        self.0.list_snapshots()
    }
    fn delete_snapshot(&self, id: &kinvault_core::SnapshotId) -> kinvault_core::Result<()> {
        self.0.delete_snapshot(id)
    }
}

fn make_source(dir: &Path) {
    fs::create_dir_all(dir.join("photos")).unwrap();
    fs::write(dir.join("diary.txt"), MARKER.repeat(500)).unwrap();
    let mut big = vec![0u8; 3 * 1024 * 1024];
    blake3::Hasher::new()
        .update(b"photo")
        .finalize_xof()
        .fill(&mut big);
    fs::write(dir.join("photos/beach.raw"), big).unwrap();
}

fn all_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            out.extend(all_files(&p))
        } else {
            out.push(p)
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_and_restore_through_remote_host() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    make_source(&src);
    let host = Host::start(tmp.path().join("host")).await;
    let (client_ep, remote) = client(&host, "laptop-docs").await;
    host.receiver.allow(client_ep.id(), Grant::default());

    let master = MasterKey::generate().unwrap();
    let (r, s, t) = (remote.clone(), src.clone(), tmp.path().to_path_buf());
    let out = tokio::task::spawn_blocking(move || {
        let mut repo =
            Repository::open(Shared(r.clone()), &master, Index::open_in_memory().unwrap());
        let (_, first) = repo.backup(std::slice::from_ref(&s), "laptop").unwrap();
        assert!(first.bytes_uploaded > 3 * 1024 * 1024 / 2);
        // Unchanged rerun only sends the snapshot record.
        let (snap, second) = repo.backup(std::slice::from_ref(&s), "laptop").unwrap();
        assert_eq!(second.bytes_uploaded, 0);
        assert_eq!(second.files_changed, 0);

        // A brand-new machine with only the key restores from the host.
        let mut fresh = Repository::open(Shared(r), &master, Index::open_in_memory().unwrap());
        let out = t.join("restored");
        fresh.restore(&snap, &out, None).unwrap();
        out
    })
    .await
    .unwrap();

    let root = kinvault_core::snapshot_root_name(&fs::canonicalize(&src).unwrap());
    assert_eq!(
        fs::read(out.join(&root).join("diary.txt")).unwrap(),
        MARKER.repeat(500)
    );
    assert_eq!(
        fs::read(out.join(&root).join("photos/beach.raw")).unwrap(),
        fs::read(src.join("photos/beach.raw")).unwrap()
    );

    // Host stored the data under the client's id, and can't read any of it.
    let peer_dir = host
        .store
        .join(client_ep.id().to_string())
        .join("laptop-docs");
    let stored = all_files(&peer_dir);
    assert!(!stored.is_empty());
    for f in stored {
        let bytes = fs::read(&f).unwrap();
        assert!(
            !bytes.windows(MARKER.len()).any(|w| w == MARKER),
            "plaintext in {f:?}"
        );
        assert!(
            !bytes.windows(9).any(|w| w == b"diary.txt"),
            "file name in {f:?}"
        );
    }

    let status = remote.status().await.unwrap();
    assert!(status.used_bytes > 0);
    host.router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_peer_is_denied() {
    let tmp = tempfile::tempdir().unwrap();
    let host = Host::start(tmp.path().join("host")).await;
    let (_ep, remote) = client(&host, "repo").await;
    let err = remote.status().await.unwrap_err();
    assert!(matches!(err, NetError::Denied(_)), "{err}");
    // Nothing was created on the host for the stranger.
    assert!(!host.store.exists() || fs::read_dir(&host.store).unwrap().next().is_none());
    host.router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_and_integrity_are_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let host = Host::start(tmp.path().join("host")).await;
    let (ep, remote) = client(&host, "repo").await;
    host.receiver.allow(
        ep.id(),
        Grant {
            quota_bytes: Some(1000),
            ..Default::default()
        },
    );

    let r = remote.clone();
    tokio::task::spawn_blocking(move || {
        let small = vec![1u8; 600];
        r.put_pack(&PackId(*blake3::hash(&small).as_bytes()), &small)
            .unwrap();

        // Second upload would exceed the 1000-byte quota.
        let more = vec![2u8; 600];
        let err = r
            .put_pack(&PackId(*blake3::hash(&more).as_bytes()), &more)
            .unwrap_err();
        assert!(err.to_string().contains("quota"), "{err}");

        // Content that doesn't match its claimed id is rejected.
        let err = r.put_pack(&PackId([0u8; 32]), b"tiny").unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");

        // Missing objects map to NotFound.
        let err = r.get_pack(&PackId([9u8; 32])).unwrap_err();
        assert!(matches!(err, kinvault_core::Error::NotFound(_)), "{err}");
    })
    .await
    .unwrap();

    assert_eq!(remote.status().await.unwrap().used_bytes, 600);
    host.receiver.revoke(&ep.id());
    assert!(matches!(
        remote.status().await.unwrap_err(),
        NetError::Denied(_)
    ));
    host.router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invites_grant_access_once() {
    use kinvault_net::{InviteAccepted, InviteHandler, InviteTicket, Offer, redeem_invite};

    let tmp = tempfile::tempdir().unwrap();
    let host = Host::start(tmp.path().join("host")).await;
    let token = [42u8; 16];
    let used = Arc::new(std::sync::Mutex::new(false));
    let (receiver, used2) = (host.receiver.clone(), used.clone());
    let handler: InviteHandler = Arc::new(move |r: kinvault_net::InviteRedemption| {
        let (receiver, used) = (receiver.clone(), used2.clone());
        Box::pin(async move {
            let mut used = used.lock().unwrap();
            if r.token != token || *used {
                return Err("invite is invalid or already used".to_string());
            }
            *used = true;
            assert_eq!(r.name.as_deref(), Some("bob"));
            assert_eq!(r.hosts, ["bob.example.org:4433"]);
            assert_eq!(
                r.offer,
                Some(Offer {
                    quota_bytes: Some(5)
                })
            );
            receiver.allow(
                r.peer,
                Grant {
                    quota_bytes: Some(1 << 20),
                    ..Default::default()
                },
            );
            Ok(InviteAccepted {
                host_name: "alice".into(),
                quota_bytes: Some(1 << 20),
            })
        })
    });
    host.receiver.set_invite_handler(handler);

    // Only the configured host name says where the host is.
    let port = host.router.endpoint().bound_sockets()[0].port();
    let mut ticket = InviteTicket {
        host: EndpointAddr::new(host.router.endpoint().id()),
        hosts: vec![format!("localhost:{port}")],
        host_name: "alice".into(),
        token: [0; 16],
        quota_bytes: Some(1 << 20),
        ask_reciprocal: true,
        expires_unix: i64::MAX,
    };
    let (ep, remote) = client(&host, "repo").await;
    let offer = Some(Offer {
        quota_bytes: Some(5),
    });

    // Wrong token: refused, and still no access.
    let err = redeem_invite(&ep, &ticket, Some("bob".into()), offer, bob_hosts())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::Denied(_)), "{err}");
    assert!(matches!(
        remote.status().await.unwrap_err(),
        NetError::Denied(_)
    ));

    ticket.token = token;
    let accepted = redeem_invite(&ep, &ticket, Some("bob".into()), offer, bob_hosts())
        .await
        .unwrap();
    assert_eq!(accepted.host_name, "alice");
    assert_eq!(remote.status().await.unwrap().quota_bytes, Some(1 << 20));

    // Single use.
    assert!(
        redeem_invite(&ep, &ticket, Some("bob".into()), offer, bob_hosts())
            .await
            .is_err()
    );
    host.router.shutdown().await.unwrap();
}

fn bob_hosts() -> Vec<String> {
    vec!["bob.example.org:4433".into()]
}

#[tokio::test(flavor = "multi_thread")]
async fn window_rate_limit_and_trash() {
    use kinvault_net::TimeWindow;

    let tmp = tempfile::tempdir().unwrap();
    let host = Host::start(tmp.path().join("host")).await;
    let (ep, remote) = client(&host, "repo").await;

    // A window that is closed right now (the hour that started 2 hours ago).
    let now = jiff::Zoned::now();
    let h = (now.hour() as u16 + 22) % 24;
    let closed = TimeWindow::new(h * 60, ((h + 1) % 24) * 60).unwrap();
    host.receiver.allow(
        ep.id(),
        Grant {
            window: Some(closed),
            ..Default::default()
        },
    );
    let r = remote.clone();
    let data = vec![3u8; 400_000];
    let id = PackId(*blake3::hash(&data).as_bytes());
    let d = data.clone();
    let err = tokio::task::spawn_blocking(move || r.put_pack(&id, &d))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().contains("only accepts uploads between"),
        "{err}"
    );
    // Reads still work outside the window (restores must never be blocked).
    remote.status().await.unwrap();

    // 400 kB at 200 kB/s takes about two seconds.
    host.receiver.allow(
        ep.id(),
        Grant {
            upload_limit: Some(200_000),
            ..Default::default()
        },
    );
    let r = remote.clone();
    let start = std::time::Instant::now();
    tokio::task::spawn_blocking(move || r.put_pack(&id, &data))
        .await
        .unwrap()
        .unwrap();
    let took = start.elapsed();
    assert!(
        took >= std::time::Duration::from_millis(1500),
        "upload took only {took:?}"
    );

    // Deleting moves to trash: hidden, still counted, purged after the grace period.
    let used = remote.status().await.unwrap().used_bytes;
    let r = remote.clone();
    tokio::task::spawn_blocking(move || {
        r.delete_pack(&id).unwrap();
        assert!(r.list_packs().unwrap().is_empty());
    })
    .await
    .unwrap();
    assert_eq!(remote.status().await.unwrap().used_bytes, used);
    let usage = host.receiver.usage_detail(&ep.id()).await.unwrap();
    assert_eq!((usage.used_bytes, usage.deleting_bytes), (used, 400_000));
    assert_eq!(
        host.receiver
            .purge_trash(std::time::Duration::from_secs(3600))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        host.receiver
            .purge_trash(std::time::Duration::ZERO)
            .await
            .unwrap(),
        400_000
    );
    assert!(remote.status().await.unwrap().used_bytes < used);
    host.router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn deleted_repositories_are_hidden_then_erased_a_week_later() {
    let tmp = tempfile::tempdir().unwrap();
    let host = Host::start(tmp.path().join("host")).await;
    let (ep, remote) = client(&host, "repo").await;
    host.receiver.allow(ep.id(), Grant::default());
    let (_, other) = {
        let backend = RemoteBackend::new(
            ep.clone(),
            host.addr(),
            "other",
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        ((), Arc::new(backend))
    };

    let data = vec![5u8; 100_000];
    let id = PackId(*blake3::hash(&data).as_bytes());
    for r in [remote.clone(), other.clone()] {
        let d = data.clone();
        tokio::task::spawn_blocking(move || r.put_pack(&id, &d))
            .await
            .unwrap()
            .unwrap();
    }

    let erase_after = remote.delete_repo().await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let week = kinvault_net::REPO_DELETE_DELAY.as_secs() as i64;
    assert!((erase_after - now - week).abs() < 60);
    // Hidden at once; the other repository is untouched; deleting again is fine.
    let (r, o) = (remote.clone(), other.clone());
    tokio::task::spawn_blocking(move || {
        assert!(r.list_packs().unwrap().is_empty());
        assert_eq!(o.list_packs().unwrap(), vec![id]);
    })
    .await
    .unwrap();
    remote.delete_repo().await.unwrap();
    // Still counted, and shown as waiting to be erased.
    let usage = host.receiver.usage_detail(&ep.id()).await.unwrap();
    assert_eq!(usage.deleting_bytes, 100_000);
    assert_eq!(usage.used_bytes, 200_000);

    // Kept until the week is up, then erased.
    let deleted = host.store.join(ep.id().to_string()).join(".deleted");
    assert_eq!(
        host.receiver
            .purge_trash(std::time::Duration::ZERO)
            .await
            .unwrap(),
        0
    );
    assert_eq!(fs::read_dir(&deleted).unwrap().count(), 2);
    for (n, entry) in fs::read_dir(&deleted).unwrap().enumerate() {
        let entry = entry.unwrap().path();
        fs::rename(&entry, deleted.join(format!("{}-repo-{n}", now - 1))).unwrap();
    }
    assert_eq!(
        host.receiver
            .purge_trash(std::time::Duration::ZERO)
            .await
            .unwrap(),
        100_000
    );
    assert_eq!(fs::read_dir(&deleted).unwrap().count(), 0);
    let o = other.clone();
    tokio::task::spawn_blocking(move || assert_eq!(o.list_packs().unwrap(), vec![id]))
        .await
        .unwrap();
    host.router.shutdown().await.unwrap();
}
