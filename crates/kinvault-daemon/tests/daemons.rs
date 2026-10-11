//! Two daemons on localhost: one backs up a folder to the other, which hosts it.

use std::fs;
use std::path::Path;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use kinvault_daemon::api::{BackupSummary, CreateSet, Reply, Request, SetState, SetStatus, Target};
use kinvault_daemon::{Daemon, DaemonOptions, ipc};

async fn local_endpoint(secret: SecretKey) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

async fn start(state: &Path, secret: SecretKey) -> Daemon {
    Daemon::start(DaemonOptions {
        state_dir: state.to_path_buf(),
        endpoint: Some(local_endpoint(secret).await),
    })
    .await
    .unwrap()
}

async fn call(d: &Daemon, req: Request) -> Reply {
    d.handle(req.clone())
        .await
        .unwrap_or_else(|e| panic!("{req:?} failed: {e}"))
}

async fn set_status(d: &Daemon) -> SetStatus {
    match call(d, Request::Status).await {
        Reply::Status(s) => s.sets.into_iter().next().expect("one set"),
        other => panic!("{other:?}"),
    }
}

/// Polls until the set has completed a backup different from `previous`.
async fn wait_for_backup(d: &Daemon, previous: Option<&str>) -> BackupSummary {
    for _ in 0..300 {
        let st = set_status(d).await;
        if let Some(b) = st.last_backup
            && Some(b.snapshot.as_str()) != previous
            && st.state != SetState::Running
        {
            return b;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no new backup; status: {:?}", set_status(d).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_backs_up_changes_to_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("documents");
    fs::create_dir_all(src.join("letters")).unwrap();
    fs::write(src.join("letters/one.txt"), b"first letter").unwrap();
    fs::write(src.join("notes.md"), b"# notes").unwrap();
    // The sender's own state lives inside the folder it backs up; it must be excluded.
    let pc_state = src.join(".kinvault");
    let host_state = tmp.path().join("host-state");

    let host = start(&host_state, SecretKey::generate()).await;
    let pc_secret = SecretKey::generate();
    let pc = start(&pc_state, pc_secret.clone()).await;

    // Host allows the PC, then the PC creates a set stored on the host.
    call(
        &host,
        Request::PeerAllow {
            id: pc.id().to_string(),
            name: Some("pc".into()),
            quota_bytes: Some(1 << 30),
        },
    )
    .await;
    let host_addr = host.endpoint().bound_sockets()[0];
    let created = call(
        &pc,
        Request::CreateSet(CreateSet {
            name: "docs".into(),
            paths: vec![src.clone()],
            target: Target::Peer {
                id: host.id().to_string(),
                addrs: vec![host_addr],
            },
            recovery_passphrase: "a long recovery phrase".into(),
            debounce_secs: Some(1),
            rescan_secs: None,
        }),
    )
    .await;
    assert!(matches!(created, Reply::SetCreated { .. }));

    // The initial backup runs on its own.
    let first = wait_for_backup(&pc, None).await;
    assert_eq!(first.files, 2, "state dir must be excluded: {first:?}");

    // No changes: it settles to idle instead of looping on its own index writes.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let st = set_status(&pc).await;
    assert_eq!(st.state, SetState::Idle);
    assert_eq!(st.last_backup.unwrap().snapshot, first.snapshot);

    // Editing a file triggers an automatic, incremental backup.
    fs::write(src.join("notes.md"), b"# notes\nmore").unwrap();
    let second = wait_for_backup(&pc, Some(&first.snapshot)).await;
    assert_eq!(second.files_changed, 1);
    assert!(second.bytes_uploaded < 4096, "{second:?}");

    // On-demand backup through the control socket.
    let listener = ipc::Listener::bind(&ipc::endpoint_name(&pc_state))
        .await
        .unwrap();
    let server = tokio::spawn(listener.serve(pc.clone()));
    let mut client = ipc::Client::connect(&pc_state).await.unwrap();
    match client
        .call(&Request::BackupNow { set: "docs".into() })
        .await
        .unwrap()
    {
        Reply::Backup(b) => assert_eq!(b.files_changed, 0),
        other => panic!("{other:?}"),
    }
    let err = client
        .call(&Request::BackupNow { set: "nope".into() })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no backup set"), "{err}");

    let Reply::Snapshots(snaps) = call(&pc, Request::ListSnapshots { set: "docs".into() }).await
    else {
        panic!()
    };
    assert_eq!(snaps.len(), 3);

    let out = tmp.path().join("restored");
    call(
        &pc,
        Request::Restore {
            set: "docs".into(),
            snapshot: "latest".into(),
            target: out.clone(),
            include: None,
        },
    )
    .await;
    let restored = out.join(
        fs::canonicalize(&src)
            .unwrap()
            .to_string_lossy()
            .trim_start_matches('/'),
    );
    assert_eq!(
        fs::read(restored.join("notes.md")).unwrap(),
        b"# notes\nmore"
    );
    assert_eq!(
        fs::read(restored.join("letters/one.txt")).unwrap(),
        b"first letter"
    );
    assert!(!restored.join(".kinvault").exists());

    // Both sides can see how much space the PC uses on the host.
    let Reply::Usage {
        used_bytes,
        quota_bytes,
    } = call(&pc, Request::RemoteUsage { set: "docs".into() }).await
    else {
        panic!()
    };
    assert!(used_bytes > 0);
    assert_eq!(quota_bytes, Some(1 << 30));
    let Reply::Peers(peers) = call(&host, Request::PeerList).await else {
        panic!()
    };
    assert_eq!(peers[0].used_bytes, used_bytes);

    // Restarting keeps the configuration and last result.
    server.abort();
    pc.shutdown().await;
    let pc = start(&pc_state, pc_secret).await;
    let st = set_status(&pc).await;
    assert_eq!(st.name, "docs");
    assert!(st.last_backup.is_some());

    // Once the host revokes access, backups fail with a clear error.
    call(
        &host,
        Request::PeerRevoke {
            id: pc.id().to_string(),
        },
    )
    .await;
    fs::write(src.join("new.txt"), b"x").unwrap();
    let err = pc
        .handle(Request::BackupNow { set: "docs".into() })
        .await
        .unwrap_err();
    assert!(err.contains("not allowed"), "{err}");
    assert!(
        set_status(&pc)
            .await
            .last_error
            .unwrap()
            .contains("not allowed")
    );

    pc.shutdown().await;
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn second_daemon_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = ipc::endpoint_name(tmp.path());
    let _first = ipc::Listener::bind(&path).await.unwrap();
    let err = ipc::Listener::bind(&path)
        .await
        .err()
        .expect("second bind must fail");
    assert!(err.to_string().contains("already running"), "{err}");
}
