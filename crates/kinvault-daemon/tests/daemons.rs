//! Two daemons on localhost: one backs up a folder to the other, which hosts it.

use std::fs;
use std::path::Path;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use kinvault_daemon::api::{
    BackupSummary, CreateInvite, CreateSet, GrantSpec, HostOffer, Reply, Request, SetState,
    SetStatus, Target, TimeWindow,
};
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
            grant: GrantSpec {
                quota_bytes: Some(1 << 30),
                ..Default::default()
            },
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
            upload_limit: None,
            window: None,
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

async fn set_named(d: &Daemon, name: &str) -> SetStatus {
    match call(d, Request::Status).await {
        Reply::Status(s) => s
            .sets
            .into_iter()
            .find(|s| s.name == name)
            .expect("set exists"),
        other => panic!("{other:?}"),
    }
}

async fn peers(d: &Daemon) -> Vec<kinvault_daemon::api::PeerInfo> {
    match call(d, Request::PeerList).await {
        Reply::Peers(p) => p,
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn friends_pair_with_an_invite_and_back_up_to_each_other() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = start(&tmp.path().join("alice"), SecretKey::generate()).await;
    let bob = start(&tmp.path().join("bob"), SecretKey::generate()).await;
    call(
        &alice,
        Request::SetInstanceName {
            name: "alice-nas".into(),
        },
    )
    .await;
    call(
        &bob,
        Request::SetInstanceName {
            name: "bob-pc".into(),
        },
    )
    .await;

    // Alice invites Bob, offering 1 GiB and asking for storage in return.
    let Reply::Invite { ticket, .. } = call(
        &alice,
        Request::CreateInvite(CreateInvite {
            name: Some("bob".into()),
            grant: GrantSpec {
                quota_bytes: Some(1 << 30),
                ..Default::default()
            },
            ask_reciprocal: true,
            expires_secs: None,
        }),
    )
    .await
    else {
        panic!()
    };
    assert!(ticket.starts_with("kvinvite1"));

    // Bob redeems it and offers Alice 512 MiB back.
    let offer = GrantSpec {
        quota_bytes: Some(512 << 20),
        ..Default::default()
    };
    let Reply::Redeemed {
        host_name,
        quota_bytes,
        ask_reciprocal,
        ..
    } = call(
        &bob,
        Request::RedeemInvite {
            ticket: ticket.clone(),
            name: None,
            offer: Some(offer),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(
        (host_name.as_str(), quota_bytes, ask_reciprocal),
        ("alice-nas", Some(1 << 30), true)
    );

    // Both sides now know each other in both directions.
    let on_alice = peers(&alice).await;
    assert_eq!(on_alice.len(), 1);
    assert_eq!(on_alice[0].name.as_deref(), Some("bob"));
    assert_eq!(on_alice[0].grant.unwrap().quota_bytes, Some(1 << 30));
    assert_eq!(
        on_alice[0].hosts_us,
        Some(HostOffer {
            quota_bytes: Some(512 << 20)
        })
    );
    let on_bob = peers(&bob).await;
    assert_eq!(on_bob[0].name.as_deref(), Some("alice-nas"));
    assert_eq!(on_bob[0].grant, Some(offer));
    assert_eq!(
        on_bob[0].hosts_us,
        Some(HostOffer {
            quota_bytes: Some(1 << 30)
        })
    );

    // Invites are single use.
    let err = bob
        .handle(Request::RedeemInvite {
            ticket,
            name: None,
            offer: None,
        })
        .await
        .unwrap_err();
    assert!(err.contains("invalid, expired or already used"), "{err}");

    // Bob backs up to Alice by name; the address came from the invite.
    let bob_src = tmp.path().join("bob-files");
    fs::create_dir_all(&bob_src).unwrap();
    fs::write(bob_src.join("thesis.tex"), b"\\documentclass{article}").unwrap();
    call(
        &bob,
        Request::CreateSet(CreateSet {
            name: "thesis".into(),
            paths: vec![bob_src.clone()],
            target: Target::Peer {
                id: "alice-nas".into(),
                addrs: vec![],
            },
            recovery_passphrase: "bobs recovery phrase".into(),
            debounce_secs: Some(1),
            rescan_secs: None,
            upload_limit: Some(10_000_000),
            window: None,
        }),
    )
    .await;
    let Reply::Backup(b) = call(
        &bob,
        Request::BackupNow {
            set: "thesis".into(),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(b.files, 1);
    assert!(peers(&alice).await[0].used_bytes > 0);

    // Alice backs up to Bob, but only during a window that is closed right now.
    let h = (jiff::Zoned::now().hour() as u16 + 22) % 24;
    let closed = TimeWindow::new(h * 60, ((h + 1) % 24) * 60).unwrap();
    let alice_src = tmp.path().join("alice-photos");
    fs::create_dir_all(&alice_src).unwrap();
    fs::write(alice_src.join("cat.jpg"), b"meow").unwrap();
    call(
        &alice,
        Request::CreateSet(CreateSet {
            name: "photos".into(),
            paths: vec![alice_src],
            target: Target::Peer {
                id: "bob".into(),
                addrs: bob.endpoint().bound_sockets(),
            },
            recovery_passphrase: "alices recovery phrase".into(),
            debounce_secs: Some(1),
            rescan_secs: None,
            upload_limit: None,
            window: Some(closed),
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let st = set_named(&alice, "photos").await;
    assert_eq!(st.state, SetState::WaitingForWindow);
    assert!(st.last_backup.is_none());
    // An explicit request ignores the window.
    let Reply::Backup(b) = call(
        &alice,
        Request::BackupNow {
            set: "photos".into(),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(b.files, 1);
    assert!(peers(&bob).await[0].used_bytes > 0);

    // Opening the window lets automatic backups run again.
    call(
        &alice,
        Request::SetLimits {
            set: "photos".into(),
            upload_limit: None,
            window: None,
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_ne!(
        set_named(&alice, "photos").await.state,
        SetState::WaitingForWindow
    );

    // Expired and cancelled invites.
    let Reply::Invite { ticket, .. } = call(
        &alice,
        Request::CreateInvite(CreateInvite {
            expires_secs: Some(0),
            ..Default::default()
        }),
    )
    .await
    else {
        panic!()
    };
    let err = bob
        .handle(Request::RedeemInvite {
            ticket,
            name: None,
            offer: None,
        })
        .await
        .unwrap_err();
    assert!(err.contains("expired"), "{err}");
    let Reply::Invite { id, .. } =
        call(&alice, Request::CreateInvite(CreateInvite::default())).await
    else {
        panic!()
    };
    call(&alice, Request::CancelInvite { id }).await;
    let Reply::Invites(left) = call(&alice, Request::ListInvites).await else {
        panic!()
    };
    assert!(left.is_empty());

    // Revoking Bob keeps Alice's record that Bob hosts her backups.
    call(&alice, Request::PeerRevoke { id: "bob".into() }).await;
    let on_alice = peers(&alice).await;
    assert!(on_alice[0].grant.is_none());
    assert!(on_alice[0].hosts_us.is_some());

    alice.shutdown().await;
    bob.shutdown().await;
}
