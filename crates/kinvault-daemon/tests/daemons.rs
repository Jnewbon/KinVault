//! Two daemons on localhost: one backs up a folder to the other, which hosts it.

use std::fs;
use std::path::Path;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use kinvault_daemon::api::{
    BackupSummary, CreateInvite, CreateSet, Event, GrantSpec, HostOffer, NearbyState, NearbyStatus,
    NetworkSettings, Reply, Request, SetState, SetStatus, Target, TimeWindow,
};
use kinvault_daemon::{Daemon, DaemonOptions, ReachabilityOptions, ipc};
use kinvault_net::nearby::NearbyOptions;

async fn local_endpoint(secret: SecretKey) -> Endpoint {
    local_endpoint_on(secret, 0).await
}

async fn local_endpoint_on(secret: SecretKey, port: u16) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .clear_ip_transports()
        .bind_addr(("127.0.0.1", port))
        .unwrap()
        .bind()
        .await
        .unwrap()
}

async fn start(state: &Path, secret: SecretKey) -> Daemon {
    start_with_nearby(state, secret, Default::default()).await
}

async fn start_with_nearby(state: &Path, secret: SecretKey, nearby: NearbyOptions) -> Daemon {
    start_with_endpoint(state, local_endpoint(secret).await, nearby).await
}

async fn start_with_endpoint(state: &Path, endpoint: Endpoint, nearby: NearbyOptions) -> Daemon {
    Daemon::start(DaemonOptions {
        state_dir: state.to_path_buf(),
        endpoint: Some(endpoint),
        nearby,
        // Check hosts often, so tests see them come and go quickly.
        reachability: ReachabilityOptions {
            interval: Duration::from_millis(500),
            timeout: Duration::from_secs(2),
        },
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
            retention: None,
            excludes: Vec::new(),
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
        // Nothing changed: no new snapshot.
        Reply::Backup(b) => {
            assert_eq!(b.files_changed, 0);
            assert_eq!(b.snapshot, second.snapshot);
        }
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
    assert_eq!(snaps.len(), 2);

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
    let restored = out.join(kinvault_core::snapshot_root_name(
        &fs::canonicalize(&src).unwrap(),
    ));
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
    assert!(!ipc::daemon_running(tmp.path()));
    let first = ipc::Listener::bind(&path).await.unwrap();
    let _serving = tokio::spawn(async move {
        let _ = first;
        std::future::pending::<()>().await
    });
    assert!(ipc::daemon_running(tmp.path()));
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
            mine: false,
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
            mine: false,
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
            mine: false,
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
            retention: None,
            excludes: Vec::new(),
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
            retention: None,
            excludes: Vec::new(),
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
            mine: false,
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
            mine: false,
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

#[tokio::test(flavor = "multi_thread")]
async fn recovery_kit_restores_backups_on_a_new_machine() {
    use kinvault_daemon::api::RetentionPolicy;
    use kinvault_daemon::recovery;

    let tmp = tempfile::tempdir().unwrap();
    let host = start(&tmp.path().join("host"), SecretKey::generate()).await;
    let old_state = tmp.path().join("old-pc");
    let pc = start(&old_state, SecretKey::generate()).await;
    let pc_id = pc.id();
    call(
        &host,
        Request::PeerAllow {
            id: pc_id.to_string(),
            name: None,
            grant: GrantSpec::default(),
        },
    )
    .await;

    let src = tmp.path().join("documents");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("taxes.pdf"), b"2025 return").unwrap();
    call(
        &pc,
        Request::CreateSet(CreateSet {
            name: "docs".into(),
            paths: vec![src.clone()],
            target: Target::Peer {
                id: host.id().to_string(),
                addrs: host.endpoint().bound_sockets(),
            },
            recovery_passphrase: "set recovery phrase".into(),
            debounce_secs: Some(60),
            rescan_secs: None,
            upload_limit: None,
            window: None,
            retention: None,
            excludes: Vec::new(),
        }),
    )
    .await;
    wait_for_backup(&pc, None).await;
    fs::write(src.join("taxes.pdf"), b"2025 return, amended").unwrap();
    call(&pc, Request::BackupNow { set: "docs".into() }).await;

    // Maintenance on demand: everything checks out, and pruning to the latest
    // snapshot removes the older one.
    let Reply::Verified(v) = call(
        &pc,
        Request::Verify {
            set: "docs".into(),
            max_bytes: None,
        },
    )
    .await
    else {
        panic!()
    };
    assert!(v.ok && v.snapshots == 2 && v.packs_checked > 0, "{v:?}");
    call(
        &pc,
        Request::SetRetention {
            set: "docs".into(),
            policy: RetentionPolicy {
                last: Some(1),
                ..Default::default()
            },
        },
    )
    .await;
    let Reply::Pruned(p) = call(&pc, Request::Prune { set: "docs".into() }).await else {
        panic!()
    };
    assert_eq!((p.snapshots_kept, p.snapshots_removed), (1, 1));
    let st = set_status(&pc).await;
    assert!(st.last_prune.is_some() && st.last_verify.unwrap().ok);

    // Export a kit, then the PC is lost.
    let Reply::RecoveryKit { json } = call(
        &pc,
        Request::ExportRecoveryKit {
            passphrase: "kit passphrase!".into(),
        },
    )
    .await
    else {
        panic!()
    };
    assert!(
        !json.contains(&hex_master_key(&old_state)),
        "set key must be encrypted in the kit"
    );
    pc.shutdown().await;
    drop(pc);

    // A new machine imports the kit.
    let new_state = tmp.path().join("new-pc");
    let err = recovery::import_offline(&new_state, &json, "wrong passphrase", false).unwrap_err();
    assert!(format!("{err:#}").contains("wrong passphrase"), "{err:#}");
    let summary = recovery::import_offline(&new_state, &json, "kit passphrase!", false).unwrap();
    assert_eq!(summary.sets, vec!["docs".to_string()]);
    assert_eq!(summary.instance_id, pc_id.to_string());
    assert!(recovery::import_offline(&new_state, &json, "kit passphrase!", false).is_err());

    // It comes back with the old identity, so the host recognises it.
    let secret = kinvault_net::load_or_create_secret(&new_state.join("identity.key")).unwrap();
    let new_pc = start(&new_state, secret).await;
    assert_eq!(new_pc.id(), pc_id);
    let st = set_status(&new_pc).await;
    assert_eq!(st.state, SetState::Paused);
    let err = new_pc
        .handle(Request::BackupNow { set: "docs".into() })
        .await
        .unwrap_err();
    assert!(err.contains("paused"), "{err}");

    let out = tmp.path().join("restored");
    call(
        &new_pc,
        Request::Restore {
            set: "docs".into(),
            snapshot: "latest".into(),
            target: out.clone(),
            include: None,
        },
    )
    .await;
    let restored = out.join(kinvault_core::snapshot_root_name(
        &fs::canonicalize(&src).unwrap(),
    ));
    assert_eq!(
        fs::read(restored.join("taxes.pdf")).unwrap(),
        b"2025 return, amended"
    );

    // Resume backing up from the restored copy on the new machine.
    call(
        &new_pc,
        Request::ResumeSet {
            set: "docs".into(),
            paths: Some(vec![restored.clone()]),
        },
    )
    .await;
    let b = wait_for_backup(&new_pc, None).await;
    assert_eq!(b.files, 1);
    assert_eq!(
        set_status(&new_pc).await.paths,
        vec![fs::canonicalize(&restored).unwrap()]
    );

    new_pc.shutdown().await;
    host.shutdown().await;
}

fn hex_master_key(state: &Path) -> String {
    let sets = state.join("sets");
    let dir = fs::read_dir(&sets).unwrap().next().unwrap().unwrap().path();
    fs::read_to_string(dir.join("master.key"))
        .unwrap()
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribers_see_state_changes_and_results() {
    use kinvault_daemon::api::Event;

    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let daemon = start(&state, SecretKey::generate()).await;
    let listener = ipc::Listener::bind(&ipc::endpoint_name(&state))
        .await
        .unwrap();
    let server = tokio::spawn(listener.serve(daemon.clone()));
    let mut events = ipc::Client::connect(&state)
        .await
        .unwrap()
        .subscribe()
        .await
        .unwrap();

    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    for i in 0..50 {
        fs::write(src.join(format!("f{i}")), vec![i as u8; 100_000]).unwrap();
    }
    call(
        &daemon,
        Request::CreateSet(CreateSet {
            name: "local".into(),
            paths: vec![src],
            target: Target::Local {
                path: tmp.path().join("disk"),
            },
            recovery_passphrase: "recovery phrase".into(),
            debounce_secs: Some(60),
            rescan_secs: None,
            upload_limit: None,
            window: None,
            retention: None,
            excludes: Vec::new(),
        }),
    )
    .await;

    let mut seen = Vec::new();
    let finished = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(event) = events.next().await {
            let done = matches!(event, Event::BackupFinished { .. });
            seen.push(event);
            if done {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(finished, "{seen:?}");
    assert!(matches!(seen[0], Event::SetsChanged), "{seen:?}");
    assert!(
        seen.iter().any(|e| matches!(
            e,
            Event::SetState {
                state: SetState::Running,
                ..
            }
        )),
        "{seen:?}"
    );
    let Some(Event::BackupFinished { summary, .. }) = seen.last() else {
        panic!()
    };
    assert_eq!(summary.files, 50);

    server.abort();
    daemon.shutdown().await;
}

fn peer_hosts(state: &Path, id: &str) -> serde_json::Value {
    let config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state.join("config.json")).unwrap()).unwrap();
    let peer = config["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
        .unwrap_or_else(|| panic!("no peer {id} in {config}"));
    peer["hosts"].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_addresses_travel_in_invites() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice_state, bob_state) = (tmp.path().join("alice"), tmp.path().join("bob"));
    let alice = start(&alice_state, SecretKey::generate()).await;
    let bob = start(&bob_state, SecretKey::generate()).await;
    let network = |reply| match reply {
        Reply::Network(info) => info,
        other => panic!("{other:?}"),
    };

    let info = network(call(&alice, Request::GetNetwork).await);
    assert_eq!(info.settings, NetworkSettings::default());
    assert!(!info.restart_required);
    let port = info.bound[0].port();

    for bad in ["not a host!", "example.org:0", "2001:db8::1:4433:x"] {
        let err = alice
            .handle(Request::SetNetwork(NetworkSettings {
                listen_port: None,
                public_hosts: vec![bad.into()],
            }))
            .await
            .unwrap_err();
        assert!(err.contains("invalid address"), "{bad}: {err}");
    }

    // Entries are normalised and deduplicated; a new port needs a restart.
    let info = network(
        call(
            &alice,
            Request::SetNetwork(NetworkSettings {
                listen_port: Some(4567),
                public_hosts: vec![
                    "LOCALHOST".into(),
                    "198.51.100.4:7000".into(),
                    "localhost".into(),
                ],
            }),
        )
        .await,
    );
    assert_eq!(
        info.settings.public_hosts,
        ["localhost", "198.51.100.4:7000"]
    );
    assert!(info.restart_required);
    let info = network(
        call(
            &alice,
            Request::SetNetwork(NetworkSettings {
                listen_port: None,
                ..info.settings
            }),
        )
        .await,
    );
    assert!(!info.restart_required);
    call(
        &bob,
        Request::SetNetwork(NetworkSettings {
            listen_port: None,
            public_hosts: vec!["192.0.2.10:9000".into()],
        }),
    )
    .await;

    // The invite carries Alice's addresses, with her listening port filled in.
    let Reply::Invite { ticket, .. } = call(
        &alice,
        Request::CreateInvite(CreateInvite {
            ask_reciprocal: true,
            ..Default::default()
        }),
    )
    .await
    else {
        panic!()
    };
    let decoded = kinvault_net::InviteTicket::decode(&ticket).unwrap();
    let alice_hosts = vec![format!("localhost:{port}"), "198.51.100.4:7000".to_string()];
    assert_eq!(decoded.hosts, alice_hosts);

    call(
        &bob,
        Request::RedeemInvite {
            ticket,
            name: None,
            offer: Some(GrantSpec::default()),
            mine: false,
        },
    )
    .await;
    // Each side remembers the other's addresses.
    assert_eq!(
        peer_hosts(&bob_state, &alice.id().to_string()),
        serde_json::json!(alice_hosts)
    );
    assert_eq!(
        peer_hosts(&alice_state, &bob.id().to_string()),
        serde_json::json!(["192.0.2.10:9000"])
    );
    alice.shutdown().await;
    bob.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn own_devices_pair_without_limits() {
    let tmp = tempfile::tempdir().unwrap();
    let nas = start(&tmp.path().join("nas"), SecretKey::generate()).await;
    let laptop = start(&tmp.path().join("laptop"), SecretKey::generate()).await;

    // Limits and the reciprocal flag are ignored for one of your own devices.
    let Reply::Invite { ticket, .. } = call(
        &nas,
        Request::CreateInvite(CreateInvite {
            name: Some("laptop".into()),
            grant: GrantSpec {
                quota_bytes: Some(1 << 30),
                ..Default::default()
            },
            ask_reciprocal: false,
            expires_secs: None,
            mine: true,
        }),
    )
    .await
    else {
        panic!()
    };
    let Reply::Invites(invites) = call(&nas, Request::ListInvites).await else {
        panic!()
    };
    assert!(invites[0].mine && invites[0].ask_reciprocal);
    assert_eq!(invites[0].grant, GrantSpec::default());

    let Reply::Redeemed { quota_bytes, .. } = call(
        &laptop,
        Request::RedeemInvite {
            ticket,
            name: Some("nas".into()),
            offer: Some(GrantSpec {
                quota_bytes: Some(1),
                ..Default::default()
            }),
            mine: true,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(quota_bytes, None);

    for (d, name) in [(&nas, "laptop"), (&laptop, "nas")] {
        let p = peers(d).await;
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name.as_deref(), Some(name));
        assert!(p[0].mine);
        assert_eq!(p[0].grant, Some(GrantSpec::default()));
        assert_eq!(p[0].hosts_us, Some(HostOffer { quota_bytes: None }));
    }

    // Moving a device to friends keeps its storage; moving it back lifts any
    // limits set in between.
    call(
        &nas,
        Request::PeerSetMine {
            id: "laptop".into(),
            mine: false,
        },
    )
    .await;
    let limited = GrantSpec {
        quota_bytes: Some(1 << 20),
        ..Default::default()
    };
    call(
        &nas,
        Request::PeerAllow {
            id: "laptop".into(),
            name: None,
            grant: limited,
        },
    )
    .await;
    let p = peers(&nas).await;
    assert!(!p[0].mine);
    assert_eq!(p[0].grant, Some(limited));
    call(
        &nas,
        Request::PeerSetMine {
            id: "laptop".into(),
            mine: true,
        },
    )
    .await;
    let p = peers(&nas).await;
    assert!(p[0].mine);
    assert_eq!(p[0].grant, Some(GrantSpec::default()));
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn nearby(d: &Daemon) -> NearbyStatus {
    match call(d, Request::NearbyStatus).await {
        Reply::Nearby(s) => s,
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nearby_devices_pair_once_confirmed_on_both() {
    let tmp = tempfile::tempdir().unwrap();
    let (port_a, port_b) = (free_udp_port(), free_udp_port());
    // Each sends its beacons straight to the other's port.
    let opts = |port, other: u16| NearbyOptions {
        port,
        targets: vec![([127, 0, 0, 1], other).into()],
    };
    let nas = start_with_nearby(
        &tmp.path().join("nas"),
        SecretKey::generate(),
        opts(port_a, port_b),
    )
    .await;
    let laptop = start_with_nearby(
        &tmp.path().join("laptop"),
        SecretKey::generate(),
        opts(port_b, port_a),
    )
    .await;
    for (d, name) in [(&nas, "nas"), (&laptop, "laptop")] {
        call(d, Request::SetInstanceName { name: name.into() }).await;
    }
    assert!(nearby(&nas).await.until_unix.is_none());
    call(&nas, Request::FindNearby).await;
    call(&laptop, Request::FindNearby).await;

    let mut found = None;
    for _ in 0..100 {
        let (a, b) = (nearby(&nas).await, nearby(&laptop).await);
        if !a.devices.is_empty() && !b.devices.is_empty() {
            found = Some((a.devices[0].clone(), b.devices[0].clone()));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (on_nas, on_laptop) = found.expect("the devices find each other");
    assert_eq!(
        (on_nas.name.as_str(), on_laptop.name.as_str()),
        ("laptop", "nas")
    );
    assert_eq!(on_nas.id, laptop.id().to_string());
    assert_eq!(on_nas.code, on_laptop.code);
    assert_eq!(on_nas.state, NearbyState::Found);

    // Confirmed on one side only: nothing is shared yet.
    let Reply::Nearby(s) = call(
        &nas,
        Request::PairNearby {
            id: on_nas.id.clone(),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(s.devices[0].state, NearbyState::Waiting);
    assert!(peers(&nas).await.is_empty());
    assert!(peers(&laptop).await.is_empty());

    // Confirmed on the other too: both list each other as their own.
    let Reply::Nearby(s) = call(
        &laptop,
        Request::PairNearby {
            id: on_laptop.id.clone(),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(s.devices[0].state, NearbyState::Paired);
    assert_eq!(nearby(&nas).await.devices[0].state, NearbyState::Paired);
    for (d, name) in [(&nas, "laptop"), (&laptop, "nas")] {
        let p = peers(d).await;
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name.as_deref(), Some(name));
        assert!(p[0].mine);
        assert_eq!(p[0].grant, Some(GrantSpec::default()));
        assert_eq!(p[0].hosts_us, Some(HostOffer { quota_bytes: None }));
    }

    call(&nas, Request::StopNearby).await;
    assert!(nearby(&nas).await.until_unix.is_none());
    let err = nas
        .handle(Request::PairNearby { id: on_nas.id })
        .await
        .unwrap_err();
    assert!(err.contains("not looking"), "{err}");
}

fn create_set(name: &str, src: &Path, target: Target) -> Request {
    Request::CreateSet(CreateSet {
        name: name.into(),
        paths: vec![src.to_path_buf()],
        target,
        recovery_passphrase: "a long recovery phrase".into(),
        debounce_secs: Some(1),
        rescan_secs: None,
        upload_limit: None,
        window: None,
        retention: None,
        excludes: Vec::new(),
    })
}

fn pending_deletions(state: &Path) -> Vec<serde_json::Value> {
    let config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state.join("config.json")).unwrap()).unwrap();
    config["pending_deletions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn deleted(reply: Reply) -> kinvault_daemon::api::DeletedSet {
    match reply {
        Reply::SetDeleted(d) => d,
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_set_erases_its_backups_wherever_they_are() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("documents");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("notes.md"), b"# notes").unwrap();
    let pc_state = tmp.path().join("pc");
    let pc = start(&pc_state, SecretKey::generate()).await;
    let host_state = tmp.path().join("host");
    let host = start(&host_state, SecretKey::generate()).await;
    call(
        &host,
        Request::PeerAllow {
            id: pc.id().to_string(),
            name: None,
            grant: GrantSpec::default(),
        },
    )
    .await;
    let peer = |d: &Daemon| Target::Peer {
        id: d.id().to_string(),
        addrs: vec![d.endpoint().bound_sockets()[0]],
    };

    // On a host that's online: hidden there now, erased in a week.
    call(&pc, create_set("remote", &src, peer(&host))).await;
    let backed_up = wait_for_backup(&pc, None).await;
    let set_id = set_named(&pc, "remote").await.id;
    let d = deleted(
        call(
            &pc,
            Request::DeleteSet {
                set: "remote".into(),
            },
        )
        .await,
    );
    let week_from_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 7 * 24 * 60 * 60;
    assert!(
        (d.erase_after_unix.unwrap() - week_from_now).abs() < 60,
        "{d:?}"
    );
    assert!(d.error.is_none() && !d.retrying);
    let Reply::Status(status) = call(&pc, Request::Status).await else {
        panic!()
    };
    assert!(status.sets.is_empty());
    assert!(!pc_state.join("sets").join(&set_id).exists(), "key erased");
    assert!(!pc_state.join("removed-sets").join(&set_id).exists());
    assert!(pending_deletions(&pc_state).is_empty());
    let hosted = host_state.join("hosted").join(pc.id().to_string());
    let gone: Vec<_> = fs::read_dir(hosted.join(".deleted")).unwrap().collect();
    assert_eq!(gone.len(), 1);
    assert!(backed_up.bytes_uploaded > 0);
    // The host still counts it, as marked for deletion.
    let on_host = peers(&host).await;
    assert!(on_host[0].used_bytes > 0);
    assert_eq!(on_host[0].deleting_bytes, on_host[0].used_bytes);

    // On a host that's gone: deleted here anyway, and it's asked again later.
    call(&pc, create_set("orphan", &src, peer(&host))).await;
    wait_for_backup(&pc, None).await;
    host.shutdown().await;
    let d = deleted(
        call(
            &pc,
            Request::DeleteSet {
                set: "orphan".into(),
            },
        )
        .await,
    );
    assert!(d.retrying && d.error.is_some(), "{d:?}");
    let Reply::Status(status) = call(&pc, Request::Status).await else {
        panic!()
    };
    assert!(status.sets.is_empty());
    let pending = pending_deletions(&pc_state);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["set_name"], "orphan");

    // In a local folder: left alone for a week, then erased by the daemon.
    let folder = tmp.path().join("usb");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("unrelated.txt"), b"keep me").unwrap();
    call(
        &pc,
        create_set(
            "local",
            &src,
            Target::Local {
                path: folder.clone(),
            },
        ),
    )
    .await;
    wait_for_backup(&pc, None).await;
    let d = deleted(
        call(
            &pc,
            Request::DeleteSet {
                set: "local".into(),
            },
        )
        .await,
    );
    assert!(
        (d.erase_after_unix.unwrap() - week_from_now).abs() < 60,
        "{d:?}"
    );
    assert!(folder.join("packs").exists());
    assert_eq!(pending_deletions(&pc_state).len(), 2);

    // A week later (the deadline moved back) the next start erases the folder.
    pc.shutdown().await;
    let path = pc_state.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    for p in config["pending_deletions"].as_array_mut().unwrap() {
        if p["set_name"] == "local" {
            p["erase_after_unix"] = 1.into();
        }
    }
    fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
    let pc = start(&pc_state, SecretKey::generate()).await;
    for _ in 0..100 {
        if !folder.join("packs").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!folder.join("packs").exists());
    assert!(!folder.join("snapshots").exists());
    assert_eq!(fs::read(folder.join("unrelated.txt")).unwrap(), b"keep me");
    // Only the unreachable host is still waiting to be told.
    let pending = pending_deletions(&pc_state);
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0]["set_name"], "orphan");
    pc.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stopped_sets_can_be_restored_until_their_grace_period_ends() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("documents");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("notes.md"), b"# notes").unwrap();
    let pc_state = tmp.path().join("pc");
    let pc_secret = SecretKey::generate();
    let pc = start(&pc_state, pc_secret.clone()).await;
    let host = start(&tmp.path().join("host"), SecretKey::generate()).await;
    call(
        &host,
        Request::PeerAllow {
            id: pc.id().to_string(),
            name: None,
            grant: GrantSpec::default(),
        },
    )
    .await;
    let target = Target::Peer {
        id: host.id().to_string(),
        addrs: vec![host.endpoint().bound_sockets()[0]],
    };
    call(&pc, create_set("docs", &src, target.clone())).await;
    wait_for_backup(&pc, None).await;
    let set_id = set_named(&pc, "docs").await.id;
    call(&pc, Request::RemoveSet { set: "docs".into() }).await;

    // Listed as stopped, erased after the grace period (30 days by default).
    let Reply::Status(status) = call(&pc, Request::Status).await else {
        panic!()
    };
    assert!(status.sets.is_empty());
    assert_eq!(status.keep_deleted_days, 30);
    let stopped = &status.stopped_sets[0];
    assert_eq!(
        (stopped.id.as_str(), stopped.name.as_str()),
        (set_id.as_str(), "docs")
    );
    assert_eq!(
        stopped.erase_after_unix - stopped.stopped_unix,
        30 * 24 * 60 * 60
    );
    assert!(pc_state.join("sets").join(&set_id).exists());

    // Still restorable, by name or id.
    let Reply::Snapshots(snaps) = call(&pc, Request::ListSnapshots { set: "docs".into() }).await
    else {
        panic!()
    };
    assert_eq!(snaps.len(), 1);
    let out = tmp.path().join("restored");
    call(
        &pc,
        Request::Restore {
            set: set_id.clone(),
            snapshot: "latest".into(),
            target: out.clone(),
            include: None,
        },
    )
    .await;
    let restored = out.join(kinvault_core::snapshot_root_name(
        &fs::canonicalize(&src).unwrap(),
    ));
    assert_eq!(fs::read(restored.join("notes.md")).unwrap(), b"# notes");

    // Its host can't be removed while it keeps the stopped set.
    call(
        &pc,
        Request::PeerAllow {
            id: host.id().to_string(),
            name: None,
            grant: GrantSpec::default(),
        },
    )
    .await;
    let refused = pc
        .handle(Request::PeerRemove {
            id: host.id().to_string(),
        })
        .await;
    let refused = refused.unwrap_err();
    assert!(refused.contains("docs"), "{refused}");

    // A stopped set whose key an earlier version moved to removed-sets/ is
    // moved back when the daemon starts.
    pc.shutdown().await;
    fs::create_dir_all(pc_state.join("removed-sets")).unwrap();
    fs::rename(
        pc_state.join("sets").join(&set_id),
        pc_state.join("removed-sets").join(&set_id),
    )
    .unwrap();
    let pc = start(&pc_state, pc_secret).await;
    let Reply::Snapshots(snaps) = call(&pc, Request::ListSnapshots { set: "docs".into() }).await
    else {
        panic!()
    };
    assert_eq!(snaps.len(), 1);

    // With no grace period left, the host is asked to erase it, then the key goes.
    call(&pc, Request::SetKeepDeletedDays { days: 0 }).await;
    let hidden = tmp
        .path()
        .join("host/hosted")
        .join(pc.id().to_string())
        .join(".deleted");
    for _ in 0..100 {
        if !pc_state.join("sets").join(&set_id).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!pc_state.join("sets").join(&set_id).exists());
    assert_eq!(fs::read_dir(&hidden).unwrap().count(), 1);
    assert!(pending_deletions(&pc_state).is_empty());
    let Reply::Status(status) = call(&pc, Request::Status).await else {
        panic!()
    };
    assert!(status.stopped_sets.is_empty());
    assert!(
        pc.handle(Request::ListSnapshots { set: "docs".into() })
            .await
            .is_err()
    );

    // A stopped set can also be deleted for good straight away.
    call(&pc, Request::SetKeepDeletedDays { days: 30 }).await;
    call(&pc, create_set("photos", &src, target)).await;
    wait_for_backup(&pc, None).await;
    let photos = set_named(&pc, "photos").await.id;
    call(
        &pc,
        Request::RemoveSet {
            set: "photos".into(),
        },
    )
    .await;
    deleted(
        call(
            &pc,
            Request::DeleteSet {
                set: "photos".into(),
            },
        )
        .await,
    );
    assert!(!pc_state.join("sets").join(&photos).exists());
    let Reply::Status(status) = call(&pc, Request::Status).await else {
        panic!()
    };
    assert!(status.stopped_sets.is_empty());
    assert_eq!(fs::read_dir(&hidden).unwrap().count(), 2);
    pc.shutdown().await;
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_can_be_removed_once_no_backup_uses_them() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("documents");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("notes.md"), b"# notes").unwrap();
    let nas_state = tmp.path().join("nas");
    let nas = start(&nas_state, SecretKey::generate()).await;
    let laptop = start(&tmp.path().join("laptop"), SecretKey::generate()).await;
    let Reply::Invite { ticket, .. } = call(
        &nas,
        Request::CreateInvite(CreateInvite {
            name: Some("laptop".into()),
            mine: true,
            ..Default::default()
        }),
    )
    .await
    else {
        panic!()
    };
    call(
        &laptop,
        Request::RedeemInvite {
            ticket,
            name: Some("nas".into()),
            offer: None,
            mine: true,
        },
    )
    .await;
    call(
        &laptop,
        create_set(
            "docs",
            &src,
            Target::Peer {
                id: nas.id().to_string(),
                addrs: vec![nas.endpoint().bound_sockets()[0]],
            },
        ),
    )
    .await;
    wait_for_backup(&laptop, None).await;

    // The laptop backs up to the NAS, so it can't forget the NAS yet.
    let err = laptop
        .handle(Request::PeerRemove { id: "nas".into() })
        .await
        .unwrap_err();
    assert!(
        err.contains("docs") && err.contains("Delete them first"),
        "{err}"
    );
    assert_eq!(peers(&laptop).await.len(), 1);

    // The NAS can forget the laptop: what it stored there is erased in a week.
    call(
        &nas,
        Request::PeerRemove {
            id: "laptop".into(),
        },
    )
    .await;
    assert!(peers(&nas).await.is_empty());
    let hosted = nas_state.join("hosted").join(laptop.id().to_string());
    let left: Vec<_> = fs::read_dir(&hosted)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left, vec![".deleted".to_string()]);
    assert_eq!(fs::read_dir(hosted.join(".deleted")).unwrap().count(), 1);

    // Once its backup is deleted, the laptop can forget the NAS too.
    call(&laptop, Request::DeleteSet { set: "docs".into() }).await;
    call(&laptop, Request::PeerRemove { id: "nas".into() }).await;
    assert!(peers(&laptop).await.is_empty());
    let err = laptop
        .handle(Request::PeerRemove { id: "nas".into() })
        .await
        .unwrap_err();
    assert!(err.contains("no peer"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn restores_run_in_the_background_with_progress() {
    use kinvault_daemon::api::Event;

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("documents");
    fs::create_dir_all(&src).unwrap();
    let mut big = vec![0u8; 48 * 1024 * 1024];
    blake3::Hasher::new()
        .update(b"big")
        .finalize_xof()
        .fill(&mut big);
    fs::write(src.join("big.bin"), &big).unwrap();
    fs::write(src.join("notes.md"), b"# notes").unwrap();
    let pc = start(&tmp.path().join("pc"), SecretKey::generate()).await;
    let store = tmp.path().join("usb");
    call(&pc, create_set("docs", &src, Target::Local { path: store })).await;
    wait_for_backup(&pc, None).await;

    let restore = |target: &str| Request::StartRestore {
        set: "docs".into(),
        snapshot: "latest".into(),
        target: tmp.path().join(target),
        include: None,
    };

    // It answers at once; progress and the result arrive as events.
    let mut events = pc.subscribe();
    let Reply::RestoreStarted { id } = call(&pc, restore("out")).await else {
        panic!()
    };
    let Reply::Status(status) = call(&pc, Request::Status).await else {
        panic!()
    };
    assert_eq!(status.restores.len(), 1);
    assert_eq!(status.restores[0].id, id);
    let mut progress = Vec::new();
    let summary = loop {
        match tokio::time::timeout(Duration::from_secs(60), events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Event::RestoreProgress(job) if job.id == id => progress.push(job),
            Event::RestoreFinished {
                id: done, summary, ..
            } if done == id => break summary,
            Event::RestoreFailed { error, .. } => panic!("{error}"),
            _ => {}
        }
    };
    assert_eq!(summary.files, 2);
    assert!(!progress.is_empty());
    let last = progress.last().unwrap();
    assert_eq!(last.total_files, 2);
    assert_eq!(last.total_bytes, big.len() as u64 + 7);
    let root = kinvault_core::snapshot_root_name(&fs::canonicalize(&src).unwrap());
    assert_eq!(
        fs::read(tmp.path().join("out").join(&root).join("big.bin")).unwrap(),
        big
    );
    let Reply::Status(status) = call(&pc, Request::Status).await else {
        panic!()
    };
    assert!(status.restores.is_empty());

    // Cancelled as soon as it starts reporting.
    let Reply::RestoreStarted { id } = call(&pc, restore("cancelled")).await else {
        panic!()
    };
    call(&pc, Request::CancelRestore { id: id.clone() }).await;
    let cancelled = loop {
        match tokio::time::timeout(Duration::from_secs(60), events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Event::RestoreFailed {
                id: done,
                cancelled,
                ..
            } if done == id => break cancelled,
            Event::RestoreFinished { id: done, .. } if done == id => {
                panic!("finished despite cancel")
            }
            _ => {}
        }
    };
    assert!(cancelled);
    let err = pc.handle(Request::CancelRestore { id }).await.unwrap_err();
    assert!(err.contains("no restore"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn excluded_files_are_left_out_and_dont_trigger_backups() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("target/debug")).unwrap();
    fs::write(repo.join("src/main.rs"), b"fn main() {}").unwrap();
    fs::write(repo.join("target/debug/app"), b"binary").unwrap();
    fs::write(repo.join("notes.log"), b"log").unwrap();
    let pc = start(&tmp.path().join("pc"), SecretKey::generate()).await;
    let usb = tmp.path().join("usb");
    let set_with = |excludes: &[&str]| {
        let Request::CreateSet(mut req) =
            create_set("code", &repo, Target::Local { path: usb.clone() })
        else {
            unreachable!()
        };
        req.excludes = excludes.iter().map(|s| s.to_string()).collect();
        Request::CreateSet(req)
    };

    let err = pc.handle(set_with(&["/media/../x"])).await.unwrap_err();
    assert!(err.contains("..."), "{err}");
    call(&pc, set_with(&["target/...", " ", "*.log"])).await;
    let first = wait_for_backup(&pc, None).await;
    assert_eq!(first.files, 1, "only src/main.rs: {first:?}");
    let st = set_named(&pc, "code").await;
    assert_eq!(st.excludes, vec!["target/...", "*.log"]);

    // Rebuilding doesn't call for a backup.
    fs::write(repo.join("target/debug/app"), b"rebuilt binary").unwrap();
    fs::write(repo.join("notes.log"), b"more log").unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    let st = set_named(&pc, "code").await;
    assert_eq!(st.last_backup.unwrap().snapshot, first.snapshot);

    // Changing the patterns applies from the next backup.
    call(
        &pc,
        Request::SetExcludes {
            set: "code".into(),
            excludes: vec!["target/".into()],
        },
    )
    .await;
    fs::write(repo.join("src/main.rs"), b"fn main() { println!(); }").unwrap();
    let second = wait_for_backup(&pc, Some(&first.snapshot)).await;
    assert_eq!(second.files, 2, "src/main.rs and notes.log: {second:?}");
}

/// Polls until the set's status satisfies `ok`.
async fn wait_for_set(d: &Daemon, ok: impl Fn(&SetStatus) -> bool) -> SetStatus {
    for _ in 0..300 {
        let st = set_status(d).await;
        if ok(&st) {
            return st;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("set never got there; status: {:?}", set_status(d).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn sets_wait_for_an_offline_host_and_back_up_when_it_returns() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("documents");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("notes.md"), b"# notes").unwrap();
    let host_state = tmp.path().join("host-state");
    let host_secret = SecretKey::generate();
    // A fixed port, so the host can come back where the PC expects it.
    let port = free_udp_port();
    let start_host = || async {
        let endpoint = local_endpoint_on(host_secret.clone(), port).await;
        start_with_endpoint(&host_state, endpoint, Default::default()).await
    };
    let host = start_host().await;
    let pc = start(&tmp.path().join("pc-state"), SecretKey::generate()).await;
    call(
        &host,
        Request::PeerAllow {
            id: pc.id().to_string(),
            name: Some("pc".into()),
            grant: GrantSpec::default(),
        },
    )
    .await;
    let target = Target::Peer {
        id: host.id().to_string(),
        addrs: vec![([127, 0, 0, 1], port).into()],
    };
    call(&pc, create_set("docs", &src, target)).await;
    let first = wait_for_backup(&pc, None).await;
    wait_for_set(&pc, |s| s.target_online == Some(true)).await;

    // The host is switched off: the PC notices, and a change waits for it
    // rather than failing.
    let mut events = pc.subscribe();
    host.shutdown().await;
    drop(host);
    wait_for_set(&pc, |s| s.target_online == Some(false)).await;
    fs::write(
        src.join("notes.md"),
        b"# notes\nwritten while the host was away",
    )
    .unwrap();
    let waiting = wait_for_set(&pc, |s| s.state == SetState::WaitingForHost).await;
    assert!(waiting.last_error.is_none(), "{waiting:?}");
    assert_eq!(waiting.last_backup.unwrap().snapshot, first.snapshot);

    // Back on: the change is backed up without waiting for a retry.
    let host = start_host().await;
    let second = wait_for_backup(&pc, Some(&first.snapshot)).await;
    assert_eq!(second.files_changed, 1);
    let st = wait_for_set(&pc, |s| s.state == SetState::Idle).await;
    assert_eq!(st.target_online, Some(true));
    assert!(st.last_error.is_none(), "{st:?}");

    // Subscribers heard it go and come back, and no failure was reported.
    let mut seen = Vec::new();
    while let Ok(ev) = events.try_recv() {
        match ev {
            Event::PeerOnline { online, .. } => seen.push(online),
            Event::BackupFailed { error, .. } => panic!("reported a failure: {error}"),
            _ => {}
        }
    }
    assert_eq!(seen, [false, true]);

    pc.shutdown().await;
    host.shutdown().await;
}
