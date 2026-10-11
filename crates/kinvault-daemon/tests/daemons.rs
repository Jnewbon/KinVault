//! Two daemons on localhost: one backs up a folder to the other, which hosts it.

use std::fs;
use std::path::Path;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use kinvault_daemon::api::{
    BackupSummary, CreateInvite, CreateSet, GrantSpec, HostOffer, NetworkSettings, Reply, Request,
    SetState, SetStatus, Target, TimeWindow,
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
            retention: None,
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
            retention: None,
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
