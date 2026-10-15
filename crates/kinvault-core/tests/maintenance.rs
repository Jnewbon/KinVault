use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use kinvault_core::{Index, LocalDirBackend, MasterKey, Repository, RetentionPolicy};

fn random(len: usize, seed: &str) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(seed.as_bytes())
        .finalize_xof()
        .fill(&mut buf);
    buf
}

/// Writes a file and gives it a distinct mtime so change detection can't miss it.
fn write(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
    let t = SystemTime::now()
        + Duration::from_secs(fs::read_dir(path.parent().unwrap()).unwrap().count() as u64);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

fn pack_files(store: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in fs::read_dir(store.join("packs")).unwrap() {
        for f in fs::read_dir(dir.unwrap().path()).unwrap() {
            out.push(f.unwrap().path());
        }
    }
    out
}

fn store_size(store: &Path) -> u64 {
    pack_files(store)
        .iter()
        .map(|p| fs::metadata(p).unwrap().len())
        .sum()
}

fn setup(
    tmp: &Path,
    pack_target: usize,
) -> (PathBuf, PathBuf, MasterKey, Repository<LocalDirBackend>) {
    let src = tmp.join("src");
    fs::create_dir_all(&src).unwrap();
    let store = tmp.join("store");
    let master = MasterKey::generate().unwrap();
    let mut repo = Repository::open(
        LocalDirBackend::create(&store).unwrap(),
        &master,
        Index::open(&tmp.join("idx.db")).unwrap(),
    );
    repo.set_pack_target(pack_target);
    (src, store, master, repo)
}

#[test]
fn prune_removes_old_snapshots_and_frees_their_data() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, store, master, mut repo) = setup(tmp.path(), 1 << 20);
    write(&src.join("big.bin"), &random(3 << 20, "big"));
    write(&src.join("notes.txt"), b"v1");
    repo.backup(std::slice::from_ref(&src), "h").unwrap();

    fs::remove_file(src.join("big.bin")).unwrap();
    write(&src.join("new.txt"), b"new");
    repo.backup(std::slice::from_ref(&src), "h").unwrap();
    write(&src.join("notes.txt"), b"v2");
    let (latest, _) = repo.backup(std::slice::from_ref(&src), "h").unwrap();
    let before = store_size(&store);

    let stats = repo
        .prune(&RetentionPolicy {
            last: Some(1),
            ..Default::default()
        })
        .unwrap();
    assert_eq!((stats.snapshots_kept, stats.snapshots_removed), (1, 2));
    assert!(stats.packs_deleted >= 3, "{stats:?}");
    assert!(stats.bytes_deleted >= 3 << 20, "{stats:?}");
    assert!(store_size(&store) < before - (3 << 20) + (64 << 10));

    // Pruning again finds nothing to do.
    let again = repo
        .prune(&RetentionPolicy {
            last: Some(1),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        (
            again.snapshots_removed,
            again.packs_deleted,
            again.packs_repacked
        ),
        (0, 0, 0)
    );

    // What's kept is intact, including from a fresh machine.
    assert!(repo.verify(u64::MAX).unwrap().is_ok());
    let mut fresh = Repository::open(
        LocalDirBackend::open(&store).unwrap(),
        &master,
        Index::open_in_memory().unwrap(),
    );
    assert_eq!(fresh.list_snapshots().unwrap().len(), 1);
    let out = tmp.path().join("out");
    fresh.restore(&latest, &out, None).unwrap();
    let root = out.join(kinvault_core::snapshot_root_name(
        &fs::canonicalize(&src).unwrap(),
    ));
    assert_eq!(fs::read(root.join("notes.txt")).unwrap(), b"v2");
    assert_eq!(fs::read(root.join("new.txt")).unwrap(), b"new");
    assert!(!root.join("big.bin").exists());
}

#[test]
fn prune_rewrites_mostly_dead_packs() {
    let tmp = tempfile::tempdir().unwrap();
    // Large pack target: both files share one data pack.
    let (src, store, _, mut repo) = setup(tmp.path(), 64 << 20);
    write(&src.join("keep.bin"), &random(100 << 10, "keep"));
    write(&src.join("drop.bin"), &random(900 << 10, "drop"));
    repo.backup(std::slice::from_ref(&src), "h").unwrap();
    fs::remove_file(src.join("drop.bin")).unwrap();
    let (latest, _) = repo.backup(std::slice::from_ref(&src), "h").unwrap();

    let stats = repo
        .prune(&RetentionPolicy {
            last: Some(1),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(stats.packs_repacked, 1, "{stats:?}");
    assert!(stats.bytes_downloaded >= 1000 << 10, "{stats:?}");
    assert!(stats.bytes_uploaded < 200 << 10, "{stats:?}");
    assert!(store_size(&store) < 300 << 10);

    let out = tmp.path().join("out");
    repo.restore(&latest, &out, None).unwrap();
    let root = out.join(kinvault_core::snapshot_root_name(
        &fs::canonicalize(&src).unwrap(),
    ));
    assert_eq!(
        fs::read(root.join("keep.bin")).unwrap(),
        random(100 << 10, "keep")
    );
    assert!(repo.verify(u64::MAX).unwrap().is_ok());
}

#[test]
fn verify_detects_damage_and_the_next_backup_heals_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, store, _, mut repo) = setup(tmp.path(), 256 << 10);
    write(&src.join("a.bin"), &random(1 << 20, "a"));
    write(&src.join("b.bin"), &random(1 << 20, "b"));
    repo.backup(std::slice::from_ref(&src), "h").unwrap();
    let report = repo.verify(u64::MAX).unwrap();
    assert!(report.is_ok(), "{report:?}");
    assert!(report.packs_checked >= 4);

    // Bit rot in one data pack, and another lost entirely (data packs are the large ones).
    let mut packs = pack_files(&store);
    packs.sort_by_key(|p| std::cmp::Reverse(fs::metadata(p).unwrap().len()));
    let mut bytes = fs::read(&packs[0]).unwrap();
    bytes[100] ^= 0xff;
    fs::write(&packs[0], bytes).unwrap();
    fs::remove_file(&packs[1]).unwrap();

    let report = repo.verify(u64::MAX).unwrap();
    assert!(!report.is_ok());
    assert_eq!(report.damaged_packs.len(), 1, "{report:?}");
    assert!(report.missing_chunks > 0, "{report:?}");

    // The files still exist locally, so the next backup re-uploads what was lost.
    let (latest, stats) = repo.backup(std::slice::from_ref(&src), "h").unwrap();
    assert!(stats.bytes_uploaded > 0);
    let report = repo.verify(u64::MAX).unwrap();
    assert!(report.is_ok(), "{report:?}");
    let out = tmp.path().join("out");
    repo.restore(&latest, &out, None).unwrap();
}

#[test]
fn verify_budget_rotates_through_packs() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, store, _, mut repo) = setup(tmp.path(), 256 << 10);
    write(&src.join("a.bin"), &random(1 << 20, "a"));
    repo.backup(std::slice::from_ref(&src), "h").unwrap();
    let total = pack_files(&store).len() as u64;
    let mut checked = 0;
    for _ in 0..total {
        let r = repo.verify(1).unwrap();
        assert_eq!(r.packs_checked, 1);
        checked += r.packs_checked;
    }
    assert_eq!(checked, total);
}

#[test]
fn prune_and_verify_report_their_progress() {
    use kinvault_core::{MaintenanceProgress, MaintenanceStep};

    let tmp = tempfile::tempdir().unwrap();
    let (src, _, _, mut repo) = setup(tmp.path(), 1 << 20);
    write(&src.join("big.bin"), &random(3 << 20, "big"));
    repo.backup(std::slice::from_ref(&src), "h").unwrap();
    write(&src.join("big.bin"), &random(3 << 20, "other"));
    repo.backup(std::slice::from_ref(&src), "h").unwrap();

    let check = |seen: &[MaintenanceProgress], steps: &[MaintenanceStep]| {
        let mut order: Vec<MaintenanceStep> = seen.iter().map(|p| p.step).collect();
        order.dedup();
        assert_eq!(order, steps, "{seen:?}");
        assert!(seen.iter().all(|p| p.done <= p.total), "{seen:?}");
    };

    let mut seen = Vec::new();
    let report = repo
        .verify_with_progress(u64::MAX, &mut |p| seen.push(*p))
        .unwrap();
    assert!(report.is_ok());
    check(
        &seen,
        &[MaintenanceStep::Listings, MaintenanceStep::Checking],
    );
    let last = seen.last().unwrap();
    assert!(last.total > 2 << 20 && last.done == last.total, "{last:?}");

    // Dropping the first snapshot leaves its data unused, to be deleted.
    let mut seen = Vec::new();
    let stats = repo
        .prune_with_progress(
            &RetentionPolicy {
                last: Some(1),
                ..Default::default()
            },
            &mut |p| seen.push(*p),
        )
        .unwrap();
    assert!(stats.packs_deleted > 0, "{stats:?}");
    check(
        &seen,
        &[MaintenanceStep::Listings, MaintenanceStep::Deleting],
    );
    let deleting = seen.last().unwrap();
    assert_eq!(deleting.total, stats.packs_deleted + stats.packs_repacked);
}
