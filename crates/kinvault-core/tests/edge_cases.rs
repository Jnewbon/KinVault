//! Less common paths through backup and restore: files that change or can't
//! be read mid-scan, odd sources, cancelling, and missing data.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, UNIX_EPOCH};

use kinvault_core::pack::{self, BlobKind};
use kinvault_core::{
    Backend, BackupProgress, Error, Index, LocalDirBackend, MasterKey, Repository,
    snapshot_root_name,
};

fn repo(tmp: &Path) -> Repository<LocalDirBackend> {
    Repository::open(
        LocalDirBackend::create(tmp.join("store")).unwrap(),
        &MasterKey::generate().unwrap(),
        Index::open_in_memory().unwrap(),
    )
}

/// A second repository over the same storage, with an empty index.
fn reopen(tmp: &Path, master: &MasterKey) -> Repository<LocalDirBackend> {
    Repository::open(
        LocalDirBackend::open(tmp.join("store")).unwrap(),
        master,
        Index::open_in_memory().unwrap(),
    )
}

fn pseudo_random(len: usize, seed: &str) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(seed.as_bytes())
        .finalize_xof()
        .fill(&mut buf);
    buf
}

fn root_name(src: &Path) -> String {
    snapshot_root_name(&fs::canonicalize(src).unwrap())
}

#[test]
fn progress_is_reported_while_backing_up() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a"), b"aaa").unwrap();
    fs::write(src.join("b"), b"bbbb").unwrap();
    let mut repo = repo(tmp.path());
    let seen: Arc<Mutex<Vec<BackupProgress>>> = Arc::default();
    let sink = seen.clone();
    repo.set_progress(Some(Arc::new(move |p: &BackupProgress| {
        sink.lock().unwrap().push(*p)
    })));
    repo.backup(std::slice::from_ref(&src), "host").unwrap();
    // Unchanged files are reported too.
    repo.backup(std::slice::from_ref(&src), "host").unwrap();
    repo.set_progress(None);
    repo.backup(std::slice::from_ref(&src), "host").unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 4);
    assert_eq!((seen[1].files, seen[1].bytes_read), (2, 7));
    assert_eq!(
        (seen[3].files, seen[3].total_bytes, seen[3].bytes_read),
        (2, 7, 0)
    );
}

#[test]
fn sources_missing_repeated_or_excluded() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let skipped = tmp.path().join("skipped");
    fs::create_dir_all(src.join("private")).unwrap();
    fs::create_dir_all(&skipped).unwrap();
    fs::write(src.join("kept"), b"k").unwrap();
    fs::write(src.join("private/secret"), b"s").unwrap();
    fs::write(skipped.join("x"), b"x").unwrap();
    let mut repo = repo(tmp.path());

    let missing = tmp.path().join("missing");
    assert!(matches!(
        repo.backup(&[src.clone(), missing], "host"),
        Err(Error::NotFound(_))
    ));

    repo.set_excludes(vec![
        fs::canonicalize(src.join("private")).unwrap(),
        fs::canonicalize(&skipped).unwrap(),
    ]);
    let (_, stats) = repo
        .backup(&[src.clone(), src.join("."), skipped], "host")
        .unwrap();
    assert_eq!(stats.files, 1);
    let snapshot = repo
        .load_snapshot(&repo.find_snapshot("latest").unwrap())
        .unwrap();
    // The repeated source counts once; the excluded one is listed but empty.
    assert_eq!(snapshot.paths.len(), 2);
}

#[cfg(unix)]
#[test]
fn files_changing_during_the_scan_are_skipped_with_warnings() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(src.join("locked")).unwrap();
    for name in ["a", "b", "c", "d"] {
        fs::write(src.join(name), name).unwrap();
    }
    fs::write(src.join("locked/inside"), b"i").unwrap();
    fs::set_permissions(src.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    // Root can read anything; there's nothing to test then.
    let root = fs::read_dir(src.join("locked")).is_ok();
    // Sockets and other special files aren't backed up.
    let _socket = std::os::unix::net::UnixListener::bind(src.join("socket")).unwrap();

    let mut repo = repo(tmp.path());
    // After the first file: one file vanishes and one becomes unreadable,
    // after the folder was listed.
    let once = Once::new();
    let (b, c) = (src.join("b"), src.join("c"));
    repo.set_progress(Some(Arc::new(move |_: &BackupProgress| {
        once.call_once(|| {
            fs::remove_file(&b).unwrap();
            fs::set_permissions(&c, fs::Permissions::from_mode(0o000)).unwrap();
        })
    })));
    let (_, stats) = repo.backup(std::slice::from_ref(&src), "host").unwrap();
    fs::set_permissions(src.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();

    let warned = |name: &str| {
        stats
            .warnings
            .iter()
            .any(|w| w.starts_with(&format!("{}: ", src.join(name).display())))
    };
    assert!(warned("b"), "{:?}", stats.warnings);
    assert_eq!(warned("c"), !root, "{:?}", stats.warnings);
    assert_eq!(warned("locked"), !root, "{:?}", stats.warnings);
    assert_eq!(stats.files, if root { 3 } else { 2 });
}

#[test]
fn files_from_before_1970_keep_their_date() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let old = UNIX_EPOCH - Duration::from_secs(86_400);
    let file = fs::File::create(src.join("old")).unwrap();
    file.set_modified(old).unwrap();
    drop(file);
    let mut repo = repo(tmp.path());
    let (snap, _) = repo.backup(std::slice::from_ref(&src), "host").unwrap();
    let out = tmp.path().join("out");
    repo.restore(&snap, &out, None).unwrap();
    let restored = out.join(root_name(&src)).join("old");
    assert_eq!(fs::metadata(restored).unwrap().modified().unwrap(), old);
}

#[test]
fn snapshots_are_found_by_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let mut repo = repo(tmp.path());
    assert!(matches!(
        repo.find_snapshot("latest"),
        Err(Error::NotFound(_))
    ));
    fs::write(src.join("f"), b"1").unwrap();
    let (first, _) = repo.backup(std::slice::from_ref(&src), "host").unwrap();
    fs::write(src.join("f"), b"22").unwrap();
    let (second, _) = repo.backup(std::slice::from_ref(&src), "host").unwrap();

    assert_eq!(repo.find_snapshot("latest").unwrap(), second);
    let hex = first.to_hex();
    assert_eq!(
        repo.find_snapshot(&hex[..12].to_uppercase()).unwrap(),
        first
    );
    assert!(matches!(repo.find_snapshot("xyz"), Err(Error::NotFound(_))));
    // Every id starts with the empty prefix.
    assert!(matches!(repo.find_snapshot(""), Err(Error::Invalid(_))));
}

#[test]
fn restores_can_be_cancelled_before_and_during_a_file() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("big"), pseudo_random(6 * 1024 * 1024, "big")).unwrap();
    let mut repo = repo(tmp.path());
    let (snap, _) = repo.backup(std::slice::from_ref(&src), "host").unwrap();

    let out = tmp.path().join("before");
    let err = repo
        .restore_with_progress(&snap, &out, None, &mut |_| false)
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    assert!(!out.exists());

    let err = repo
        .restore_with_progress(&snap, &tmp.path().join("during"), None, &mut |p| {
            p.bytes == 0
        })
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
}

#[cfg(unix)]
#[test]
fn restoring_a_folder_with_symlinks_counts_only_files() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(src.join("dir")).unwrap();
    fs::write(src.join("dir/f"), b"data").unwrap();
    std::os::unix::fs::symlink("f", src.join("dir/link")).unwrap();
    let mut repo = repo(tmp.path());
    let (snap, _) = repo.backup(std::slice::from_ref(&src), "host").unwrap();

    let out = tmp.path().join("out");
    let mut last = None;
    let include = format!("{}/dir", root_name(&src));
    let stats = repo
        .restore_with_progress(&snap, &out, Some(&include), &mut |p| {
            last = Some(*p);
            true
        })
        .unwrap();
    assert_eq!((stats.files, stats.symlinks), (1, 1));
    assert_eq!(last.unwrap().total_files, 1);
    // Restoring again replaces the symlink.
    repo.restore(&snap, &out, Some(&include)).unwrap();
    let link = out.join(&include).join("link");
    assert_eq!(fs::read_link(link).unwrap(), PathBuf::from("f"));
}

#[test]
fn restore_reports_data_missing_from_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("f"), b"contents").unwrap();
    let master = MasterKey::generate().unwrap();
    let mut repo = Repository::open(
        LocalDirBackend::create(tmp.path().join("store")).unwrap(),
        &master,
        Index::open_in_memory().unwrap(),
    );
    let (snap, _) = repo.backup(std::slice::from_ref(&src), "host").unwrap();

    // Remove the pack holding the file's data, keeping the folder listings.
    let data_pack = repo
        .backend()
        .list_packs()
        .unwrap()
        .into_iter()
        .find(|p| {
            let pack = repo.backend().get_pack(p).unwrap();
            let keys = master.derive_keys();
            pack::read_header(&keys, &pack).unwrap()[0].kind == BlobKind::Data
        })
        .unwrap();
    repo.backend().delete_pack(&data_pack).unwrap();

    // A fresh index learns what storage holds before restoring.
    let mut fresh = reopen(tmp.path(), &master);
    let err = fresh
        .restore(&snap, &tmp.path().join("out"), None)
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err}");
}

#[test]
fn large_pack_headers_are_fetched_in_full() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    // Enough small files that one pack's header outgrows the first fetch.
    for i in 0..2500 {
        fs::write(src.join(format!("{i}")), format!("file {i}")).unwrap();
    }
    let master = MasterKey::generate().unwrap();
    let mut repo = Repository::open(
        LocalDirBackend::create(tmp.path().join("store")).unwrap(),
        &master,
        Index::open_in_memory().unwrap(),
    );
    repo.set_pack_target(64 * 1024 * 1024);
    let (snap, _) = repo.backup(std::slice::from_ref(&src), "host").unwrap();

    let mut fresh = reopen(tmp.path(), &master);
    let stats = fresh.restore(&snap, &tmp.path().join("out"), None).unwrap();
    assert_eq!(stats.files, 2500);
}
