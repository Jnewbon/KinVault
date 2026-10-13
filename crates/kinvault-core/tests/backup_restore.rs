use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use kinvault_core::{
    Backend, Index, LocalDirBackend, MasterKey, PackId, Repository, Result, SnapshotId,
};

/// Wraps a backend and counts bytes sent to it, to check incremental traffic.
struct Counting {
    inner: LocalDirBackend,
    uploaded: AtomicU64,
}

impl Backend for Counting {
    fn put_pack(&self, id: &PackId, data: &[u8]) -> Result<()> {
        self.uploaded
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        self.inner.put_pack(id, data)
    }
    fn get_pack(&self, id: &PackId) -> Result<Vec<u8>> {
        self.inner.get_pack(id)
    }
    fn list_packs(&self) -> Result<Vec<PackId>> {
        self.inner.list_packs()
    }
    fn delete_pack(&self, id: &PackId) -> Result<()> {
        self.inner.delete_pack(id)
    }
    fn put_snapshot(&self, id: &SnapshotId, data: &[u8]) -> Result<()> {
        self.uploaded
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        self.inner.put_snapshot(id, data)
    }
    fn get_snapshot(&self, id: &SnapshotId) -> Result<Vec<u8>> {
        self.inner.get_snapshot(id)
    }
    fn list_snapshots(&self) -> Result<Vec<SnapshotId>> {
        self.inner.list_snapshots()
    }
    fn delete_snapshot(&self, id: &SnapshotId) -> Result<()> {
        self.inner.delete_snapshot(id)
    }
}

const MARKER: &[u8] = b"KINVAULT-PLAINTEXT-MARKER-0123456789";

fn pseudo_random(len: usize, seed: &str) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(seed.as_bytes())
        .finalize_xof()
        .fill(&mut buf);
    buf
}

fn make_tree(src: &Path) {
    fs::create_dir_all(src.join("docs/nested")).unwrap();
    fs::create_dir_all(src.join("empty")).unwrap();
    let mut text = MARKER.repeat(1000);
    text.extend_from_slice(b"\nend");
    fs::write(src.join("docs/notes.txt"), &text).unwrap();
    fs::write(src.join("docs/nested/copy.txt"), &text).unwrap();
    fs::write(src.join("empty.bin"), b"").unwrap();
    fs::write(src.join("big.bin"), pseudo_random(8 * 1024 * 1024, "big")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("docs/notes.txt", src.join("link")).unwrap();
}

/// Asserts every regular file/symlink under `a` matches the one under `b`.
fn assert_same(a: &Path, b: &Path) {
    let mut count = 0;
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for entry in fs::read_dir(a.join(&rel)).unwrap() {
            let entry = entry.unwrap();
            let rel = rel.join(entry.file_name());
            let ft = entry.file_type().unwrap();
            if ft.is_symlink() {
                assert_eq!(
                    fs::read_link(a.join(&rel)).unwrap(),
                    fs::read_link(b.join(&rel)).unwrap()
                );
            } else if ft.is_dir() {
                assert!(b.join(&rel).is_dir(), "missing dir {rel:?}");
                stack.push(rel);
            } else {
                assert_eq!(
                    fs::read(a.join(&rel)).unwrap(),
                    fs::read(b.join(&rel)).unwrap(),
                    "{rel:?}"
                );
                let ma = fs::metadata(a.join(&rel)).unwrap().modified().unwrap();
                let mb = fs::metadata(b.join(&rel)).unwrap().modified().unwrap();
                assert_eq!(ma, mb, "mtime of {rel:?}");
            }
            count += 1;
        }
    }
    assert!(count > 0);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
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

#[test]
fn backup_restore_incremental_and_opaque() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let store = tmp.path().join("store");
    make_tree(&src);

    let master = MasterKey::generate().unwrap();
    let backend = Counting {
        inner: LocalDirBackend::create(&store).unwrap(),
        uploaded: AtomicU64::new(0),
    };
    let mut repo = Repository::open(
        backend,
        &master,
        Index::open(&tmp.path().join("index.db")).unwrap(),
    );
    repo.set_pack_target(4 * 1024 * 1024);

    // First backup: duplicated text file is stored once.
    let (snap1, stats1) = repo
        .backup(std::slice::from_ref(&src), "test-host")
        .unwrap();
    assert!(stats1.warnings.is_empty(), "{:?}", stats1.warnings);
    assert_eq!(stats1.files, 4);
    let first_upload = repo.backend().uploaded.load(Ordering::Relaxed);

    // Nothing changed: no file is re-read, and only the small snapshot record is sent.
    let before = repo.backend().uploaded.load(Ordering::Relaxed);
    let (_, stats2) = repo
        .backup(std::slice::from_ref(&src), "test-host")
        .unwrap();
    assert_eq!(stats2.files_changed, 0);
    assert_eq!(stats2.bytes_read, 0);
    assert_eq!(stats2.packs_uploaded, 0);
    assert!(repo.backend().uploaded.load(Ordering::Relaxed) - before < 1024);

    // One byte changed in the 8 MiB file: only ~one chunk is uploaded.
    let big = src.join("big.bin");
    let mut data = fs::read(&big).unwrap();
    data[4 * 1024 * 1024] ^= 0xff;
    fs::write(&big, &data).unwrap();
    fs::File::options()
        .write(true)
        .open(&big)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(5))
        .unwrap();
    let before = repo.backend().uploaded.load(Ordering::Relaxed);
    let (snap3, stats3) = repo
        .backup(std::slice::from_ref(&src), "test-host")
        .unwrap();
    let delta = repo.backend().uploaded.load(Ordering::Relaxed) - before;
    assert_eq!(stats3.files_changed, 1);
    assert!(
        delta < 2 * 4 * 1024 * 1024 + 64 * 1024,
        "uploaded {delta} bytes for a 1-byte change"
    );
    assert!(delta < first_upload / 2);

    // The store holds no plaintext: neither file contents nor file names.
    for f in all_files(&store) {
        let bytes = fs::read(&f).unwrap();
        assert!(!contains(&bytes, MARKER), "plaintext found in {f:?}");
        assert!(!contains(&bytes, b"notes.txt"), "file name found in {f:?}");
        assert!(!contains(&bytes, b"test-host"), "hostname found in {f:?}");
    }

    // Restore the latest snapshot and compare.
    let out = tmp.path().join("restore");
    repo.restore(&snap3, &out, None).unwrap();
    let root_name = kinvault_core::snapshot_root_name(&fs::canonicalize(&src).unwrap());
    assert_same(&src, &out.join(&root_name));

    // Fresh machine: only the master key and the store, with an empty index.
    let fresh = Repository::open(
        LocalDirBackend::open(&store).unwrap(),
        &master,
        Index::open_in_memory().unwrap(),
    );
    let mut fresh = fresh;
    assert_eq!(fresh.list_snapshots().unwrap().len(), 3);
    assert_eq!(fresh.find_snapshot("latest").unwrap(), snap3);
    let out2 = tmp.path().join("restore2");
    fresh.restore(&snap3, &out2, None).unwrap();
    assert_same(&src, &out2.join(&root_name));

    // Partial restore of the first snapshot.
    let out3 = tmp.path().join("restore3");
    let stats = fresh
        .restore(&snap1, &out3, Some(&format!("{root_name}/docs")))
        .unwrap();
    assert_eq!(stats.files, 2);
    assert!(!out3.join(&root_name).join("big.bin").exists());
    assert!(out3.join(&root_name).join("docs/nested/copy.txt").exists());

    // A different key can't read anything.
    let stranger = Repository::open(
        LocalDirBackend::open(&store).unwrap(),
        &MasterKey::generate().unwrap(),
        Index::open_in_memory().unwrap(),
    );
    assert!(stranger.list_snapshots().is_err());
}

#[test]
fn corrupted_pack_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"some content").unwrap();
    let store = tmp.path().join("store");
    let master = MasterKey::generate().unwrap();
    let mut repo = Repository::open(
        LocalDirBackend::create(&store).unwrap(),
        &master,
        Index::open_in_memory().unwrap(),
    );
    let (snap, _) = repo.backup(&[src], "h").unwrap();

    for f in all_files(&store.join("packs")) {
        let mut bytes = fs::read(&f).unwrap();
        bytes[10] ^= 1;
        fs::write(&f, bytes).unwrap();
    }
    let err = repo
        .restore(&snap, &tmp.path().join("out"), None)
        .unwrap_err();
    assert!(err.to_string().contains("corrupt"), "{err}");
}

#[test]
fn unchanged_backup_reuses_previous_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"some content").unwrap();
    let mut repo = Repository::open(
        LocalDirBackend::create(tmp.path().join("store")).unwrap(),
        &MasterKey::generate().unwrap(),
        Index::open_in_memory().unwrap(),
    );
    let sources = std::slice::from_ref(&src);
    let (first, _) = repo.backup(sources, "h").unwrap();

    let (same, stats) = repo.backup_if_changed(sources, "h", Some(&first)).unwrap();
    assert_eq!(same, first);
    assert_eq!(stats.files_changed, 0);
    assert_eq!(repo.list_snapshots().unwrap().len(), 1);

    // A previous snapshot that no longer exists doesn't stop a backup.
    let gone = SnapshotId::from_hex(&"00".repeat(32)).unwrap();
    let (fresh, _) = repo.backup_if_changed(sources, "h", Some(&gone)).unwrap();
    assert_ne!(fresh, first);

    fs::write(src.join("a.txt"), b"other content").unwrap();
    let (changed, _) = repo.backup_if_changed(sources, "h", Some(&fresh)).unwrap();
    assert_ne!(changed, fresh);
    assert_eq!(repo.list_snapshots().unwrap().len(), 3);
}

#[test]
fn restore_reports_progress_and_can_be_cancelled() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    make_tree(&src);
    let master = MasterKey::generate().unwrap();
    let mut repo = Repository::open(
        LocalDirBackend::create(tmp.path().join("store")).unwrap(),
        &master,
        Index::open_in_memory().unwrap(),
    );
    let (snap, stats) = repo
        .backup(std::slice::from_ref(&src), "test-host")
        .unwrap();
    let root_name = kinvault_core::snapshot_root_name(&fs::canonicalize(&src).unwrap());

    // Everything: totals come from the snapshot, and the last report reaches them.
    let mut seen = Vec::new();
    repo.restore_with_progress(&snap, &tmp.path().join("all"), None, &mut |p| {
        seen.push(*p);
        true
    })
    .unwrap();
    let last = seen.last().unwrap();
    assert_eq!(
        (last.total_files, last.total_bytes),
        (stats.files, stats.total_bytes)
    );
    assert_eq!(
        (last.files, last.bytes),
        (last.total_files, last.total_bytes)
    );
    assert!(seen.windows(2).all(|w| w[0].bytes <= w[1].bytes));

    // Part of it: totals count only that part.
    let mut last = None;
    let part = repo
        .restore_with_progress(
            &snap,
            &tmp.path().join("part"),
            Some(&format!("{root_name}/docs")),
            &mut |p| {
                last = Some(*p);
                true
            },
        )
        .unwrap();
    let last = last.unwrap();
    assert_eq!(last.total_files, part.files);
    assert_eq!(last.total_bytes, part.bytes);
    assert!(last.total_files < stats.files);

    // Cancelled after the first file.
    let err = repo
        .restore_with_progress(&snap, &tmp.path().join("cancelled"), None, &mut |p| {
            p.files == 0
        })
        .unwrap_err();
    assert!(matches!(err, kinvault_core::Error::Cancelled), "{err}");
}

#[test]
fn excluded_files_are_left_out_of_new_snapshots_only() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    make_tree(&src);
    let master = MasterKey::generate().unwrap();
    let mut repo = Repository::open(
        LocalDirBackend::create(tmp.path().join("store")).unwrap(),
        &master,
        Index::open_in_memory().unwrap(),
    );
    let (before, _) = repo
        .backup(std::slice::from_ref(&src), "test-host")
        .unwrap();

    // Added after the first backup: binaries anywhere, and one folder.
    repo.set_exclude_patterns(kinvault_core::Excludes::parse(&["*.bin", "docs/nested/"]).unwrap());
    let (after, stats) = repo
        .backup(std::slice::from_ref(&src), "test-host")
        .unwrap();
    assert_ne!(before, after);

    let root = kinvault_core::snapshot_root_name(&fs::canonicalize(&src).unwrap());
    let out = tmp.path().join("after");
    repo.restore(&after, &out, None).unwrap();
    let restored = out.join(&root);
    assert!(restored.join("docs/notes.txt").exists());
    assert!(!restored.join("big.bin").exists());
    assert!(!restored.join("empty.bin").exists());
    assert!(!restored.join("docs/nested").exists());
    assert!(stats.total_bytes < 1024 * 1024, "{stats:?}");

    // The earlier snapshot still has them until retention removes it.
    let out = tmp.path().join("before");
    repo.restore(&before, &out, None).unwrap();
    assert!(out.join(&root).join("big.bin").exists());
    assert!(out.join(&root).join("docs/nested/copy.txt").exists());
}
