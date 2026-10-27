//! Copying snapshots to another repository with the same key, e.g. a second
//! host that keeps fewer versions. Packs are copied as they are, so both
//! hold byte-identical data and either can be restored from.

use std::collections::{HashSet, VecDeque};

use super::Repository;
use crate::backend::Backend;
use crate::error::{Error, Result};
use crate::ids::{PackId, SnapshotId};
use crate::pack;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CopyStats {
    pub snapshots: u64,
    pub packs: u64,
    pub bytes: u64,
}

impl<B: Backend> Repository<B> {
    /// Copies `snapshots` to `dest`, which must use the same key, together
    /// with every pack they need that `dest` doesn't have. Packs go first and
    /// each snapshot last, so `dest` never lists one it can't restore.
    /// `progress` gets the bytes of packs copied so far and in total.
    pub fn copy_snapshots_to<D: Backend>(
        &self,
        dest: &mut Repository<D>,
        snapshots: &[SnapshotId],
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<CopyStats> {
        const PROBE: &[u8] = b"kinvault copy key check";
        if self.keys.chunk_id(PROBE) != dest.keys.chunk_id(PROBE) {
            return Err(Error::Invalid(
                "can't copy between backups with different keys".into(),
            ));
        }
        let mut stats = CopyStats::default();
        if snapshots.is_empty() {
            return Ok(stats);
        }
        dest.sync_index()?;

        // Everything the snapshots need, then the packs holding what `dest` lacks.
        let mut roots = Vec::with_capacity(snapshots.len());
        for id in snapshots {
            roots.push(self.load_snapshot(id)?.root);
        }
        let mut cache = VecDeque::new();
        let mut quiet: &mut dyn FnMut(&super::MaintenanceProgress) = &mut |_| {};
        let needed = self.reachable(&roots, &mut cache, &mut quiet)?;
        drop(cache);
        let mut packs: Vec<PackId> = Vec::new();
        let mut seen = HashSet::new();
        for chunk in &needed {
            if dest.index.has_chunk(chunk)? {
                continue;
            }
            let location = self
                .index
                .locate(chunk)?
                .ok_or_else(|| Error::Corrupt(format!("chunk {chunk} isn't in any pack")))?;
            if seen.insert(location.pack) {
                packs.push(location.pack);
            }
        }
        let sizes = self.index.pack_sizes()?;
        let total: u64 = packs.iter().filter_map(|p| sizes.get(p)).sum();
        progress(0, total);

        for id in &packs {
            self.check_cancelled()?;
            let data = self.fetch_pack(id)?;
            let entries = pack::read_header(&self.keys, &data)?;
            tracing::debug!(
                pack = %&id.to_hex()[..12],
                bytes = data.len(),
                "copying a pack"
            );
            dest.backend.put_pack(id, &data)?;
            dest.index.add_pack(id, &entries)?;
            stats.packs += 1;
            stats.bytes += data.len() as u64;
            progress(stats.bytes.min(total), total);
        }
        for id in snapshots {
            let data = self.backend.get_snapshot(id)?;
            dest.backend.put_snapshot(id, &data)?;
            stats.snapshots += 1;
        }
        Ok(stats)
    }

    /// The snapshots this repository holds, as `(id, time in ns)` pairs.
    pub fn snapshot_times(&self) -> Result<Vec<(SnapshotId, i64)>> {
        Ok(self
            .list_snapshots()?
            .into_iter()
            .map(|(id, s)| (id, s.time_ns))
            .collect())
    }
}
