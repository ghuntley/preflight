use anyhow::Result;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Verdict {
    pub rules: Vec<String>,
    pub artifact: Option<String>,
    pub artifact_digest: Option<String>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub memory_entries: usize,
    pub disk_entries: usize,
    pub artifact_bytes: u64,
    pub max_artifact_bytes: u64,
    pub ttl_secs: i64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_entries: 50_000,
            disk_entries: 100_000,
            artifact_bytes: 1024 * 1024 * 1024,
            max_artifact_bytes: 64 * 1024 * 1024,
            ttl_secs: 7 * 86400,
        }
    }
}
pub struct Cache {
    _lock: std::fs::File,
    db: Connection,
    memory: HashMap<String, (i64, u64, Verdict)>,
    generation: u64,
    tick: u64,
    dir: PathBuf,
    limits: Limits,
}
impl Cache {
    pub fn open(path: &Path) -> Result<Self> {
        Self::with_limits(path, Limits::default())
    }
    pub fn with_limits(path: &Path, limits: Limits) -> Result<Self> {
        anyhow::ensure!(
            limits.ttl_secs > 0 && limits.memory_entries > 0 && limits.disk_entries > 0,
            "invalid cache limits"
        );
        std::fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::create_dir_all(path.join("artifacts"))?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.join("cache.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        let db = Connection::open(path.join("verdicts.sqlite"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA secure_delete=ON; CREATE TABLE IF NOT EXISTS verdicts (key TEXT PRIMARY KEY, expires INTEGER NOT NULL, accessed INTEGER NOT NULL, value TEXT NOT NULL);")?;
        let mut result = Self {
            _lock: lock,
            db,
            memory: HashMap::new(),
            generation: 0,
            tick: 0,
            dir: path.into(),
            limits,
        };
        result.sweep()?;
        Ok(result)
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    fn remember(&mut self, key: &str, expires: i64, v: Verdict) {
        self.tick += 1;
        if self.memory.len() >= self.limits.memory_entries
            && let Some(k) = self
                .memory
                .iter()
                .min_by_key(|(_, (_, tick, _))| tick)
                .map(|(k, _)| k.clone())
        {
            self.memory.remove(&k);
        }
        self.memory.insert(key.into(), (expires, self.tick, v));
    }
    pub fn get(&mut self, key: &str) -> Option<(Verdict, Option<Vec<u8>>)> {
        self.tick += 1;
        let (mut expires, v) = if let Some((expires, tick, v)) =
            self.memory.get_mut(key).filter(|(e, _, _)| *e > now())
        {
            *tick = self.tick;
            (*expires, v.clone())
        } else {
            self.db
                .query_row(
                    "SELECT expires,value FROM verdicts WHERE key=?1 AND expires>?2",
                    params![key, now()],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .ok()
                .and_then(|(e, s)| serde_json::from_str(&s).ok().map(|v| (e, v)))?
        };
        let artifact = if let Some(id) = &v.artifact {
            if uuid::Uuid::parse_str(id).is_err() {
                return None;
            }
            let file = self.dir.join("artifacts").join(id);
            if std::fs::metadata(&file).ok()?.len() > self.limits.max_artifact_bytes {
                return None;
            }
            let bytes = std::fs::read(file).ok()?;
            if Some(crate::digest(&bytes)) != v.artifact_digest {
                return None;
            }
            Some(bytes)
        } else {
            None
        };
        // Coarse access refresh avoids one SQLite write per hot lookup.
        let refresh_interval = (self.limits.ttl_secs / 2).clamp(1, 3600);
        if expires - now() < self.limits.ttl_secs - refresh_interval {
            let refreshed = now() + self.limits.ttl_secs;
            if self
                .db
                .execute(
                    "UPDATE verdicts SET expires=?2,accessed=?3 WHERE key=?1",
                    params![key, refreshed, now()],
                )
                .is_ok()
            {
                expires = refreshed;
            }
        }
        self.remember(key, expires, v.clone());
        Some((v, artifact))
    }
    pub fn contains(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }
    pub fn insert(&mut self, key: &str, generation: u64) -> Result<()> {
        self.put(key, generation, Verdict::default(), None)
    }
    /// @cc [owner:ghuntley,label:security] generation-insertion
    /// An insertion with a generation captured before the latest purge MUST NOT
    /// repopulate persistent or memory caches. Callers MUST supply complete verdicts.
    pub fn put(
        &mut self,
        key: &str,
        generation: u64,
        mut verdict: Verdict,
        artifact: Option<&[u8]>,
    ) -> Result<()> {
        if generation != self.generation {
            return Ok(());
        }
        if let Some(bytes) = artifact {
            if bytes.len() as u64 > self.limits.max_artifact_bytes
                || bytes.len() as u64 > self.limits.artifact_bytes
            {
                return Ok(());
            }
            let id = uuid::Uuid::new_v4().to_string();
            let mut temp = tempfile::NamedTempFile::new_in(self.dir.join("artifacts"))?;
            use std::io::Write;
            temp.write_all(bytes)?;
            temp.as_file().sync_all()?;
            temp.persist(self.dir.join("artifacts").join(&id))?;
            verdict.artifact = Some(id);
            verdict.artifact_digest = Some(crate::digest(bytes));
        }
        let expires = now() + self.limits.ttl_secs;
        self.db.execute(
            "INSERT OR REPLACE INTO verdicts VALUES (?1,?2,?3,?4)",
            params![key, expires, now(), serde_json::to_string(&verdict)?],
        )?;
        self.remember(key, expires, verdict);
        self.sweep()?;
        Ok(())
    }
    pub fn sweep(&mut self) -> Result<()> {
        self.db
            .execute("DELETE FROM verdicts WHERE expires<=?1", [now()])?;
        self.db.execute("DELETE FROM verdicts WHERE key IN (SELECT key FROM verdicts ORDER BY accessed DESC LIMIT -1 OFFSET ?1)",[self.limits.disk_entries as u64])?;
        let records: Vec<(String, String)> = self
            .db
            .prepare("SELECT key,value FROM verdicts ORDER BY accessed DESC")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let mut retained = std::collections::HashSet::new();
        let mut total = 0u64;
        for (key, json) in records {
            let v: Verdict = serde_json::from_str(&json)?;
            if let Some(id) = v.artifact {
                let size = std::fs::metadata(self.dir.join("artifacts").join(&id))
                    .map(|m| m.len())
                    .unwrap_or(u64::MAX);
                if uuid::Uuid::parse_str(&id).is_err()
                    || total.saturating_add(size) > self.limits.artifact_bytes
                {
                    self.db
                        .execute("DELETE FROM verdicts WHERE key=?1", [&key])?;
                    self.memory.remove(&key);
                } else {
                    total += size;
                    retained.insert(id);
                }
            }
        }
        for entry in std::fs::read_dir(self.dir.join("artifacts"))? {
            let e = entry?;
            if !retained.contains(&e.file_name().to_string_lossy().to_string()) {
                std::fs::remove_file(e.path())?;
            }
        }
        self.memory.retain(|_, (e, _, _)| *e > now());
        Ok(())
    }
    /// @cc [owner:ghuntley,label:security] purge-invalidates
    /// Successful purge MUST invalidate all prior verdicts in memory and SQLite.
    pub fn purge(&mut self) -> Result<()> {
        self.generation = self.generation.wrapping_add(1);
        self.memory.clear();
        self.db.execute("DELETE FROM verdicts", [])?;
        self.sweep()?;
        self.db
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
        Ok(())
    }
    /// @cc [owner:ghuntley,label:security] purge-scope-isolation
    /// Scoped purge MUST delete only records prefixed by that validated scope.
    /// Advancing the global generation MAY prevent unrelated in-flight insertions.
    pub fn purge_scope(&mut self, scope: &str) -> Result<()> {
        anyhow::ensure!(
            scope.len() == 64 && scope.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid scope"
        );
        self.generation = self.generation.wrapping_add(1);
        let prefix = format!("{scope}:");
        self.memory.retain(|key, _| !key.starts_with(&prefix));
        self.db.execute(
            "DELETE FROM verdicts WHERE key LIKE ?1",
            [format!("{prefix}%")],
        )?;
        self.sweep()?;
        Ok(())
    }
    pub fn count(&self) -> Result<u64> {
        Ok(self
            .db
            .query_row("SELECT count(*) FROM verdicts", [], |r| r.get(0))?)
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn access_refresh_updates_memory_and_database_together() {
        let temp = tempfile::tempdir().unwrap();
        let mut cache = Cache::open(temp.path()).unwrap();
        cache.insert("entry", cache.generation()).unwrap();
        let old = now() + cache.limits.ttl_secs - 7200;
        cache.memory.get_mut("entry").unwrap().0 = old;
        assert!(cache.contains("entry"));
        let memory_expiry = cache.memory["entry"].0;
        let disk_expiry = cache
            .db
            .query_row("SELECT expires FROM verdicts WHERE key='entry'", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
        assert!(memory_expiry > old);
        assert_eq!(memory_expiry, disk_expiry);
    }
}
