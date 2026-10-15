use std::fs;
use std::io::{self, Write};
use std::path::Path;

use iroh::SecretKey;

/// Loads this instance's long-term identity, creating it on first run.
/// The public half is the instance's address; the file must stay private.
pub fn load_or_create_secret(path: &Path) -> io::Result<SecretKey> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(text.trim(), &mut bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            let mut f = opts.open(path)?;
            f.write_all(hex::encode(key.to_bytes()).as_bytes())?;
            f.sync_all()?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_once_then_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("new/dir/secret");
        let created = load_or_create_secret(&path).unwrap();
        let loaded = load_or_create_secret(&path).unwrap();
        assert_eq!(created.to_bytes(), loaded.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn damaged_or_unreadable_files_are_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secret");
        fs::write(&path, "not hex").unwrap();
        let err = load_or_create_secret(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // A folder where the file should be: neither readable nor missing.
        assert!(load_or_create_secret(tmp.path()).is_err());
        // Missing, but with no folder to create it in.
        assert!(load_or_create_secret(Path::new("")).is_err());
    }
}
