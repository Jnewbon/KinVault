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
