use crate::{invalid, Result, MAX_FILE_BYTES};
use std::{fs, io::{Read, Write}, path::Path};

pub fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() > MAX_FILE_BYTES { return Err(invalid("configuration exceeds 8 MiB limit")); }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES+1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES { return Err(invalid("configuration exceeds 8 MiB limit")); }
    Ok(bytes)
}

pub fn write_atomic(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    if bytes.len() as u64 > MAX_FILE_BYTES { return Err(invalid("configuration exceeds 8 MiB limit")); }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_file() { return Err(invalid("destination must be a regular file, not a symlink/directory")); }
        if !overwrite { return Err(invalid("destination already exists; use --overwrite to replace it")); }
    }
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    if overwrite { tmp.persist(path).map_err(|e| e.error)?; }
    else { tmp.persist_noclobber(path).map_err(|e| e.error)?; }
    // Best-effort directory durability. Not portable to all filesystems/Windows.
    #[cfg(unix)] { if let Ok(dir) = fs::File::open(parent) { let _ = dir.sync_all(); } }
    Ok(())
}
