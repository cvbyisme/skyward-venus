//! Letting a key into a filesystem, so the files it was used on can be
//! read. The kernel keeps the key for the filesystem, not for any one
//! file, and names it by a hash it works out itself.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// How long the name the kernel gives a key is.
pub const NAME_BYTES: usize = 16;

/// Let `raw` into the filesystem mounted at `mount`, and give the name the
/// kernel knows it by. Every file whose directory names that key can be
/// read from then on.
#[cfg(target_os = "android")]
pub fn add_key(mount: &Path, raw: &[u8], wrapped: bool) -> Result<[u8; NAME_BYTES]> {
    use std::os::fd::AsRawFd;
    /// The request's fixed part, before the key itself.
    const HEADER_BYTES: usize = 80;
    /// The key is named by what the kernel makes of it rather than by
    /// anything this side chooses.
    const BY_IDENTIFIER: u32 = 2;
    /// The key is one only the storage hardware can unwrap.
    const HARDWARE_WRAPPED: u32 = 1;
    const ADD_KEY: u32 = 0xc050_6617;

    let mut arg = vec![0u8; HEADER_BYTES + raw.len()];
    arg[0..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes());
    arg[40..44].copy_from_slice(&(raw.len() as u32).to_ne_bytes());
    if wrapped {
        arg[76..80].copy_from_slice(&HARDWARE_WRAPPED.to_ne_bytes());
    }
    arg[HEADER_BYTES..].copy_from_slice(raw);
    let dir = std::fs::File::open(mount).with_context(|| format!("open {}", mount.display()))?;
    if unsafe { libc::ioctl(dir.as_raw_fd(), ADD_KEY as libc::Ioctl, arg.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("let a key into {}", mount.display()));
    }
    let mut name = [0u8; NAME_BYTES];
    name.copy_from_slice(&arg[8..8 + NAME_BYTES]);
    Ok(name)
}

/// How a directory is encrypted, as the kernel records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Which generation of the record this is: 1 or 2.
    pub version: u8,
    pub contents_mode: u8,
    pub filenames_mode: u8,
    pub flags: u32,
    /// What the key is called: 16 bytes for a policy of the second kind, 8
    /// for one of the first, padded with zeroes.
    pub key: [u8; NAME_BYTES],
}

/// The request the kernel answers with how a directory is encrypted, and
/// the largest record the answer holds.
///
/// The number in the request is the one the header works out, not a size
/// guessed here: asking with the wrong one is answered with ENOTTY, and a
/// caller that takes any failure for "not encrypted" reads every encrypted
/// directory as plain.
const GET_POLICY_EX: u32 = 0xc008_6613;
const POLICY_BYTES: usize = 24;

/// How `dir` is encrypted, or `None` where it is not.
#[cfg(target_os = "android")]
pub fn policy(dir: &Path) -> Result<Option<Policy>> {
    use std::os::fd::AsRawFd;
    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    let mut arg = [0u8; 8 + POLICY_BYTES];
    arg[..8].copy_from_slice(&(POLICY_BYTES as u64).to_ne_bytes());
    if unsafe { libc::ioctl(folder.as_raw_fd(), GET_POLICY_EX as libc::Ioctl, arg.as_mut_ptr()) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(None);
        }
        return Err(e).with_context(|| format!("read how {} is encrypted", dir.display()));
    }
    let body = &arg[8..];
    let version = body[0];
    let (contents_mode, filenames_mode, flags) = (body[1], body[2], u32::from_ne_bytes(body[4..8].try_into().expect("four bytes")));
    let mut key = [0u8; NAME_BYTES];
    match version {
        // The first kind of policy is shorter than the second: its key is
        // called by eight bytes, and the rest of the record is not there.
        0 => key[..8].copy_from_slice(&body[8..16]),
        2 => key.copy_from_slice(&body[8..8 + NAME_BYTES]),
        other => bail!("{} is encrypted under a policy of version {other}, which is not known here", dir.display()),
    }
    Ok(Some(Policy { version, contents_mode, filenames_mode, flags, key }))
}

/// Whether the names and contents under `dir` read as they are: it is not
/// encrypted, or the key it is encrypted with is in the kernel. A user's
/// own files read only once that user's key is let in.
#[cfg(target_os = "android")]
pub fn unlocked(dir: &Path) -> Result<bool> {
    use std::os::fd::AsRawFd;
    const GET_KEY_STATUS: u32 = 0xc080_661a;
    /// How the first kind of policy names its key, and how the second does.
    const BY_DESCRIPTOR: u32 = 1;
    const BY_IDENTIFIER: u32 = 2;
    /// Where the answer says how the key stands: after the name of the key
    /// and the room the kernel keeps beside it.
    const STATUS_AT: usize = 56;
    const PRESENT: u32 = 2;
    let Some(how) = policy(dir)? else { return Ok(true) };
    let mut ask = [0u8; 128];
    match how.version {
        0 => {
            ask[..4].copy_from_slice(&BY_DESCRIPTOR.to_ne_bytes());
            ask[8..16].copy_from_slice(&how.key[..8]);
        }
        _ => {
            ask[..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes());
            ask[8..8 + NAME_BYTES].copy_from_slice(&how.key);
        }
    }
    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    if unsafe { libc::ioctl(folder.as_raw_fd(), GET_KEY_STATUS as libc::Ioctl, ask.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("ask whether the key for {} is in", dir.display()));
    }
    let status = u32::from_ne_bytes(ask[STATUS_AT..STATUS_AT + 4].try_into().expect("four bytes"));
    Ok(status == PRESENT)
}

/// Whether `dir` can be listed with the names it was written with: the
/// only proof that what a user kept there is readable.
#[cfg(target_os = "android")]
pub fn readable(dir: &Path) -> bool {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => match entries.next() {
            Some(entry) => entry.is_ok(),
            None => true,
        },
        Err(_) => false,
    }
}

/// Whether what a phone says about how it encrypts its files means the
/// keys are ones only the storage hardware can unwrap.
pub fn hardware_wrapped(mode: &str) -> bool {
    mode.split(['+', ':']).any(|part| part == "wrappedkey_v0")
}

/// Read the name the phone recorded for a key it let in, to check against
/// the name the kernel works out now.
pub fn recorded_name(path: &Path) -> Result<[u8; NAME_BYTES]> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    match <[u8; NAME_BYTES]>::try_from(&raw[..]) {
        Ok(name) => Ok(name),
        Err(_) => bail!("{} holds {} bytes, and a key's name is {NAME_BYTES}", path.display(), raw.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phone_says_whether_the_hardware_holds_the_keys() {
        assert!(hardware_wrapped("aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0"));
        assert!(!hardware_wrapped("aes-256-xts:aes-256-cts:v2"));
        assert!(!hardware_wrapped("aes-256-xts:aes-256-cts:v2+wrappedkey_v1"));
    }

    #[test]
    fn a_name_is_read_back_only_at_its_own_length() {
        let dir = std::env::temp_dir().join(format!("skyward-fscrypt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("ref");
        std::fs::write(&good, [7u8; NAME_BYTES]).unwrap();
        assert_eq!(recorded_name(&good).unwrap(), [7u8; NAME_BYTES]);
        let short = dir.join("short");
        std::fs::write(&short, [7u8; 8]).unwrap();
        assert!(recorded_name(&short).is_err());
    }
}
