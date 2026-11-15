//! Packing the recovery that is running back into a ramdisk.
//!
//! The recovery starts from the ramdisk the boot partition holds, which init
//! unpacks into the root it runs on. Writing that recovery back into the boot
//! partition is therefore packing the root it runs on: the same recovery,
//! without an image to be started from first, which is what a phone whose
//! recovery has no partition of its own needs.
//!
//! What the recovery mounts under the root, and the folders it makes as it
//! runs, are left as empty folders: they are made again on the next start, and
//! what is in them belongs to whichever system is installed.
use anyhow::{Context, Result};
use skyward_bootimg::{Entry, Ramdisk};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The folders the recovery makes as it runs, at the top of the root: the
/// ones it mounts a partition or a filesystem of the kernel over.
const MADE: [&str; 7] = ["dev", "proc", "sys", "tmp", "mnt", "storage", "sdcard"];

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFSOCK: u32 = 0o140000;

/// The recovery that is running, packed as a ramdisk: the root it runs on,
/// without what it mounts under it.
pub fn live() -> Result<Vec<u8>> {
    let mounted = mount_points()?;
    let mut rd = Ramdisk { entries: Vec::new() };
    collect(Path::new("/"), "", &mounted, &mut rd)?;
    let archive = rd.archive().context("pack the root")?;
    let mut out = Vec::new();
    let mut enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::fast());
    enc.write_all(&archive).context("gzip the ramdisk")?;
    enc.finish().context("finish the ramdisk")?;
    Ok(out)
}

/// Where the kernel has something mounted, as paths under the root.
fn mount_points() -> Result<BTreeSet<String>> {
    let info = fs::read_to_string("/proc/self/mountinfo").context("read what is mounted")?;
    let mut at = BTreeSet::new();
    for line in info.lines() {
        // `36 35 98:0 / /mnt rw,noatime - ext4 /dev/block/sda1 rw`
        let Some(field) = line.split_whitespace().nth(4) else { continue };
        let where_ = field.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n");
        if where_ != "/" {
            at.insert(where_);
        }
    }
    Ok(at)
}

/// Add what is in `dir` (`under` being where it stands in the ramdisk) to the
/// archive, going into the folders that are part of the recovery.
fn collect(dir: &Path, under: &str, mounted: &BTreeSet<String>, rd: &mut Ramdisk) -> Result<()> {
    let Ok(reading) = fs::read_dir(dir) else { return Ok(()) };
    let mut found: Vec<fs::DirEntry> = reading.filter_map(Result::ok).collect();
    found.sort_by_key(fs::DirEntry::file_name);
    for entry in found {
        let name = entry.file_name().to_string_lossy().into_owned();
        let shown = if under.is_empty() { name.clone() } else { format!("{under}/{name}") };
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        let mode = meta.mode();
        let kind = mode & S_IFMT;
        if kind == S_IFDIR {
            // A folder the recovery mounts over, or one it makes as it runs,
            // is written back empty: init makes it again.
            let mounted_here = mounted.contains(&format!("/{shown}")) || (under.is_empty() && MADE.contains(&name.as_str()));
            rd.entries.push(entry_of(&shown, mode, &meta, Vec::new()));
            if !mounted_here {
                collect(&path, &shown, mounted, rd)?;
            }
        } else if kind == S_IFSOCK {
            continue;
        } else if kind == S_IFLNK {
            let target = fs::read_link(&path).with_context(|| format!("read the link {shown}"))?;
            rd.entries.push(entry_of(&shown, mode, &meta, target.to_string_lossy().as_bytes().to_vec()));
        } else {
            let data = match fs::read(&path) {
                Ok(data) => data,
                Err(_) => continue,
            };
            rd.entries.push(entry_of(&shown, mode, &meta, data));
        }
    }
    Ok(())
}

fn entry_of(name: &str, mode: u32, meta: &fs::Metadata, data: Vec<u8>) -> Entry {
    let nlink = if mode & S_IFMT == S_IFDIR { 2 } else { 1 };
    let rdev = meta.rdev();
    let (major, minor) = (major_of(rdev), minor_of(rdev));
    Entry {
        name: name.to_string(),
        mode,
        uid: meta.uid(),
        gid: meta.gid(),
        mtime: u32::try_from(meta.mtime()).unwrap_or(0),
        nlink,
        dev: (0, 0),
        rdev: (major, minor),
        data,
    }
}

fn major_of(rdev: u64) -> u32 {
    (((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)) as u32
}

fn minor_of(rdev: u64) -> u32 {
    ((rdev & 0xff) | ((rdev >> 12) & !0xff)) as u32
}
