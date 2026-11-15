//! Keeping the recovery that is running in the phone's boot partition.
//!
//! What the bootloader starts is the kernel and the ramdisk in the boot
//! partition, and this phone has no recovery partition of its own: the
//! recovery is only a ramdisk. The kernel in the partition is the phone's
//! own, so the two go together as the image that was booted once carried
//! them, with the kernel left as the partition has it and the ramdisk taken
//! from the image. That is what a phone whose recovery has no partition of
//! its own has in place of writing a whole image over the one it starts
//! from, and what makes a recovery started with `fastboot boot` stay.

use anyhow::{bail, Context, Result};
use skyward_bootimg::BootImage;
use skyward_block::BY_NAME;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// What one embed left, for the caller to tell the screen.
pub struct Embedded {
    /// The boot partition written.
    pub partition: PathBuf,
    /// Where the partition as it was went, where it was kept.
    pub backup: Option<PathBuf>,
    /// How many bytes of ramdisk were written.
    pub ramdisk: usize,
}

/// Write the ramdisk of `image` into the boot partition `slot` starts from,
/// on the kernel that partition already holds, keeping the partition as it
/// was in `backup_dir`.
///
/// The header the partition carries is kept as well, so the command line the
/// bootloader hands the kernel, and the versions the image names, stay the
/// ones this phone already runs.
pub fn embed(image: &Path, slot: skyward_vab::Slot, backup_dir: Option<&Path>) -> Result<Embedded> {
    let partition = Path::new(BY_NAME).join(format!("boot{}", slot.suffix()));
    log(&format!("keeping {} in {}", image.display(), partition.display()));
    let was = fs::read(&partition).with_context(|| format!("read {}", partition.display()))?;
    let size = was.len();
    log(&format!("{} holds {size} bytes", partition.display()));
    let mut mine = BootImage::read(image)?;
    if mine.ramdisk.is_empty() {
        bail!("{} holds no ramdisk", image.display());
    }
    let mut boot = BootImage::parse(&was).with_context(|| format!("read what {} holds", partition.display()))?;
    boot.ramdisk = unpinned(image, std::mem::take(&mut mine.ramdisk))?;
    let ramdisk = boot.ramdisk.len();
    let bytes = boot.to_bytes().context("build the image")?;
    log(&format!("the image comes to {} bytes with {} of ramdisk", bytes.len(), ramdisk));
    if bytes.len() > size {
        bail!("the image comes to {} bytes, more than the {size} the partition holds", bytes.len());
    }
    let backup = match backup_dir {
        None => None,
        Some(dir) => {
            fs::create_dir_all(dir).with_context(|| format!("make {}", dir.display()))?;
            let path = dir.join(format!("boot{}-{}.img", slot.suffix(), stamp()));
            fs::write(&path, &was).with_context(|| format!("write {}", path.display()))?;
            Some(path)
        }
    };
    log(&format!(
        "kept the recovery in {}: {} bytes of ramdisk on the kernel it holds, {size} bytes of partition",
        partition.display(),
        ramdisk
    ));
    write(&partition, &bytes, size)?;
    Ok(Embedded { partition, backup, ramdisk })
}

/// The ramdisk `image` holds, with the one property that pins every start of
/// the phone to the recovery commented out.
///
/// An image booted once by hand has to say that it is the recovery, because
/// the bootloader marks every image it loads by hand as a normal boot. One
/// written into the boot partition must not: the bootloader answers whether a
/// start is a normal one or a recovery, and a ramdisk that answers for it
/// leaves the system unable to start at all.
///
/// The property is commented out where it stands, leaving the archive the
/// same length, so the ramdisk is unpacked, one byte changed and packed
/// again: rebuilding it entry by entry would cost the phone a minute.
fn unpinned(image: &Path, ramdisk: Vec<u8>) -> Result<Vec<u8>> {
    const SAID: &[u8] = b"ro.boot.force_normal_boot=0";
    let mut cpio = Vec::new();
    if ramdisk.starts_with(&[0x1f, 0x8b]) {
        flate2::read::GzDecoder::new(ramdisk.as_slice())
            .read_to_end(&mut cpio)
            .with_context(|| format!("unpack the ramdisk of {}", image.display()))?;
    } else {
        anyhow::bail!("{} holds a ramdisk that is not gzip", image.display());
    }
    let at = cpio.windows(SAID.len()).position(|w| w == SAID);
    let Some(at) = at else {
        log(&format!("{} already leaves the bootloader to say how a start is", image.display()));
        return Ok(ramdisk);
    };
    // A line that starts with `#` is one init does not read, and one byte
    // keeps every entry in the archive where it was.
    cpio[at] = b'#';
    let mut out = Vec::new();
    let mut enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::fast());
    enc.write_all(&cpio).context("pack the ramdisk again")?;
    enc.finish().context("finish the ramdisk")?;
    log(&format!("{} keeps {} bytes of ramdisk, one property left out", image.display(), out.len()));
    Ok(out)
}

/// Say what was done, for the log the phone keeps.
fn log(line: &str) {
    if skyward_sys::kmsg(line).is_err() {
        eprintln!("{line}");
    }
}

/// Put `bytes` at the start of `path` and leave nothing of what the partition
/// held after them: the footer a stock image ends in would still point at the
/// image that was there, and a bootloader that finds a footer pointing at
/// anything but a vbmeta image gives the whole slot up.
fn write(path: &Path, bytes: &[u8], size: usize) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    f.seek(SeekFrom::Start(0)).with_context(|| format!("rewind {}", path.display()))?;
    f.write_all(bytes).context("write the image")?;
    let zeros = [0u8; 64 * 1024];
    let mut at = bytes.len();
    while at < size {
        let n = (size - at).min(zeros.len());
        f.write_all(&zeros[..n]).context("clear what was after the image")?;
        at += n;
    }
    f.sync_all().with_context(|| format!("flush {}", path.display()))?;
    Ok(())
}

/// A time in a name that sorts: the seconds since the epoch.
fn stamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
