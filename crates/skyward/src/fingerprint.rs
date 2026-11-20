//! What the recovery says about the phone it is running on, before it tries
//! to open anything: the filesystems and how they are encrypted, the keys
//! that lead to each layer, the services that hold those keys, and the
//! generation of each of those against the generation of the rest.
//!
//! A phone whose data partition does not open is diagnosed from this alone,
//! so every field here is written down as it is found: a layer that fails
//! is reported with the number the failure came with, never with a word
//! that stands for all failures alike.
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

/// The files the phone keeps its own table of filesystems in, in the order
/// a phone names them.
const FSTABS: [&str; 6] = [
    "/vendor/etc/fstab.qcom",
    "/odm/etc/fstab.qcom",
    "/vendor/etc/fstab.default",
    "/odm/etc/fstab.default",
    "/vendor/etc/fstab.emmc",
    "/odm/etc/fstab.emmc",
];

/// The properties that say which build of Android and of the vendor code
/// this phone is, and how its bootloader was left.
const PROPS: [&str; 9] = [
    "ro.build.version.release",
    "ro.build.version.security_patch",
    "ro.vendor.build.security_patch",
    "ro.vndk.version",
    "ro.build.fingerprint",
    "ro.boot.verifiedbootstate",
    "ro.boot.slot_suffix",
    "ro.crypto.state",
    "ro.crypto.type",
];

/// The filesystems that hold the keys, and what each needs to be there.
const DIRECTORIES: [(&str, &str); 4] = [
    ("/data/unencrypted", "the key for the files nobody owns"),
    ("/data/unencrypted/key", "that key itself"),
    ("/data/system_de/0", "the owner's blobs for their secret"),
    ("/data/user/0", "the owner's own files"),
];

/// The nodes the key services read and write, and what each must be.
const NODES: [&str; 8] = [
    "/dev/qseecom",
    "/dev/spcom",
    "/dev/smcinvoke",
    "/dev/hwbinder",
    "/dev/vndbinder",
    "/dev/ion",
    "/dev/dma_heap",
    "/dev/block/by-name/metadata",
];

/// Where a phone describes the services it has: the newer kind in a
/// manifest of its own, and both kinds in the init files that start them.
const MANIFESTS: [&str; 5] = [
    "/vendor/etc/vintf/manifest.xml",
    "/vendor/etc/vintf/manifest_lahaina.xml",
    "/odm/etc/vintf/manifest.xml",
    "/vendor/manifest.xml",
    "/odm/manifest.xml",
];

/// Say where the phone's key services are and what each of them has to
/// reach. A service that is missing, an instance that is described but not
/// registered, and a node that is there but belongs to the wrong account
/// all look like "the key will not open" from above, and only this says
/// which one it was.
pub fn log(props: &HashMap<String, String>) -> Result<()> {
    say("fingerprint: what the phone is");
    for name in PROPS {
        let said = props.get(name).map_or("(unset)", String::as_str);
        say(&format!("fingerprint: prop {name} = {said}"));
    }
    for (file, line) in fstab_lines() {
        say(&format!("fingerprint: {file} says {line}"));
        for (name, value) in fields(&line) {
            say(&format!("fingerprint:   {name} = {value}"));
        }
    }
    for (dir, what) in DIRECTORIES {
        say(&format!("fingerprint: {} holds {what}: {}", dir, describe(Path::new(dir))));
    }
    for node in NODES {
        say(&format!("fingerprint: {node} {}", node_of(node)));
    }
    for file in MANIFESTS {
        for described in manifest(file) {
            say(&format!("fingerprint: {file} describes {described}"));
        }
    }
    say(&format!("fingerprint: qseecomd {}", if running("/vendor/bin/qseecomd") { "is running" } else { "is not running" }));
    for (what, at) in [("the firmware", "/vendor/firmware_mnt"), ("the settings", "/mnt/vendor/persist"), ("the metadata", "/metadata")] {
        say(&format!("fingerprint: {what} at {at} {}", if mounted(at) { "is mounted" } else { "is not mounted" }));
    }
    say(&format!("fingerprint: the kernel is {}", kernel()));
    say(&format!("fingerprint: {} modules are loaded", modules().len()));
    for (name, size, used) in modules().into_iter().take(64) {
        say(&format!("fingerprint:   module {name} {size} bytes, {used}"));
    }
    if let Some((version, patch)) = boot_header() {
        say(&format!("fingerprint: the boot header says OS {version}, patch level {patch}"));
    }
    Ok(())
}

/// Write a line where the exported log and the kernel log both keep it.
fn say(line: &str) {
    let _ = skyward_sys::kmsg(line);
}

/// The line each of the phone's own tables has about the two filesystems
/// that carry its encryption, and the file it is in.
fn fstab_lines() -> Vec<(String, String)> {
    for file in FSTABS {
        let Ok(text) = std::fs::read_to_string(file) else { continue };
        let named: Vec<(String, String)> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .filter(|l| l.split_once(' ').is_some_and(|(_, rest)| rest.trim_start().starts_with("/data") || rest.trim_start().starts_with("/metadata")))
            .map(|l| (file.to_string(), l.to_string()))
            .collect();
        if !named.is_empty() {
            return named;
        }
    }
    Vec::new()
}

/// What a line of the table says beyond the mount itself, as the words
/// that decide how the filesystem is encrypted.
fn fields(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let columns: Vec<&str> = line.split_whitespace().collect();
    let (Some(device), Some(point), Some(filesystem), Some(options)) = (columns.first(), columns.get(1), columns.get(2), columns.get(3)) else {
        return out;
    };
    out.push(("device".into(), device.to_string()));
    out.push(("mount point".into(), point.to_string()));
    out.push(("filesystem".into(), filesystem.to_string()));
    out.push(("options".into(), options.to_string()));
    for extra in columns.get(4).map(|e| e.split(',')).into_iter().flatten() {
        let wanted = ["fileencryption", "metadata_encryption", "keydirectory", "quota", "checkpoint", "latemount", "first_stage_mount", "formattable", "wait", "check"];
        if wanted.contains(&extra) {
            out.push(("flag".into(), extra.to_string()));
        }
    }
    out
}

/// What the kernel says about how a directory is encrypted, or why it does
/// not say.
fn describe(dir: &Path) -> String {
    match skyward_crypto::fscrypt::policy(dir) {
        Ok(None) => "is not encrypted".to_string(),
        Ok(Some(how)) => format!(
            "is encrypted under a policy of version {} with contents {}, names {}, flags {:#x}, key {}",
            how.version,
            how.contents_mode,
            how.filenames_mode,
            how.flags,
            how.key.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
        Err(e) => format!("could not be asked: {e:#}"),
    }
}

/// What is at a node: whether it is there, and who it belongs to.
fn node_of(node: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(node) {
        Ok(m) => format!("is there, owned by {}:{} in mode {:o}", m.uid(), m.gid(), m.mode()),
        Err(e) => format!("is not there: {e}"),
    }
}

/// The service names a manifest describes: each is named by its interface
/// and its instance, which is what the directory now serves.
fn manifest(file: &str) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(file) else { return Vec::new() };
    let mut out = Vec::new();
    let mut inside = false;
    let mut name = String::new();
    let mut instance = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("<hal ") {
            (inside, name, instance) = (true, String::new(), String::new());
            continue;
        }
        if !inside {
            continue;
        }
        let value = |tag: &str| line.strip_prefix(tag).and_then(|rest| rest.split('<').next()).map(|v| v.trim().to_string());
        if let Some(n) = value("<name>") {
            name = n;
        }
        if let Some(i) = value("<instance>") {
            instance = i;
        }
        if line.starts_with("</hal>") {
            inside = false;
            if !name.is_empty() {
                out.push(if instance.is_empty() { name.clone() } else { format!("{name}/{instance}") });
            }
        }
    }
    out
}

/// Whether a process is running `path`.
fn running(path: &str) -> bool {
    std::fs::read_dir("/proc").into_iter().flatten().flatten().any(|entry| {
        std::fs::read_link(entry.path().join("exe")).is_ok_and(|exe| exe == Path::new(path))
    })
}

/// Whether `at` is a mount point, read from the table the kernel keeps.
fn mounted(at: &str) -> bool {
    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else { return false };
    mountinfo.lines().any(|line| line.split(' ').nth(4) == Some(at))
}

/// Which kernel is running, as it names itself.
fn kernel() -> String {
    std::fs::read_to_string("/proc/version").map_or_else(|e| format!("unreadable: {e}"), |v| v.trim().to_string())
}

/// The modules loaded and what each says it was built for: a module built
/// for another kernel is the one failure that makes every driver after it
/// look broken.
fn modules() -> Vec<(String, u64, String)> {
    let Ok(text) = std::fs::read_to_string("/proc/modules") else { return Vec::new() };
    text.lines()
        .filter_map(|line| {
            let mut columns = line.split_whitespace();
            let name = columns.next()?.to_string();
            let size = columns.next()?.parse().ok()?;
            let used = columns.next()?.to_string();
            Some((name, size, used))
        })
        .collect()
}

/// What the boot image the phone started from says about its own
/// generation, which the system's and the vendor's patch levels are
/// checked against when a key is unwrapped.
fn boot_header() -> Option<(String, String)> {
    let slot = skyward_sys::prop("ro.boot.slot_suffix").unwrap_or_default();
    let path = Path::new(skyward_block::BY_NAME).join(format!("boot{slot}"));
    let header = skyward_bootimg::BootImage::header(&path).ok()?;
    let os = header.os_version;
    let version = format!("{}.{}.{}", os >> 25, (os >> 18) & 0x7f, (os >> 11) & 0x7f);
    let patch = format!("{}-{:02}", 2000 + ((os >> 4) & 0x7f), os & 0xf);
    Some((version, patch))
}
