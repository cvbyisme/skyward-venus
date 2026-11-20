//! What the phone says about its own key services, read from the files it
//! keeps them in rather than copied from another phone's build.
//!
//! A device configuration names the programs that hold the keys, and one
//! written from a newer phone's build names programs this phone has never
//! had: the recovery then says "is missing; skipped" about the key service
//! and opens nothing. The files here say what is really here -- the init
//! files name every program, its path and the account it runs as, and the
//! manifests name every interface and which instance of it -- so what the
//! configuration asks for that is not here is taken from them, and what it
//! names that this phone does not run is said plainly instead.
use anyhow::{Context, Result};
use skyward_config::Service;
use std::collections::BTreeMap;
use std::path::Path;

/// The directories a phone keeps its init files in.
const INIT_DIRS: [&str; 4] = ["/vendor/etc/init", "/odm/etc/init", "/vendor/bin/hw", "/odm/bin/hw"];

/// Where a phone describes the interfaces it serves, and with which
/// transport.
const MANIFESTS: [&str; 6] = [
    "/vendor/etc/vintf/manifest.xml",
    "/vendor/etc/vintf/manifest_lahaina.xml",
    "/vendor/etc/vintf/manifest_shima.xml",
    "/vendor/etc/vintf/manifest_yupik.xml",
    "/odm/etc/vintf/manifest.xml",
    "/vendor/manifest.xml",
];

/// The parts of a program's init file this reads: what it is called, where
/// it is, and who it runs as.
#[derive(Debug, Clone, Default)]
struct Named {
    path: String,
    args: Vec<String>,
    user: Option<String>,
    groups: Vec<String>,
}

/// One interface the phone serves: what it is called, which instance, and
/// which directory of services it registers with.
#[derive(Debug, Clone)]
struct Described {
    /// The interface and its instance, as the directory is asked for it.
    name: String,
    /// Whether it is served over the hardware services' directory, which is
    /// the older kind, rather than the ordinary one.
    hardware: bool,
}

/// Add to `services` what the phone says it runs of the key services and
/// the configuration does not name. Nothing is added twice: a program with
/// the same path, or one that would register the same name, is left as the
/// configuration has it.
pub fn add_missing(services: &mut Vec<Service>) -> Result<Vec<String>> {
    let mut said = Vec::new();
    let programs = programs()?;
    for described in described()? {
        let Some(kind) = kind_of(&described.name) else { continue };
        if services.iter().any(|s| s.ready_service.as_deref() == Some(&described.name) || s.ready_hardware_service.as_deref() == Some(&described.name)) {
            continue;
        }
        let found = programs.iter().find(|pair| pair.0.contains(kind) && Path::new(&pair.1.path).is_file());
        let Some(pair) = found else {
            said.push(format!("{} is described by the phone and no program of this phone serves it", described.name));
            continue;
        };
        let program = pair.1;
        let service = Service {
            path: program.path.clone(),
            args: program.args.clone(),
            libraries: Vec::new(),
            oneshot: false,
            ready_property: None,
            ready_service: match described.hardware {
                true => None,
                false => Some(described.name.clone()),
            },
            registers: Vec::new(),
            description: None,
            ready_hardware_service: match described.hardware {
                true => Some(described.name.clone()),
                false => None,
            },
            when: None,
            user: program.user.clone(),
            groups: program.groups.clone(),
            capabilities: Vec::new(),
        };
        said.push(format!("{} is served here by {}, which the phone's own init names", described.name, program.path));
        // The key service is needed by everything that holds a key, and it
        // has to be up before the credential service that guards one: it
        // goes where the configuration's own key service is, or after all
        // of them where there is none.
        let at = services
            .iter()
            .position(|s| kind_of(&s.path).is_some_and(|k| k == kind || k == "keymaster"))
            .unwrap_or(services.len());
        services.insert(at, service);
    }
    Ok(said)
}

/// Which of the key services a name belongs to, where it is one of them:
/// this is the only part of the phone's own naming this program relies on,
/// because the keys it opens are held by exactly these.
fn kind_of(name: &str) -> Option<&'static str> {
    ["keymaster", "keymint", "gatekeeper"].into_iter().find(|k| name.contains(k))
}

/// Every program the phone's init files name, by the name it gives them.
fn programs() -> Result<BTreeMap<String, Named>> {
    let mut out = BTreeMap::new();
    for dir in INIT_DIRS {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "rc") {
                continue;
            }
            let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            for (name, program) in blocks(&text) {
                out.insert(name, program);
            }
        }
    }
    Ok(out)
}

/// The `service` blocks of an init file: its name, then its path and what
/// follows on that line, then the account it runs as and its groups.
fn blocks(text: &str) -> Vec<(String, Named)> {
    let mut out = Vec::new();
    let mut current: Option<(String, Named)> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // A line at the margin starts something new; anything indented
        // belongs to what was started.
        let at_margin = !raw.starts_with([' ', '\t']);
        if at_margin && (line.starts_with("service ") || line.starts_with("on ") || line.starts_with("import ") || line.starts_with("subsys")) {
            if let Some(done) = current.take() {
                out.push(done);
            }
            if let Some(rest) = line.strip_prefix("service ") {
                let mut words = rest.split_whitespace();
                let name = words.next().unwrap_or_default().to_string();
                let path = words.next().unwrap_or_default().to_string();
                let args: Vec<String> = words.map(str::to_string).collect();
                if !path.is_empty() {
                    current = Some((name, Named { path, args, ..Named::default() }));
                }
            }
            continue;
        }
        let Some((_, program)) = current.as_mut() else { continue };
        if let Some(rest) = line.strip_prefix("user ") {
            program.user = rest.split_whitespace().next().map(str::to_string);
        }
        if let Some(rest) = line.strip_prefix("group ") {
            program.groups = rest.split_whitespace().map(str::to_string).collect();
        }
    }
    if let Some(done) = current {
        out.push(done);
    }
    out
}

/// The key services the phone's manifests describe.
fn described() -> Result<Vec<Described>> {
    let mut out = Vec::new();
    for file in MANIFESTS {
        let Ok(text) = std::fs::read_to_string(file) else { continue };
        out.extend(manifest(&text));
    }
    Ok(out)
}

/// The interfaces of one manifest: a `hal` says what it is called and how
/// it is reached, and each of its interfaces says which instance is served.
fn manifest(text: &str) -> Vec<Described> {
    let mut out = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut format = String::from("hidl");
    let mut inside = false;
    let mut interface = String::new();
    let mut instance = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("<hal") {
            inside = true;
            name.clear();
            version.clear();
            format = if line.contains("aidl") { "aidl".into() } else { "hidl".into() };
            continue;
        }
        if !inside {
            continue;
        }
        if let Some(v) = value(line, "<name>") {
            // A name inside an interface belongs to the interface.
            name = v;
        }
        if let Some(v) = value(line, "<version>") {
            version = v;
        }
        if let Some(v) = value(line, "<interface>") {
            interface = v;
        }
        if let Some(v) = value(line, "<instance>") {
            instance = v;
        }
        if line.starts_with("</interface>") {
            if !name.is_empty() && !interface.is_empty() {
                let full = match format.as_str() {
                    "aidl" => format!("{}.{interface}/{}", name, if instance.is_empty() { "default" } else { &instance }),
                    _ => format!("{name}@{version}::{interface}/{}", if instance.is_empty() { "default" } else { &instance }),
                };
                out.push(Described { name: full, hardware: format != "aidl" });
            }
            interface.clear();
            instance.clear();
        }
        if line.starts_with("</hal>") {
            inside = false;
        }
    }
    out
}

/// What a line of a manifest says inside one of its tags.
fn value(line: &str, tag: &str) -> Option<String> {
    let rest = line.strip_prefix(tag)?;
    let end = rest.find('<')?;
    Some(rest[..end].trim().to_string())
}
