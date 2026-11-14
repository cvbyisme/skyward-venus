use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub mod modprobe;

/// Where a module source's files are in the recovery: the vendor_boot
/// ramdisk's modules under /lib/modules, the vendor_dlkm and vendor
/// partitions where they are mounted, and the kernel's own modules in
/// system_dlkm, which it also keeps in one folder.
pub fn source_dir(source: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(match source {
        "vendor_boot" => "/lib/modules",
        "vendor_dlkm" => "/vendor_dlkm/lib/modules",
        "vendor" => "/vendor/lib/modules",
        "system_dlkm" => "/system_dlkm/flatten/lib/modules",
        _ => bail!("unknown module source {source:?}"),
    }))
}

/// Load `names` (module names without `.ko`) with their dependencies. Each
/// comes from the first of `dirs` that holds it, and its dependencies from the
/// tables of all of `dirs`, read as Android's modprobe reads them when it is
/// told one folder after another; a module the kernel already has counts as
/// loaded. Returns the files loaded, dependencies first.
///
/// The tables are read together because a phone may keep the chain a module
/// needs in a folder of its own: venus keeps one table for the modules its
/// recovery needs and a second under `5.4-gki` for the rest, and its own init
/// runs modprobe over both, so the whole of the wireless driver's chain is
/// written down only in the second.
pub fn load(dirs: &[PathBuf], names: &[String]) -> Result<Vec<PathBuf>> {
    let graph = merge_dep(dirs)?;
    let mut loaded = Vec::new();
    for name in names {
        let file = format!("{name}.ko");
        if !dirs.iter().any(|d| d.join(&file).is_file()) {
            bail!("{file} is in none of {dirs:?}");
        }
        for m in graph.load_order(std::slice::from_ref(&file)) {
            let path = graph
                .resolve_path(&m)
                .ok_or_else(|| anyhow!("{m} is in none of {dirs:?}"))?;
            insmod(&path, "")?;
            loaded.push(path);
        }
    }
    Ok(loaded)
}

/// A `modules.dep` graph: each module file mapped to the module files it
/// depends on. Keys and values are reduced to bare file names so the graph is
/// independent of where the modules were sourced from (GKI devices keep them
/// in several places: vendor_boot ramdisk, vendor_dlkm, vendor).
#[derive(Debug, Default)]
pub struct ModuleGraph {
    /// The folders searched for a module, in the order given.
    pub dirs: Vec<PathBuf>,
    pub deps: BTreeMap<String, Vec<String>>,
    /// Where each module a table names lies, as that table gave it.
    pub files: BTreeMap<String, PathBuf>,
}
/// The graph of one folder's tables.
pub fn parse_dep(base: impl AsRef<Path>) -> Result<ModuleGraph> {
    let base = base.as_ref().to_path_buf();
    merge_dep(std::slice::from_ref(&base))
}
/// The graph of every folder's tables together: the first table that names a
/// module is the one that says what it depends on, and a folder that keeps a
/// table of its own beside the modules, as one with two builds of them does,
/// is read after the folder it lies in.
pub fn merge_dep(dirs: &[PathBuf]) -> Result<ModuleGraph> {
    let mut graph = ModuleGraph { dirs: dirs.to_vec(), ..ModuleGraph::default() };
    let mut found = false;
    for dir in dirs {
        for root in table_roots(dir) {
            found |= read_table(&mut graph, &root)?;
        }
    }
    if !found {
        bail!("no modules.dep in any of {dirs:?}");
    }
    Ok(graph)
}
/// The folders whose table is read for `dir`: the folder itself, then the
/// folders inside it that keep a table of their own.
fn table_roots(dir: &Path) -> Vec<PathBuf> {
    let mut roots = vec![dir.to_path_buf()];
    if let Ok(entries) = fs::read_dir(dir) {
        let mut inner: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.join("modules.dep").is_file())
            .collect();
        inner.sort();
        roots.extend(inner);
    }
    roots
}
/// Read one folder's table into the graph, leaving alone what a table read
/// before it already named. Whether the folder had a table at all.
fn read_table(graph: &mut ModuleGraph, root: &Path) -> Result<bool> {
    let dep_path = root.join("modules.dep");
    let text = match fs::read_to_string(&dep_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("read {}", dep_path.display())),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once(':') else {
            continue;
        };
        let lhs = lhs.trim();
        let name = basename(lhs);
        if graph.deps.contains_key(&name) {
            continue;
        }
        let ds = rhs.split_whitespace().map(basename).collect();
        let mut file = root.join(lhs);
        if !file.is_file() {
            file = find_file(root, &name).unwrap_or(file);
        }
        graph.deps.insert(name.clone(), ds);
        graph.files.insert(name, file);
    }
    Ok(true)
}

fn basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string())
}

impl ModuleGraph {
    /// Topologically ordered load list. With an empty `requested`, every module
    /// in the graph is scheduled; otherwise only the requested modules and
    /// their transitive dependencies, dependencies first.
    pub fn load_order(&self, requested: &[String]) -> Vec<String> {
        let mut order = Vec::new();
        let mut seen = BTreeSet::new();
        let list: Vec<String> = if requested.is_empty() {
            self.deps.keys().cloned().collect()
        } else {
            requested.to_vec()
        };
        for m in list {
            self.visit(&m, &mut seen, &mut order);
        }
        order
    }

    fn visit(&self, m: &str, seen: &mut BTreeSet<String>, order: &mut Vec<String>) {
        if !seen.insert(m.to_string()) {
            return;
        }
        if let Some(ds) = self.deps.get(m) {
            for d in ds {
                self.visit(d, seen, order);
            }
        }
        order.push(m.to_string());
    }

    pub fn resolve_path(&self, module: &str) -> Option<PathBuf> {
        if let Some(file) = self.files.get(module) {
            if file.is_file() {
                return Some(file.clone());
            }
        }
        for dir in &self.dirs {
            let direct = dir.join(module);
            if direct.exists() {
                return Some(direct);
            }
            if let Some(found) = find_file(dir, module) {
                return Some(found);
            }
        }
        None
    }
}

fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(f) = find_file(&p, name) {
                return Some(f);
            }
        } else if p.file_name().map(|s| s == name).unwrap_or(false) {
            return Some(p);
        }
    }
    None
}

/// Hand the open module `file` to the kernel with the settings `params`.
#[cfg(target_os = "android")]
fn finit_module(file: &fs::File, params: &str) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let params = std::ffi::CString::new(params).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let rc = unsafe { libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0 as libc::c_int) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn finit_module(_file: &fs::File, _params: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "modules are loaded only on the phone"))
}

pub fn insmod(path: impl AsRef<Path>, params: &str) -> Result<()> {
    let path = path.as_ref();
    let f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    match finit_module(&f, params) {
        Ok(()) => Ok(()),
        // Already loaded is success for our purposes.
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("finit_module {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_dependencies_first() {
        let mut deps = BTreeMap::new();
        deps.insert("a.ko".to_string(), vec!["b.ko".to_string()]);
        deps.insert("b.ko".to_string(), vec!["c.ko".to_string()]);
        deps.insert("c.ko".to_string(), vec![]);
        let g = ModuleGraph { deps, ..ModuleGraph::default() };
        let order = g.load_order(&["a.ko".to_string()]);
        assert_eq!(order, vec!["c.ko", "b.ko", "a.ko"]);
    }

    #[test]
    fn a_module_takes_the_table_that_names_it_and_not_one_that_does_not() {
        let root = std::env::temp_dir().join(format!("skyward-dep-{}", std::process::id()));
        let (first, second) = (root.join("plain"), root.join("plain/5.4-gki"));
        fs::create_dir_all(&second).expect("make the folders");
        fs::write(first.join("modules.dep"), "/vendor/lib/modules/a.ko: /vendor/lib/modules/b.ko\n").expect("write the first table");
        fs::write(second.join("modules.dep"), "/vendor/lib/modules/a.ko: /vendor/lib/modules/c.ko\n/vendor/lib/modules/z.ko: /vendor/lib/modules/c.ko\n").expect("write the second table");
        for name in ["a.ko", "b.ko", "c.ko", "z.ko"] {
            fs::write(first.join(name), b"").expect("write a module");
        }
        let dirs = vec![first.clone()];
        let g = merge_dep(&dirs).expect("read the tables");
        assert_eq!(g.deps.get("a.ko"), Some(&vec!["b.ko".to_string()]), "the folder's own table comes first");
        assert_eq!(g.deps.get("z.ko"), Some(&vec!["c.ko".to_string()]), "a chain only the inner table writes down is still found");
        assert_eq!(g.load_order(&["z.ko".to_string()]), vec!["c.ko".to_string(), "z.ko".to_string()]);
        fs::remove_dir_all(&root).ok();
    }
    #[test]
    fn strips_paths_to_basenames() {
        assert_eq!(basename("kernel/drivers/foo/bar.ko"), "bar.ko");
    }
}
