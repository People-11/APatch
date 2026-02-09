use crate::defs::{DISABLE_FILE_NAME, MODULE_DIR, SKIP_MOUNT_FILE_NAME};
use crate::magic_mount::NodeFileType::{Directory, RegularFile, Symlink, Whiteout};
use crate::restorecon::{ensure_syscon, lgetfilecon, lsetfilecon, restore_syscon};
use crate::utils::ensure_dir_exists;
use crate::utils::get_tmp_path;
use rustix::fs::{
    Gid, MetadataExt, Mode, Uid, chmod, chown,
};
use rustix::mount::{
    MountPropagationFlags, UnmountFlags, unmount
};
use crate::mount::{bind_mount, bind_mount_file, move_mount_path};
use rustix::mount::mount_change;
use anyhow::{Context, Result, bail};
use extattr::lgetxattr;
use rustix::path::Arg;
use std::cmp::PartialEq;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fs;
use std::ffi::{OsStr, OsString};
use std::fs::{DirEntry, FileType, create_dir, create_dir_all, read_link};
use std::os::unix::fs::{FileTypeExt, symlink};
use std::path::{Path, PathBuf};

const REPLACE_DIR_XATTR: &str = "trusted.overlay.opaque";

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
enum NodeFileType {
    RegularFile,
    Directory,
    Symlink,
    Whiteout,
}

impl NodeFileType {
    fn from_file_type(file_type: FileType) -> Option<Self> {
        if file_type.is_file() {
            Some(RegularFile)
        } else if file_type.is_dir() {
            Some(Directory)
        } else if file_type.is_symlink() {
            Some(Symlink)
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct Node {
    name: OsString,
    file_type: NodeFileType,
    children: BTreeMap<OsString, Node>,
    module_path: Option<PathBuf>,
    replace: bool,
    skip: bool,
}

impl Node {
    fn collect_module_files<T: AsRef<Path>>(&mut self, module_dir: T) -> Result<bool> {
        let dir = module_dir.as_ref();
        let mut has_file = false;
        for entry in dir.read_dir()?.flatten() {
            let name = entry.file_name();

            let node = match self.children.entry(name.clone()) {
                Entry::Occupied(o) => Some(o.into_mut()),
                Entry::Vacant(v) => Self::new_module(v.key().clone(), &entry).map(|it| v.insert(it)),
            };

            if let Some(node) = node {
                has_file |= if node.file_type == Directory {
                    node.collect_module_files(dir.join(&node.name))? || node.replace
                } else {
                    true
                }
            }
        }

        Ok(has_file)
    }

    fn new_root<T: AsRef<OsStr>>(name: T) -> Self {
        Node {
            name: name.as_ref().to_os_string(),
            file_type: Directory,
            children: Default::default(),
            module_path: None,
            replace: false,
            skip: false,
        }
    }

    fn new_module<T: Into<OsString>>(name: T, entry: &DirEntry) -> Option<Self> {
        if let Ok(metadata) = entry.metadata() {
            let path = entry.path();
            let file_type = if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
                Some(Whiteout)
            } else {
                NodeFileType::from_file_type(metadata.file_type())
            };
            if let Some(file_type) = file_type {
                let mut replace = false;
                if file_type == Directory {
                    if let Ok(v) = lgetxattr(&path, REPLACE_DIR_XATTR) {
                        if v.as_slice() == b"y" {
                            replace = true;
                        }
                    }
                }
                return Some(Node {
                    name: name.into(),
                    file_type,
                    children: Default::default(),
                    module_path: Some(path),
                    replace,
                    skip: false,
                });
            }
        }

        None
    }
}

fn collect_module_files() -> Result<Option<Node>> {
    let mut root = Node::new_root("");
    let module_root = Path::new(MODULE_DIR);
    let mut has_file = false;
    
    let partitions = [
        ("system", false),
        ("vendor", true),
        ("system_ext", true),
        ("product", true),
        ("odm", false),
        ("oem", false),
    ];

    for entry in module_root.read_dir()?.flatten() {
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let module_path = entry.path();
        if module_path.join(DISABLE_FILE_NAME).exists()
            || module_path.join(SKIP_MOUNT_FILE_NAME).exists()
        {
            continue;
        }

        log::debug!("collecting {} and restoring context", module_path.display());
        
        // Merge restorecon walk with module discovery
        if let Err(e) = restore_syscon(&module_path) {
            log::warn!("Failed to restorecon for {}: {}", module_path.display(), e);
        }

        // Use a single read_dir for faster partition checking
        if let Ok(dir) = module_path.read_dir() {
            for entry in dir.flatten() {
                let name = entry.file_name();
                if let Some((partition, _)) = partitions.iter().find(|(p, _)| OsStr::new(p) == name) {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let mod_part = module_path.join(partition);
                        let node = root.children.entry(name)
                            .or_insert_with(|| Node::new_root(partition));
                        has_file |= node.collect_module_files(&mod_part)?;
                    }
                }
            }
        }
    }

    if has_file {
        if let Some(mut system_node) = root.children.remove(OsStr::new("system")) {
            for (partition, require_symlink) in partitions.iter().skip(1) { // 略过索引 0 ("system")
                let path_of_root = Path::new("/").join(partition);
                let path_of_system = Path::new("/system").join(partition);
                
                if path_of_root.is_dir() && (!require_symlink || path_of_system.is_symlink()) {
                    let name = OsString::from(*partition);
                    if let Some(node) = system_node.children.remove(&name) {
                        match root.children.entry(name) {
                             Entry::Vacant(v) => {
                                 v.insert(node);
                             },
                             Entry::Occupied(mut o) => {
                                 let root_node = o.get_mut();
                                 if node.replace {
                                     root_node.replace = true;
                                 }
                                 // 使用内联 append 或直接 extend 的方式转移所有合并的集合来解除迭代的循环冗余开销
                                 root_node.children.extend(node.children);
                             }
                        }
                    }
                }
            }
            root.children.insert(OsString::from("system"), system_node);
        }
        Ok(Some(root))
    } else {
        Ok(None)
    }
}

fn clone_symlink<Src: AsRef<Path>, Dst: AsRef<Path>>(src: Src, dst: Dst) -> Result<()> {
    let src_symlink = read_link(src.as_ref())?;
    symlink(&src_symlink, dst.as_ref())?;
    lsetfilecon(dst.as_ref(), lgetfilecon(src.as_ref())?.as_str())?;
    log::debug!(
        "clone symlink {} -> {}({})",
        src.as_ref().display(),
        dst.as_ref().display(),
        src_symlink.display()
    );
    Ok(())
}

fn mount_mirror<P: AsRef<Path>, WP: AsRef<Path>>(
    path: P,
    work_dir_path: WP,
    entry: &DirEntry,
) -> Result<()> {
    let path = path.as_ref().join(entry.file_name());
    let work_dir_path = work_dir_path.as_ref().join(entry.file_name());
    let file_type = entry.file_type()?;

    if file_type.is_file() {
        log::debug!(
            "mount mirror file {} -> {}",
            path.display(),
            work_dir_path.display()
        );
        fs::File::create(&work_dir_path)?;
        bind_mount_file(&path, &work_dir_path)?;
    } else if file_type.is_dir() {
        log::debug!(
            "mount mirror dir {} -> {}",
            path.display(),
            work_dir_path.display()
        );
        create_dir(&work_dir_path)?;
        let metadata = entry.metadata()?;
        chmod(&work_dir_path, Mode::from_raw_mode(metadata.mode()))?;
        chown(
            &work_dir_path,
            Some(Uid::from_raw(metadata.uid())),
            Some(Gid::from_raw(metadata.gid())),
        )?;
        bind_mount(&path, &work_dir_path)?;
    } else if file_type.is_symlink() {
        log::debug!(
            "create mirror symlink {} -> {}",
            path.display(),
            work_dir_path.display()
        );
        clone_symlink(&path, &work_dir_path)?;
    }

    Ok(())
}

fn do_magic_mount<P: AsRef<Path>, WP: AsRef<Path>>(
    path: P,
    work_dir_path: WP,
    current: Node,
    has_tmpfs: bool,
) -> Result<()> {
    let mut current = current;
    let path = path.as_ref().join(&current.name);
    let work_dir_path = work_dir_path.as_ref().join(&current.name);
    match current.file_type {
        RegularFile => {
            let target_path = if has_tmpfs {
                fs::File::create(&work_dir_path)?;
                &work_dir_path
            } else {
                &path
            };
            if let Some(module_path) = &current.module_path {
                log::debug!(
                    "mount module file {} -> {}",
                    module_path.display(),
                    work_dir_path.display()
                );
                bind_mount_file(module_path, target_path)?;
            } else {
                bail!("cannot mount root file {}!", path.display());
            }
        }
        Symlink => {
            if let Some(module_path) = &current.module_path {
                log::debug!(
                    "create module symlink {} -> {}",
                    module_path.display(),
                    work_dir_path.display()
                );
                clone_symlink(module_path, &work_dir_path)?;
            } else {
                bail!("cannot mount root symlink {}!", path.display());
            }
        }
        Directory => {
            let mut create_tmpfs = !has_tmpfs && current.replace && current.module_path.is_some();
            if !has_tmpfs && !create_tmpfs {
                for it in &mut current.children {
                    let (name, node) = it;
                    let real_path = path.join(name);
                    let need = match node.file_type {
                        Symlink => true,
                        Whiteout => real_path.exists(),
                        _ => {
                            if let Ok(metadata) = real_path.symlink_metadata() {
                                let file_type = NodeFileType::from_file_type(metadata.file_type())
                                    .unwrap_or(Whiteout);
                                file_type != node.file_type || file_type == Symlink
                            } else {
                                true
                            }
                        }
                    };
                    if need {
                        if current.module_path.is_none() {
                            let name_lossy = name.to_string_lossy();
                            log::error!(
                                "cannot create tmpfs on {}, ignore: {name_lossy}",
                                path.display()
                            );
                            node.skip = true;
                            continue;
                        }
                        create_tmpfs = true;
                        break;
                    }
                }
            }

            let has_tmpfs = has_tmpfs || create_tmpfs;

            if has_tmpfs {
                log::debug!(
                    "creating tmpfs skeleton for {} at {}",
                    path.display(),
                    work_dir_path.display()
                );
                create_dir_all(&work_dir_path)?;
                let (metadata, path) = if path.exists() {
                    (path.metadata()?, &path)
                } else if let Some(module_path) = &current.module_path {
                    (module_path.metadata()?, module_path)
                } else {
                    bail!("cannot mount root dir {}!", path.display());
                };
                chmod(&work_dir_path, Mode::from_raw_mode(metadata.mode()))?;
                chown(
                    &work_dir_path,
                    Some(Uid::from_raw(metadata.uid())),
                    Some(Gid::from_raw(metadata.gid())),
                )?;
                lsetfilecon(&work_dir_path, lgetfilecon(path)?.as_str())?;
            }

            if create_tmpfs {
                log::debug!(
                    "creating tmpfs for {} at {}",
                    path.display(),
                    work_dir_path.display()
                );
                bind_mount(&work_dir_path, &work_dir_path).context("bind self")?;
            }

            if path.exists() && !current.replace {
                for entry in path.read_dir()?.flatten() {
                    let name = entry.file_name();
                    let result = if let Some(node) = current.children.remove(&name) {
                        if node.skip {
                            continue;
                        }
                        do_magic_mount(&path, &work_dir_path, node, has_tmpfs)
                            .with_context(|| format!("magic mount {}/{}", path.display(), name.to_string_lossy()))
                    } else if has_tmpfs {
                        mount_mirror(&path, &work_dir_path, &entry)
                            .with_context(|| format!("mount mirror {}/{}", path.display(), name.to_string_lossy()))
                    } else {
                        Ok(())
                    };

                    if let Err(e) = result {
                        if has_tmpfs {
                            return Err(e);
                        } else {
                            log::error!("mount child {}/{} failed: {}", path.display(), name.to_string_lossy(), e);
                        }
                    }
                }
            }

            if current.replace {
                if current.module_path.is_none() {
                    bail!(
                        "dir {} is declared as replaced but it is root!",
                        path.display()
                    );
                } else {
                    log::debug!("dir {} is replaced", path.display());
                }
            }

            for (name, node) in current.children.into_iter() {
                if node.skip {
                    continue;
                }
                if let Err(e) = do_magic_mount(&path, &work_dir_path, node, has_tmpfs)
                    .with_context(|| format!("magic mount {}/{}", path.display(), name.to_string_lossy()))
                {
                    if has_tmpfs {
                        return Err(e);
                    } else {
                        log::error!("mount child {}/{} failed: {}", path.display(), name.to_string_lossy(), e);
                    }
                }
            }

            if create_tmpfs {
                log::debug!(
                    "moving tmpfs {} -> {}",
                    work_dir_path.display(),
                    path.display()
                );
                move_mount_path(&work_dir_path, &path).context("move self")?;
                mount_change(&path, MountPropagationFlags::PRIVATE).context("make self private")?;
            }
        }
        Whiteout => {
            log::debug!("file {} is removed", path.display());
        }
    }

    Ok(())
}

pub fn magic_mount() -> Result<()> {
    match collect_module_files()? {
        Some(root) => {
            log::debug!("collected: {:#?}", root);
            let tmp_dir = PathBuf::from(get_tmp_path());
            ensure_dir_exists(&tmp_dir)?;
            crate::mount::mount_tmpfs(&tmp_dir).context("mount tmpfs")?;
            let result = do_magic_mount("/", &tmp_dir, root, false);
            if let Err(e) = unmount(&tmp_dir, UnmountFlags::DETACH) {
                log::error!("failed to unmount tmp {}", e);
            }
            fs::remove_dir(tmp_dir).ok();
            result
        }
        _ => {
            log::info!("no modules to mount, skipping!");
            Ok(())
        }
    }
}
