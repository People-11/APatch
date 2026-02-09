#[cfg(any(target_os = "linux", target_os = "android"))]
use anyhow::Context;
use anyhow::{Ok, Result};
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unused_imports)]
use retry::delay::NoDelay;
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::{fd::AsFd, fs::CWD, mount::*};
use std::fs::create_dir;
#[cfg(any(target_os = "linux", target_os = "android"))]
use log::info;
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_mount(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    info!(
        "bind mount {} -> {}",
        from.as_ref().display(),
        to.as_ref().display()
    );
    match open_tree(
        CWD,
        from.as_ref(),
        OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::AT_RECURSIVE,
    ) {
        Result::Ok(tree) => {
            rustix::mount::move_mount(
                tree.as_fd(),
                "",
                CWD,
                to.as_ref(),
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )?;
        }
        _ => {
            mount(
                from.as_ref(),
                to.as_ref(),
                "",
                MountFlags::BIND | MountFlags::REC,
                rustix::cstr!(""),
            )?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn move_mount_path(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
     rustix::mount::move_mount(
         CWD,
         from.as_ref(),
         CWD,
         to.as_ref(),
         MoveMountFlags::empty(),
     )?;
     Ok(())
}

#[allow(dead_code)]
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn mount_devpts(dest: impl AsRef<Path>) -> Result<()> {
    create_dir(dest.as_ref())?;
    mount(
        "APatch",
        dest.as_ref(),
        "devpts",
        MountFlags::empty(),
        rustix::cstr!("newinstance"),
    )?;
    mount_change(dest.as_ref(), MountPropagationFlags::PRIVATE).context("make devpts private")?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn mount_devpts(_dest: impl AsRef<Path>) -> Result<()> {
    unimplemented!()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn mount_tmpfs(dest: impl AsRef<Path>) -> Result<()> {
    info!("mount tmpfs on {}", dest.as_ref().display());
    match fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC) {
        Result::Ok(fs) => {
            let fs = fs.as_fd();
            fsconfig_set_string(fs, "source", "APatch")?;
            fsconfig_create(fs)?;
            let mount = fsmount(fs, FsMountFlags::FSMOUNT_CLOEXEC, MountAttrFlags::empty())?;
            move_mount(
                mount.as_fd(),
                "",
                CWD,
                dest.as_ref(),
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )?;
        }
        _ => {
            mount(
                "APatch",
                dest.as_ref(),
                "tmpfs",
                MountFlags::empty(),
                rustix::cstr!(""),
            )?;
        }
    }
    mount_change(dest.as_ref(), MountPropagationFlags::PRIVATE).context("make tmpfs private")?;
    // Note: detailed PTS mounting removed to match legacy magic_mount behavior
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn mount_tmpfs(_dest: impl AsRef<Path>) -> Result<()> {
    unimplemented!()
}
