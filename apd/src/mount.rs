//! Bind-mount primitives used by magic mount.
//!
//! Each one prefers the new mount API (`open_tree` + `move_mount`) and falls
//! back to the legacy `mount(2)` syscall, since `open_tree` only exists from
//! kernel 5.2 and APatch still supports 4.x.

#[cfg(any(target_os = "linux", target_os = "android"))]
use anyhow::Context;
use anyhow::{Ok, Result};
#[cfg(any(target_os = "linux", target_os = "android"))]
use log::debug;
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::{fd::AsFd, fs::CWD, mount::*};
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_mount(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    debug!(
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
            )
            .with_context(|| format!("move_mount to {}", to.as_ref().display()))?;
        }
        _ => {
            mount(
                from.as_ref(),
                to.as_ref(),
                "",
                MountFlags::BIND | MountFlags::REC,
                rustix::cstr!(""),
            )
            .with_context(|| format!("bind mount to {}", to.as_ref().display()))?;
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn bind_mount(_from: impl AsRef<Path>, _to: impl AsRef<Path>) -> Result<()> {
    unimplemented!()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_mount_file(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    debug!(
        "bind mount file {} -> {}",
        from.as_ref().display(),
        to.as_ref().display()
    );
    match open_tree(
        CWD,
        from.as_ref(),
        OpenTreeFlags::OPEN_TREE_CLOEXEC | OpenTreeFlags::OPEN_TREE_CLONE,
    ) {
        Result::Ok(tree) => {
            rustix::mount::move_mount(
                tree.as_fd(),
                "",
                CWD,
                to.as_ref(),
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )
            .with_context(|| format!("move_mount file to {}", to.as_ref().display()))?;
        }
        _ => {
            mount(
                from.as_ref(),
                to.as_ref(),
                "",
                MountFlags::BIND,
                rustix::cstr!(""),
            )
            .with_context(|| format!("bind mount file to {}", to.as_ref().display()))?;
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn bind_mount_file(_from: impl AsRef<Path>, _to: impl AsRef<Path>) -> Result<()> {
    unimplemented!()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn move_mount_path(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    if let Err(e) = rustix::mount::move_mount(
        CWD,
        from.as_ref(),
        CWD,
        to.as_ref(),
        MoveMountFlags::empty(),
    ) {
        debug!("move_mount failed: {e:?}, falling back to legacy mount");
        mount(
            from.as_ref(),
            to.as_ref(),
            "",
            MountFlags::from_bits_retain(0x2000), // MS_MOVE
            rustix::cstr!(""),
        )
        .with_context(|| format!("move mount to {}", to.as_ref().display()))?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn move_mount_path(_from: impl AsRef<Path>, _to: impl AsRef<Path>) -> Result<()> {
    unimplemented!()
}

/// Private tmpfs that magic mount assembles the merged tree in before moving
/// it over the real directory.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn mount_tmpfs(dest: impl AsRef<Path>) -> Result<()> {
    debug!("mount tmpfs on {}", dest.as_ref().display());
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
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn mount_tmpfs(_dest: impl AsRef<Path>) -> Result<()> {
    unimplemented!()
}
