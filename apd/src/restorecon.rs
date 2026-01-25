use std::path::Path;

use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "android"))]
use anyhow::{Context, Ok};
#[cfg(any(target_os = "linux", target_os = "android"))]
use extattr::{Flags as XattrFlags, lsetxattr};
use jwalk::{Parallelism::Serial, WalkDir};

use crate::defs;

pub const SYSTEM_CON: &str = "u:object_r:system_file:s0";
pub const ADB_CON: &str = "u:object_r:adb_data_file:s0";
pub const UNLABEL_CON: &str = "u:object_r:unlabeled:s0";

const SELINUX_XATTR: &str = "security.selinux";

pub fn lsetfilecon<P: AsRef<Path>>(path: P, con: &str) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    lsetxattr(&path, SELINUX_XATTR, con, XattrFlags::empty()).with_context(|| {
        format!(
            "Failed to change SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn lgetfilecon<P: AsRef<Path>>(path: P) -> Result<String> {
    let con = extattr::lgetxattr(&path, SELINUX_XATTR).with_context(|| {
        format!(
            "Failed to get SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    let con = String::from_utf8_lossy(&con);
    Ok(con.to_string())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn setsyscon<P: AsRef<Path>>(path: P) -> Result<()> {
    lsetfilecon(path, SYSTEM_CON)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn setsyscon<P: AsRef<Path>>(path: P) -> Result<()> {
    unimplemented!()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn lgetfilecon<P: AsRef<Path>>(path: P) -> Result<String> {
    unimplemented!()
}

pub fn restore_syscon<P: AsRef<Path>>(dir: P) -> Result<()> {
    for dir_entry in WalkDir::new(dir).parallelism(Serial) {
        if let Some(path) = dir_entry.ok().map(|dir_entry| dir_entry.path()) {
            setsyscon(&path)?;
        }
    }
    Ok(())
}

fn restore_syscon_if_unlabeled<P: AsRef<Path>>(dir: P) -> Result<()> {
    for dir_entry in WalkDir::new(dir).parallelism(Serial) {
        if let Some(path) = dir_entry.ok().map(|dir_entry| dir_entry.path()) {
            if let Result::Ok(con) = lgetfilecon(&path) {
                if con == UNLABEL_CON || con.is_empty() {
                    lsetfilecon(&path, SYSTEM_CON)?;
                }
            }
        }
    }
    Ok(())
}

pub fn restorecon() -> Result<()> {
    lsetfilecon(defs::DAEMON_PATH, ADB_CON)?;
    // Recursively set system_file context for all modules.
    // This is critical for OverlayFS because files with adb_data_file context 
    // will cause the system to crash/reboot if overlaid on /system.
    restore_syscon(defs::MODULE_DIR)?;
    
    // Also ensure the RW directory (used for upperdir/workdir) exists and has correct context
    let system_rw_dir = Path::new(defs::SYSTEM_RW_DIR);
    if !system_rw_dir.exists() {
        let _ = std::fs::create_dir_all(system_rw_dir);
    }
    if system_rw_dir.exists() {
        let _ = restore_syscon(system_rw_dir);
    }
    
    Ok(())
}
