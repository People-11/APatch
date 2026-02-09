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
    Ok(con.trim_matches('\0').to_string())
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

pub fn ensure_con<P: AsRef<Path>>(path: P, target_con: &str) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // Optimization: Only set context if it is incorrect.
        // Reading xattr is much cheaper than writing it.
        match lgetfilecon(&path) {
            Result::Ok(con) if con == target_con => return Ok(()),
            _ => lsetfilecon(&path, target_con)?,
        }
    }
    Ok(())
}

pub fn ensure_syscon<P: AsRef<Path>>(path: P) -> Result<()> {
    ensure_con(path, SYSTEM_CON)
}

pub fn restore_syscon<P: AsRef<Path>>(dir: P) -> Result<()> {
    for dir_entry in WalkDir::new(dir).parallelism(Serial) {
        if let Some(path) = dir_entry.ok().map(|dir_entry| dir_entry.path()) {
            ensure_syscon(&path)?;
        }
    }
    Ok(())
}


pub fn restorecon() -> Result<()> {
    ensure_con(defs::DAEMON_PATH, ADB_CON)?;
    Ok(())
}
