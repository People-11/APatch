#[allow(unused_imports)]
use std::fs::{Permissions, set_permissions};
#[cfg(unix)]
use std::os::unix::prelude::PermissionsExt;
use std::{
    ffi::CString,
    fs::{File, OpenOptions, create_dir_all, metadata},
    io::{ErrorKind::AlreadyExists, Write},
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{Context, Error, Ok, Result, bail};
use log::{info, warn};

use crate::{defs, supercall::sc_su_get_safemode};

pub fn ensure_file_exists<T: AsRef<Path>>(file: T) -> Result<()> {
    match File::options().write(true).create_new(true).open(&file) {
        Result::Ok(_) => Ok(()),
        Err(err) => {
            if err.kind() == AlreadyExists && file.as_ref().is_file() {
                Ok(())
            } else {
                Err(Error::from(err))
                    .with_context(|| format!("{} is not a regular file", file.as_ref().display()))
            }
        }
    }
}

pub fn ensure_dir_exists<T: AsRef<Path>>(dir: T) -> Result<()> {
    let result = create_dir_all(&dir).map_err(Error::from);
    if dir.as_ref().is_dir() {
        result
    } else if result.is_ok() {
        bail!("{} is not a regular directory", dir.as_ref().display())
    } else {
        result
    }
}

// todo: ensure
pub fn ensure_binary<T: AsRef<Path>>(path: T) -> Result<()> {
    set_permissions(&path, Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn getprop(prop: &str) -> Option<String> {
    android_properties::getprop(prop).value()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn getprop(_prop: &str) -> Option<String> {
    unimplemented!()
}
pub fn run_command(
    command: &str,
    args: &[&str],
    stdout: Option<Stdio>,
) -> Result<std::process::Child> {
    let mut command_builder = Command::new(command);
    command_builder.args(args);
    if let Some(out) = stdout {
        command_builder.stdout(out);
    }
    let child = command_builder.spawn()?;
    Ok(child)
}
pub fn is_safe_mode(superkey: Option<String>) -> bool {
    let safemode = getprop("persist.sys.safemode")
        .filter(|prop| prop == "1")
        .is_some()
        || getprop("ro.sys.safemode")
            .filter(|prop| prop == "1")
            .is_some();
    info!("safemode: {}", safemode);
    if safemode {
        return true;
    }
    let safemode = superkey
        .as_ref()
        .and_then(|key_str| CString::new(key_str.as_str()).ok())
        .map_or_else(
            || {
                warn!("[is_safe_mode] No valid superkey provided, assuming safemode as false.");
                false
            },
            |cstr| sc_su_get_safemode(&cstr) == 1,
        );
    info!("kernel_safemode: {}", safemode);
    safemode
}

/// Set the name reported by /proc/<pid>/comm and /proc/<pid>/stat.
///
/// Both are 0444 and only shielded by hidepid, which an isolated process
/// bypasses with gid 3009, so they are readable by any app that cares to look.
/// /proc/<pid>/exe still resolves to the real binary, but reading that link
/// needs ptrace access to another uid's process, which such a caller does not
/// have -- comm and cmdline are the part actually on display.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_process_name(name: &str) {
    // PR_SET_NAME reads 16 bytes and wants them NUL-terminated.
    let mut buf = [0u8; 16];
    let bytes = name.as_bytes();
    let n = bytes.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&bytes[..n]);
    unsafe {
        libc::prctl(libc::PR_SET_NAME, buf.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn switch_mnt_ns(pid: i32) -> Result<()> {
    use std::os::fd::AsRawFd;

    use anyhow::ensure;
    let path = format!("/proc/{pid}/ns/mnt");
    let fd = File::open(path)?;
    let current_dir = std::env::current_dir();
    let ret = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNS) };
    if let Result::Ok(current_dir) = current_dir {
        let _ = std::env::set_current_dir(current_dir);
    }
    ensure!(ret == 0, "switch mnt ns failed");
    Ok(())
}

fn switch_cgroup(grp: &str, pid: u32) {
    let path = Path::new(grp).join("cgroup.procs");
    if !path.exists() {
        return;
    }

    let fp = OpenOptions::new().append(true).open(path);
    if let Result::Ok(mut fp) = fp {
        let _ = write!(fp, "{pid}");
    }
}

pub fn switch_cgroups() {
    let pid = std::process::id();
    switch_cgroup("/acct", pid);
    switch_cgroup("/dev/cg2_bpf", pid);
    switch_cgroup("/sys/fs/cgroup", pid);

    if getprop("ro.config.per_app_memcg")
        .filter(|prop| prop == "false")
        .is_none()
    {
        switch_cgroup("/dev/memcg/apps", pid);
    }
}

/// Detach the current process into a background daemon so it survives the
/// framework being torn down around it (e.g. `stop` during a soft reboot).
/// Redirects stdin/stdout/stderr to /dev/null and double-forks out of the
/// caller's process group / cgroup.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn daemonize() -> Result<()> {
    use std::os::fd::AsRawFd;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork error: {}", std::io::Error::last_os_error());
    }
    if pid > 0 {
        // Parent: wait for the child, then exit so the caller sees success.
        let mut status: i32 = 0;
        loop {
            if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    std::process::exit(1);
                }
            } else {
                break;
            }
        }
        std::process::exit(0);
    }

    unsafe { libc::setsid() };
    switch_cgroups();

    if let Result::Ok(null) = File::open("/dev/null") {
        let fd = null.as_raw_fd();
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork error: {}", std::io::Error::last_os_error());
    }
    if pid > 0 {
        unsafe { libc::_exit(0) };
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn daemonize() -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn umask(mask: u32) {
    unsafe { libc::umask(mask) };
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn umask(_mask: u32) {
    unimplemented!("umask is not supported on this platform")
}

pub fn has_magisk() -> bool {
    which::which("magisk").is_ok()
}
pub fn get_tmp_path() -> &'static str {
    if metadata(defs::TEMP_DIR_LEGACY).is_ok() {
        return defs::TEMP_DIR_LEGACY;
    }
    if metadata(defs::TEMP_DIR).is_ok() {
        return defs::TEMP_DIR;
    }
    ""
}

/// Which mounting strategy modules use. Unset or unrecognised means magic
/// mount, which is what a device without the setting has always done.
pub fn get_mount_mode() -> String {
    if let Result::Ok(content) = std::fs::read_to_string(defs::MOUNT_MODE_FILE) {
        let mode = content.trim();
        if matches!(
            mode,
            defs::MOUNT_MODE_MAGIC | defs::MOUNT_MODE_METAMODULE | defs::MOUNT_MODE_DISABLED
        ) {
            return mode.to_string();
        }
    }
    defs::MOUNT_MODE_MAGIC.to_string()
}
