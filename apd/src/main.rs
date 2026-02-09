mod apd;
mod assets;
mod cli;
mod defs;
mod event;
mod magic_mount;
mod lua;
mod metamodule;
mod module;
mod mount;
mod package;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod pty;
mod restorecon;
mod sepolicy;
mod mpolicy;
mod supercall;
mod utils;
mod resetprop;
fn main() -> anyhow::Result<()> {
    cli::run()
}
