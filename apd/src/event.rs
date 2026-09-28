use crate::sepolicy::get_policy_main;
use anyhow::{Context, Result, bail};
use libc::SIGPWR;
use log::{info, warn};
use notify::{
    Config, Event, EventKind, INotifyWatcher, RecursiveMode, Watcher,
    event::{ModifyKind, RenameMode},
};
use signal_hook::{consts::signal::*, iterator::Signals};
use std::{
    env,
    ffi::CString,
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::{
    assets, defs, hide, lua, magic_mount, metamodule, module, package, restorecon, supercall,
    supercall::{init_load_su_path, refresh_ap_package_list},
    utils::{self, switch_cgroups},
};

/// argv[0] and comm for the package-list monitor. /proc/<pid>/cmdline and
/// /proc/<pid>/comm are readable by any isolated process (gid 3009 bypasses
/// hidepid), and the default of both would be "/data/adb/apd" / "apd".
const UID_MONITOR_NAME: &str = "uid_monitor";

/// How long packages.list has to stay quiet before a burst is considered
/// finished. Only delays the catch-up refresh; the first one is immediate.
const PACKAGE_LIST_QUIET: Duration = Duration::from_millis(500);

pub fn report_kernel(superkey: Option<String>, event: &str, state: &str) {
    let Some(superkey) = superkey else {
        warn!("skip kernel event {event}/{state}: no SuperKey");
        return;
    };
    let args = [
        superkey,
        "event".to_string(),
        event.to_string(),
        state.to_string(),
    ];
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    // Best-effort notification to the kernel; a failed report must not abort
    // boot stages such as post-fs-data.
    if let Err(e) = utils::run_command("truncate", &args_ref, None)
        .and_then(|mut child| child.wait().map_err(anyhow::Error::from))
    {
        warn!("report kernel event {event}/{state} failed: {e}");
    }
}

pub fn on_post_data_fs(superkey: Option<String>) -> Result<()> {
    utils::umask(0);
    report_kernel(superkey.clone(), "post-fs-data", "before");
    use std::process::Stdio;
    #[cfg(unix)]
    init_load_su_path(&superkey);

    let mut sepol = get_policy_main(&["magiskpolicy".to_string(), "--live".to_string()])?;
    sepol.magisk_rules();
    sepol
        .to_file("/sys/fs/selinux/load")
        .context("Cannot apply policy")?;

    info!("Re-privilege apd profile after injecting sepolicy");
    supercall::privilege_apd_profile(&superkey);

    // Clear all temporary module configs early
    if let Err(e) = crate::module_config::clear_all_temp_configs() {
        warn!("clear temp configs failed: {e}");
    }

    if utils::has_magisk() {
        warn!("Magisk detected, skip post-fs-data!");
        report_kernel(superkey.clone(), "post-fs-data", "after");
        return Ok(());
    }

    // Create log environment
    if !Path::new(defs::APATCH_LOG_FOLDER).exists() {
        fs::create_dir(defs::APATCH_LOG_FOLDER).expect("Failed to create log folder");
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(defs::APATCH_LOG_FOLDER, permissions)
            .expect("Failed to set permissions");
    }
    let command_string = format!(
        "rm -rf {}*.old.log; for file in {}*; do mv \"$file\" \"$file.old.log\"; done",
        defs::APATCH_LOG_FOLDER,
        defs::APATCH_LOG_FOLDER
    );
    let mut args = vec!["-c", &command_string];
    // for all file to .old
    let result = utils::run_command("sh", &args, None)?.wait()?;
    if result.success() {
        info!("Successfully deleted .old files.");
    } else {
        info!("Failed to delete .old files.");
    }
    let logcat_path = format!("{}logcat.log", defs::APATCH_LOG_FOLDER);
    let dmesg_path = format!("{}dmesg.log", defs::APATCH_LOG_FOLDER);
    let bootlog = fs::File::create(dmesg_path)?;
    args = vec![
        "-s",
        "9",
        "45s",
        "logcat",
        "-b",
        "main,system,crash",
        "DrmLibFs:S",
        "-f",
        &logcat_path,
        "logcatcher-bootlog:S",
    ];
    let _ = unsafe {
        Command::new("timeout")
            .process_group(0)
            .pre_exec(|| {
                switch_cgroups();
                Ok(())
            })
            .args(args)
            .spawn()
    };
    args = vec!["-s", "9", "120s", "dmesg", "-w"];
    let _result = unsafe {
        Command::new("timeout")
            .process_group(0)
            .pre_exec(|| {
                switch_cgroups();
                Ok(())
            })
            .args(args)
            .stdout(Stdio::from(bootlog))
            .spawn()
    };

    let key = "KERNELPATCH_VERSION";
    match env::var(key) {
        Ok(value) => println!("{}: {}", key, value),
        Err(_) => println!("{} not found", key),
    }

    let key = "KERNEL_VERSION";
    match env::var(key) {
        Ok(value) => println!("{}: {}", key, value),
        Err(_) => println!("{} not found", key),
    }

    let safe_mode = utils::is_safe_mode(superkey.clone());

    if safe_mode {
        // we should still mount modules.img to `/data/adb/modules` in safe mode
        // becuase we may need to operate the module dir in safe mode
        warn!("safe mode, skip common post-fs-data.d scripts");
        // Not redundant with the disable below: ensure_binaries /
        // handle_updated_modules can still fail with `?` before reaching it,
        // and returning early with modules left enabled risks a bootloop.
        if let Err(e) = module::disable_all_modules() {
            warn!("disable all modules failed: {}", e);
        }
    } else {
        // Then exec common post-fs-data scripts
        if let Err(e) = module::exec_common_scripts("post-fs-data.d", true) {
            warn!("exec common post-fs-data scripts failed: {}", e);
        }
    }
    let module_update_dir = defs::MODULE_UPDATE_DIR; //save module place
    let module_dir = defs::MODULE_DIR; // run modules place
    let module_update_flag = Path::new(defs::WORKING_DIR).join(defs::UPDATE_FILE_NAME); // if update ,there will be renewed modules file
    assets::ensure_binaries().with_context(|| "binary missing")?;

    if Path::new(defs::MODULE_UPDATE_DIR).exists() {
        module::handle_updated_modules()?;
        fs::remove_dir_all(module_update_dir)?;
    }

    if safe_mode {
        warn!("safe mode, skip post-fs-data scripts and disable all modules!");
        if let Err(e) = module::disable_all_modules() {
            warn!("disable all modules failed: {}", e);
        }
        return Ok(());
    }

    if let Err(e) = module::prune_modules() {
        warn!("prune modules failed: {}", e);
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {}", e);
    }

    // load sepolicy.rule
    if module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    let mount_mode = utils::get_mount_mode();
    info!("mount mode: {mount_mode}");
    match mount_mode.as_str() {
        defs::MOUNT_MODE_DISABLED => {
            info!("module mounting is disabled, only scripts will run");
        }
        defs::MOUNT_MODE_METAMODULE => {
            if let Err(e) = metamodule::exec_mount_script(module_dir) {
                warn!("execute metamodule mount failed: {e}");
            }
        }
        // magic, and anything unrecognised
        _ => {
            if let Err(e) = magic_mount::magic_mount() {
                warn!("magic mount failed: {e}");
            }
        }
    }

    // exec modules post-fs-data scripts
    // TODO: Add timeout
    if let Err(e) = module::exec_stage_script("post-fs-data", true) {
        warn!("exec post-fs-data scripts failed: {}", e);
    }
    if let Err(e) = lua::exec_stage_lua("post-fs-data", true, superkey.as_deref().unwrap_or("")) {
        warn!("Failed to exec post-fs-data lua: {}", e);
    }
    // load system.prop
    if let Err(e) = module::load_system_prop() {
        warn!("load system.prop failed: {}", e);
    }

    // rewrite bootloader/debuggable props (opt-in, after modules had their say)
    if let Err(e) = hide::hide_sensitive_props() {
        warn!("failed to hide sensitive props: {}", e);
    }

    info!("remove update flag");
    let _ = fs::remove_file(module_update_flag);

    run_stage("post-mount", superkey.clone(), true);

    env::set_current_dir("/").with_context(|| "failed to chdir to /")?;
    report_kernel(superkey, "post-fs-data", "after");
    Ok(())
}

fn run_stage(stage: &str, superkey: Option<String>, block: bool) {
    utils::umask(0);

    if utils::has_magisk() {
        warn!("Magisk detected, skip {stage}");
        return;
    }

    if utils::is_safe_mode(superkey.clone()) {
        warn!("safe mode, skip {stage} scripts");
        if let Err(e) = module::disable_all_modules() {
            warn!("disable all modules failed: {}", e);
        }
        return;
    }

    // execute metamodule stage script first (priority), but only when the
    // metamodule is the thing doing the mounting
    if utils::get_mount_mode() == defs::MOUNT_MODE_METAMODULE
        && let Err(e) = metamodule::exec_stage_script(stage, block)
    {
        warn!("Failed to exec metamodule {stage} script: {e}");
    }

    if let Err(e) = module::exec_common_scripts(&format!("{stage}.d"), block) {
        warn!("Failed to exec common {stage} scripts: {e}");
    }
    if let Err(e) = module::exec_stage_script(stage, block) {
        warn!("Failed to exec {stage} scripts: {e}");
    }
    if let Err(e) = lua::exec_stage_lua(stage, block, superkey.as_deref().unwrap_or("")) {
        warn!("Failed to exec {stage} lua: {e}");
    }
}

pub fn on_services(superkey: Option<String>) -> Result<()> {
    info!("on_services triggered!");
    run_stage("service", superkey, false);

    Ok(())
}

fn run_uid_monitor(superkey: Option<&str>) {
    info!("Trigger run_uid_monitor!");

    let Some(superkey) = superkey else {
        warn!("not starting uid monitor: no SuperKey");
        return;
    };

    let mut command = &mut Command::new("/data/adb/apd");
    {
        command = command.process_group(0);
        // Keeps the real path out of /proc/<pid>/cmdline; the binary that runs
        // is still /data/adb/apd.
        command = command.arg0(UID_MONITOR_NAME);
        // The key is handed over on stdin, never on argv: this daemon outlives
        // the boot and /proc/<pid>/cmdline is readable by anything that can see
        // the pid. An isolated process carries gid 3009 (AID_READPROC) and can
        // see every pid, so argv here would hand the SuperKey to any app.
        command = command.stdin(Stdio::piped());
        command = unsafe {
            command.pre_exec(|| {
                // ignore the error?
                switch_cgroups();
                Ok(())
            })
        };
    }
    command = command.arg("uid-listener");

    match command.spawn() {
        Ok(mut child) => {
            match child.stdin.take() {
                // Dropping the pipe closes it, which is the child's EOF.
                Some(mut stdin) => {
                    if let Err(e) = writeln!(stdin, "{superkey}") {
                        warn!("[run_uid_monitor] failed to hand over the SuperKey: {e}");
                    }
                }
                None => warn!("[run_uid_monitor] no stdin pipe to hand the SuperKey over"),
            }
        }
        Err(e) => warn!("[run_uid_monitor] Failed to run uid monitor: {e}"),
    }
}

pub fn on_boot_completed(superkey: Option<String>) -> Result<()> {
    info!("on_boot_completed triggered!");

    run_stage("boot-completed", superkey.clone(), false);

    run_uid_monitor(superkey.as_deref());
    Ok(())
}

pub fn start_uid_listener(superkey: Option<String>) -> Result<()> {
    info!("start_uid_listener triggered!");
    println!("[start_uid_listener] Registering...");

    utils::set_process_name(UID_MONITOR_NAME);

    // run_uid_monitor hands the key over on stdin so it stays out of
    // /proc/<pid>/cmdline; -s is still accepted for running this by hand.
    let superkey = match superkey {
        Some(key) => key,
        None => {
            let mut key = String::new();
            std::io::stdin()
                .read_line(&mut key)
                .context("uid listener requires a SuperKey on stdin")?;
            let key = key.trim_end_matches(['\r', '\n']).to_string();
            if key.is_empty() {
                bail!("uid listener requires a SuperKey");
            }
            key
        }
    };
    let superkey_c = CString::new(superkey.clone()).context("SuperKey contains a null byte")?;

    // Prime the baseline with the boot state; this first call reports nothing
    // by design, and without it the first change would.
    let _ = package::get_package_changes();

    // create inotify instance
    const SYS_PACKAGES_LIST_TMP: &str = "/data/system/packages.list.tmp";
    let sys_packages_list_tmp = PathBuf::from(&SYS_PACKAGES_LIST_TMP);
    let dir: PathBuf = sys_packages_list_tmp.parent().unwrap().into();

    let (tx, rx) = std::sync::mpsc::channel();
    let mutex = Arc::new(Mutex::new(()));

    {
        let mutex_clone = mutex.clone();
        let signal_key = superkey_c.clone();
        thread::spawn(move || {
            let mut signals = Signals::new([SIGTERM, SIGINT, SIGPWR]).unwrap();
            if let Some(sig) = signals.forever().next() {
                log::warn!("[shutdown] Caught signal {sig}, refreshing package list...");
                refresh_ap_package_list(&signal_key, &mutex_clone);
            }
        });
    }

    let mut watcher = INotifyWatcher::new(
        move |ev: notify::Result<Event>| match ev {
            Ok(Event {
                kind: EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
                paths,
                ..
            }) => {
                if paths.contains(&sys_packages_list_tmp) {
                    info!("[uid_monitor] System packages list changed, sending to tx...");
                    tx.send(()).unwrap()
                }
            }
            Err(err) => warn!("inotify error: {err}"),
            _ => (),
        },
        Config::default(),
    )?;

    watcher.watch(dir.as_ref(), RecursiveMode::NonRecursive)?;

    let mut refresh = || {
        refresh_ap_package_list(&superkey_c, &mutex);
        report_kernel(
            Some(superkey.clone()),
            "uid_listener",
            "package-list-updated",
        );
    };

    // Leading edge, then one catch-up for the tail. Acting on the first rename
    // at once is what keeps the install notification prompt; folding the rest
    // of the burst into a single follow-up is what keeps it from becoming a
    // storm. PackageManager rewrites packages.list for routine things (an app
    // leaving the stopped state), and a refresh revokes every uid before
    // re-granting from the config, so one refresh per rename would repeatedly
    // drop root out from under running apps.
    while rx.recv().is_ok() {
        refresh();

        let mut tail = false;
        while rx.recv_timeout(PACKAGE_LIST_QUIET).is_ok() {
            tail = true;
        }
        if tail {
            refresh();
        }
    }

    Ok(())
}

/// Emulate a system reboot: restart the Android framework (`stop` / `start`)
/// and re-apply the service stage. Used by jailbreak mode so that a runtime-loaded
/// `kernelpatch.ko` stays active (a full reboot would drop it).
pub fn soft_reboot(superkey: Option<String>) -> Result<()> {
    use std::process::Command;

    // Detach from the caller (app root shell) first: `stop` tears down the
    // framework including the app/zygote tree this process was spawned from, so
    // without daemonizing the `start` below would never be reached.
    utils::daemonize()?;

    info!("emulating soft reboot!");
    utils::switch_mnt_ns(1)?;
    std::env::set_current_dir("/").with_context(|| "failed to chdir to /")?;

    if let Err(e) = crate::resetprop::set_prop("sys.boot_completed", "0") {
        warn!("reset boot completed failed: {e}");
    }

    info!("stop");
    let status = Command::new("stop").status().context("stop failed")?;
    if !status.success() {
        warn!("stop exited with status: {status}");
    }

    info!("post-fs-data");
    // Never abort the soft reboot here: the framework must always be restarted.
    // The daemonized stdin (dev null) keeps the supercall/truncate redirects from
    // blocking, so re-applying the boot stages is safe.
    if let Err(e) = on_post_data_fs(superkey.clone()) {
        warn!("post-fs-data failed during soft reboot: {e:#}");
    }

    info!("start");
    let status = Command::new("start").status().context("start failed")?;
    if !status.success() {
        warn!("start exited with status: {status}");
    }

    info!("services");
    on_services(superkey)?;

    Ok(())
}
