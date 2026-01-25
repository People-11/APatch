use std::{
    env,
    ffi::CStr,
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use libc::SIGPWR;
use log::{info, warn};
use notify::{
    Config, Event, EventKind, INotifyWatcher, RecursiveMode, Watcher,
    event::{ModifyKind, RenameMode},
};
use signal_hook::{consts::signal::*, iterator::Signals};

use crate::{
    assets, defs, magic_mount, metamodule, module, mount, restorecon, supercall,
    supercall::{
        fork_for_result, init_load_package_uid_config, init_load_su_path, refresh_ap_package_list,
    },
    utils::{
        self, switch_cgroups,
    },
};

use std::io;
use anyhow::ensure;

/// Calculate the total size of all files in a directory (recursive)
fn calculate_total_size(path: &Path) -> io::Result<u64> {
    let mut total_size = 0;
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_file() {
                total_size += entry.metadata()?.len();
            } else if file_type.is_dir() {
                total_size += calculate_total_size(&entry.path())?;
            }
        }
    }
    Ok(total_size)
}

/// Ensure a file exists, create it if it doesn't
fn ensure_file_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::File::create(path).with_context(|| format!("Failed to create {}", path.display()))?;
    }
    Ok(())
}

/// Ensure a directory exists and is empty
fn ensure_clean_dir(path: &str) -> Result<()> {
    let path = Path::new(path);
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)?;
    Ok(())
}

/// Get the current mount mode from configuration file
fn get_mount_mode() -> String {
    let mode_file = Path::new(defs::MOUNT_MODE_FILE);
    if mode_file.exists() {
        if let Ok(content) = std::fs::read_to_string(mode_file) {
            let mode = content.trim();
            match mode {
                defs::MOUNT_MODE_MAGIC | defs::MOUNT_MODE_METAMODULE | defs::MOUNT_MODE_DISABLED => return mode.to_string(),
                _ => {}
            }
        }
    }
    // Check legacy lite mode file for backwards compatibility
    if Path::new(defs::LITEMODE_FILE).exists() {
        return defs::MOUNT_MODE_DISABLED.to_string();
    }
    // Default to magic mount for backwards compatibility
    defs::MOUNT_MODE_MAGIC.to_string()
}

/// Check if OverlayFS should be used instead of bind mount
/// OverlayFS is only used when:
/// 1. Force OverlayFS file exists (/data/adb/.overlayfs_enable), AND
/// 2. Kernel supports OverlayFS
fn should_use_overlayfs() -> bool {
    let available = utils::overlayfs_available();
    println!("OverlayFS available: {}", available);
    Path::new(defs::FORCE_OVERLAYFS_FILE).exists() && utils::overlayfs_available()
}

/// Mount a partition using OverlayFS with module directories as lower layers
fn mount_partition(partition_name: &str, lowerdir: &Vec<String>) -> Result<()> {
    if lowerdir.is_empty() {
        info!("partition: {partition_name} lowerdir is empty, skip");
        return Ok(());
    }

    let partition = format!("/{partition_name}");


    let mut workdir = None;
    let mut upperdir = None;
    let system_rw_dir = Path::new(defs::SYSTEM_RW_DIR);
    if system_rw_dir.exists() {
        let part_rw_dir = system_rw_dir.join(partition_name);
        let wd = part_rw_dir.join("workdir");
        let ud = part_rw_dir.join("upperdir");
        
        let _ = std::fs::create_dir_all(&wd);
        let _ = std::fs::create_dir_all(&ud);
        let _ = restorecon::setsyscon(&part_rw_dir);
        let _ = restorecon::setsyscon(&wd);
        let _ = restorecon::setsyscon(&ud);

        workdir = Some(wd);
        upperdir = Some(ud);
    }

    mount::mount_overlay(&partition, lowerdir, workdir, upperdir)
}

/// Mount modules using OverlayFS (systemless mount)
/// This collects all module system directories and mounts them as overlay layers
fn mount_systemlessly_overlayfs(module_dir: &str) -> Result<()> {
    let module_dir_path = Path::new(module_dir);
    let dir = match fs::read_dir(module_dir) {
        Ok(d) => d,
        Err(e) => {
            warn!("Failed to read module dir {}: {}", module_dir, e);
            return Ok(());
        }
    };

    let mut system_lowerdir: Vec<String> = Vec::new();

    // Extended partition list including Samsung partitions
    let partitions = crate::defs::EXTENDED_PARTITIONS;
    let mut partition_lowerdir: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for (part, _) in partitions {
        let path_of_root = Path::new("/").join(part);
        // Only require the root partition to exist
        if path_of_root.is_dir() {
            partition_lowerdir.insert(part.to_string(), Vec::new());
        }
    }
    
    for entry in dir.flatten() {
        let module = entry.path();
        if !module.is_dir() {
            continue;
        }

        // Check if module is disabled
        if let Some(module_name) = module.file_name() {
            let real_module_path = module_dir_path.join(module_name);
            if real_module_path.join(defs::DISABLE_FILE_NAME).exists() {
                info!("module: {} is disabled, skip", module.display());
                continue;
            }
        }

        // Check if module has skip_mount flag
        if module.join(defs::SKIP_MOUNT_FILE_NAME).exists() {
            info!("module: {} has skip_mount, skip", module.display());
            continue;
        }

        // Collect /system overlay
        let module_system = module.join("system");
        if module_system.is_dir() {
            system_lowerdir.push(format!("{}", module_system.display()));
        }

        // Collect partition-specific overlays
        for (part, _) in partitions {
            let part_path = module.join(part);
            let part_path_in_system = module.join("system").join(part);
            
            if let Some(v) = partition_lowerdir.get_mut(*part) {
                // Priority: system/$PART > $PART
                if part_path_in_system.is_dir() {
                    v.push(format!("{}", part_path_in_system.display()));
                }
                
                if part_path.is_dir() {
                    v.push(format!("{}", part_path.display()));
                }
            }
        }
    }

    // Mount /system first
    if let Err(e) = mount_partition("system", &system_lowerdir) {
        warn!("mount system overlay failed: {:#}", e);
        return Err(e);
    }

    // Mount other partitions
    for (partition, dirs) in partition_lowerdir {
        if let Err(e) = mount_partition(&partition, &dirs) {
            warn!("mount {} overlay failed: {:#}", partition, e);
            return Err(e);
        }
    }


    Ok(())
}

/// Mount modules using an ext4 image (modules.img)
/// This is used when bind mounting individual directories is not preferred or efficient
/// 1. Creates/Updates modules.img
/// 2. Mounts modules.img to modules_mount dir
/// 3. Performs overlayfs mount from the mounted image
fn mount_systemlessly_with_image(module_dir: &str) -> Result<()> {
    info!("Using image-based OverlayFS mount");
    let module_mount_dir = defs::MODULE_MOUNT_DIR;
    let tmp_module_img = defs::MODULE_UPDATE_TMP_IMG;
    let tmp_module_path = Path::new(tmp_module_img);

    ensure_clean_dir(module_mount_dir)?;
    info!("- Preparing image");

    let module_update_flag = Path::new(defs::WORKING_DIR).join(defs::UPDATE_FILE_NAME);

    // If tmp image doesn't exist, force update logic to create it
    if !tmp_module_path.exists() {
        ensure_file_exists(&module_update_flag)?;
    }

    if module_update_flag.exists() {
        if tmp_module_path.exists() {
            // If it has update, remove tmp file
            fs::remove_file(tmp_module_path)?;
        }
        
        // Calculate size needed. Use module_dir as source of truth.
        let total_size = calculate_total_size(Path::new(module_dir))?;
        info!(
            "Total size of files in '{}': {} bytes",
            module_dir,
            total_size
        );
        
        // Create image with extra space (128MB)
        let grow_size = 128 * 1024 * 1024 + total_size;
        fs::File::create(tmp_module_img)
            .context("Failed to create ext4 image file")?
            .set_len(grow_size)
            .context("Failed to extend ext4 image")?;
            
        // Format image
        let result = Command::new("mkfs.ext4")
            .arg("-b")
            .arg("1024")
            .arg("-O")
            .arg("^has_journal") // Disable journal for speed and less space
            .arg(tmp_module_img)
            .stdout(std::process::Stdio::piped())
            .output()?;
            
        ensure!(
            result.status.success(),
            "Failed to format ext4 image: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        
        info!("Checking Image");
        // We skip check_image simple implementation for now, mkfs should be enough
    }

    info!("- Mounting image");
    // Mount the image to module_mount_dir using AutoMountExt4
    // This resolves "unused struct AutoMountExt4" warning
    let _mounted_image = mount::AutoMountExt4::try_new(tmp_module_img, module_mount_dir, false)
        .context("mount module image failed")?;
        
    info!("mounted {} to {}", tmp_module_img, module_mount_dir);
    
    // Set context recursively for all files inside the mounted image
    let _ = restorecon::restore_syscon(module_mount_dir);

    // Copy modules into the mounted image if we are updating
    if module_update_flag.exists() {
        info!("Copying modules to image...");
        let command_string = format!(
            "cp --preserve=context -RP {}* {};",
            module_dir, module_mount_dir
        );
        let args = vec!["-c", &command_string];
        let _ = utils::run_command("sh", &args, None)?.wait()?;
        
        // Remove update flag
        fs::remove_file(module_update_flag).ok();
    }
    
    // Now perform standard systemless mount using the files in the mounted image
    mount_systemlessly_overlayfs(module_mount_dir)
}

pub fn on_post_data_fs(superkey: Option<String>) -> Result<()> {
    utils::umask(0);
    use std::process::Stdio;
    #[cfg(unix)]
    init_load_package_uid_config(&superkey);

    init_load_su_path(&superkey);

    let args = ["/data/adb/ap/bin/magiskpolicy", "--magisk", "--live"];
    fork_for_result("/data/adb/ap/bin/magiskpolicy", &args, &superkey);

    info!("Re-privilege apd profile after injecting sepolicy");
    supercall::privilege_apd_profile(&superkey);

    if utils::has_magisk() {
        warn!("Magisk detected, skip post-fs-data!");
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
    let logcat_path = format!("{}locat.log", defs::APATCH_LOG_FOLDER);
    let dmesg_path = format!("{}dmesg.log", defs::APATCH_LOG_FOLDER);
    let bootlog = fs::File::create(dmesg_path)?;
    args = vec![
        "-s",
        "9",
        "120s",
        "logcat",
        "-b",
        "main,system,crash",
        "-f",
        &logcat_path,
        "logcatcher-bootlog:S",
        "&",
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

    // Mount modules based on configured mount mode
    let mount_mode = get_mount_mode();
    info!("Current mount mode: {}", mount_mode);

    match mount_mode.as_str() {
        defs::MOUNT_MODE_DISABLED => {
            info!("Mount disabled (lite mode), skipping all module mounts");
        }
        defs::MOUNT_MODE_METAMODULE => {
            // Use metamodule's custom mount script
            if let Err(e) = metamodule::exec_mount_script(module_dir) {
                warn!("execute metamodule mount failed: {e}");
            }
        }
        defs::MOUNT_MODE_MAGIC | _ => {
            // Use built-in magic mount (default for backwards compatibility)
            println!("Choosing mount mode... magic/default");
            if should_use_overlayfs() {
                // OverlayFS mode
                info!("Using OverlayFS mount mode");
                println!("Using OverlayFS mount mode");
                // 1. Try image-based overlay mount (most stable, compatible with legacy)
                match mount_systemlessly_with_image(module_dir) {
                    Ok(_) => {
                        info!("Image-based OverlayFS mount successful");
                        println!("Image-based OverlayFS mount successful");
                    }
                    Err(e_img) => {
                        warn!("Image-based OverlayFS mount failed: {}, falling back to direct overlay", e_img);
                        println!("Image-based OverlayFS mount failed: {}, falling back to direct overlay", e_img);
                        // 2. Try direct directory overlay mount (lightweight)
                        match mount_systemlessly_overlayfs(module_dir) {
                            Ok(_) => {
                                info!("Direct OverlayFS mount successful");
                                println!("Direct OverlayFS mount successful");
                            }
                            Err(e_dir) => {
                                warn!("Direct OverlayFS mount failed: {}, falling back to magic mount", e_dir);
                                println!("Direct OverlayFS mount failed: {}, falling back to magic mount", e_dir);
                                // 3. Fallback to magic mount (bind mount)
                                if let Err(e_magic) = magic_mount::magic_mount() {
                                    warn!("Magic mount fallback also failed: {}", e_magic);
                                    println!("Magic mount fallback also failed: {}", e_magic);
                                }
                            }
                        }
                    }
                }
            } else {
                // Standard magic mount (bind mount)
                info!("Using Magic Mount (bind mount) mode");
                println!("Using Magic Mount (bind mount) mode");
                if let Err(e) = magic_mount::magic_mount() {
                    warn!("magic mount failed: {}", e);
                    println!("magic mount failed: {}", e);
                }
            }
        }
    }

    // exec modules post-fs-data scripts
    // TODO: Add timeout
    if let Err(e) = module::exec_stage_script("post-fs-data", true) {
        warn!("exec post-fs-data scripts failed: {}", e);
    }
    if let Err(e) = module::exec_stage_lua("post-fs-data", true, superkey.as_deref().unwrap_or(""))
    {
        warn!("Failed to exec post-fs-data lua: {}", e);
    }
    // load system.prop
    if let Err(e) = module::load_system_prop() {
        warn!("load system.prop failed: {}", e);
    }

    info!("remove update flag");
    let _ = fs::remove_file(module_update_flag);

    run_stage("post-mount", superkey, true);

    env::set_current_dir("/").with_context(|| "failed to chdir to /")?;

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

    // execute metamodule stage script first (priority)
    if let Err(e) = metamodule::exec_stage_script(stage, block) {
        warn!("Failed to exec metamodule {stage} script: {e}");
    }

    if let Err(e) = module::exec_common_scripts(&format!("{stage}.d"), block) {
        warn!("Failed to exec common {stage} scripts: {e}");
    }
    if let Err(e) = module::exec_stage_script(stage, block) {
        warn!("Failed to exec {stage} scripts: {e}");
    }
    if let Err(e) = module::exec_stage_lua(stage, block, superkey.as_deref().unwrap_or("")) {
        warn!("Failed to exec {stage} lua: {e}");
    }
}

pub fn on_services(superkey: Option<String>) -> Result<()> {
    info!("on_services triggered!");
    run_stage("service", superkey, false);

    Ok(())
}

fn run_uid_monitor() {
    info!("Trigger run_uid_monitor!");

    let mut command = &mut Command::new("/data/adb/apd");
    {
        command = command.process_group(0);
        command = unsafe {
            command.pre_exec(|| {
                // ignore the error?
                switch_cgroups();
                Ok(())
            })
        };
    }
    command = command.arg("uid-listener");

    command
        .spawn()
        .map(|_| ())
        .expect("[run_uid_monitor] Failed to run uid monitor");
}

pub fn on_boot_completed(superkey: Option<String>) -> Result<()> {
    info!("on_boot_completed triggered!");

    run_stage("boot-completed", superkey, false);

    run_uid_monitor();
    Ok(())
}

pub fn start_uid_listener() -> Result<()> {
    info!("start_uid_listener triggered!");
    println!("[start_uid_listener] Registering...");

    // create inotify instance
    const SYS_PACKAGES_LIST_TMP: &str = "/data/system/packages.list.tmp";
    let sys_packages_list_tmp = PathBuf::from(&SYS_PACKAGES_LIST_TMP);
    let dir: PathBuf = sys_packages_list_tmp.parent().unwrap().into();

    let (tx, rx) = std::sync::mpsc::channel();
    let tx_clone = tx.clone();
    let mutex = Arc::new(Mutex::new(()));

    {
        let mutex_clone = mutex.clone();
        thread::spawn(move || {
            let mut signals = Signals::new(&[SIGTERM, SIGINT, SIGPWR]).unwrap();
            for sig in signals.forever() {
                log::warn!("[shutdown] Caught signal {sig}, refreshing package list...");
                let skey = CStr::from_bytes_with_nul(b"su\0")
                    .expect("[shutdown_listener] CStr::from_bytes_with_nul failed");
                refresh_ap_package_list(&skey, &mutex_clone);
                break; // 执行一次后退出线程
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
                    tx_clone.send(false).unwrap()
                }
            }
            Err(err) => warn!("inotify error: {err}"),
            _ => (),
        },
        Config::default(),
    )?;

    watcher.watch(dir.as_ref(), RecursiveMode::NonRecursive)?;

    let mut debounce = false;
    while let Ok(delayed) = rx.recv() {
        if delayed {
            debounce = false;
            let skey = CStr::from_bytes_with_nul(b"su\0")
                .expect("[start_uid_listener] CStr::from_bytes_with_nul failed");
            refresh_ap_package_list(&skey, &mutex);
        } else if !debounce {
            thread::sleep(Duration::from_secs(1));
            debounce = true;
            tx.send(true)?;
        }
    }

    Ok(())
}
