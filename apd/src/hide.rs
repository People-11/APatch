/// This function is inspired by
/// https://github.com/matsuzaka-yuki/FolkPatch/blob/main/FolkS/Hide.zig
use anyhow::{Context, Result};
use log::info;
use prop_rs_android::resetprop::ResetProp as InnerResetProp;
use prop_rs_android::sys_prop;
use crate::defs;
use std::fs;

/// Hide sensitive props like Factory Props
pub fn hide_sensitive_props() -> Result<()> {
    if let Ok(enabled) = fs::read_to_string(defs::FACTORY_PROPS_FILE) {
        if enabled.trim() != "1" {
            return Ok(());
        }
    } else {
        return Ok(());
    }

    sys_prop::init().context("Failed to initialize system property API")?;

    let rp = InnerResetProp {
        skip_svc: true,
        persistent: false,
        persist_only: false,
        verbose: false,
        show_context: false,
    };

    let core_list = [
        ("ro.boot.vbmeta.device_state", "locked"),
        ("ro.boot.verifiedbootstate", "green"),
        ("ro.boot.flash.locked", "1"),
        ("ro.boot.veritymode", "enforcing"),
        ("ro.boot.warranty_bit", "0"),
        ("ro.warranty_bit", "0"),
        ("ro.debuggable", "0"),
        ("ro.force.debuggable", "0"),
        ("ro.secure", "1"),
        ("ro.adb.secure", "1"),
        ("ro.build.type", "user"),
        ("ro.build.tags", "release-keys"),
        ("ro.vendor.boot.warranty_bit", "0"),
        ("ro.vendor.warranty_bit", "0"),
        ("vendor.boot.vbmeta.device_state", "locked"),
        ("vendor.boot.verifiedbootstate", "green"),
        ("sys.oem_unlock_allowed", "0"),
        ("ro.secureboot.lockstate", "locked"),
        ("ro.boot.realmebootstate", "green"),
        ("ro.boot.realme.lockstate", "1"),
    ];

    for (key, value) in core_list {
        let _ = rp.set(key, value);
    }

    let boot_keys = ["ro.bootmode", "ro.boot.bootmode", "vendor.boot.bootmode"];
    for key in boot_keys {
        if let Some(val) = rp.get(key) {
            if val.contains("recovery") {
                let _ = rp.set(key, "unknown");
            }
        }
    }

    let patch_list = [
        ("ro.boot.vbmeta.device_state", "locked"),
        ("ro.boot.vbmeta.invalidate_on_error", "yes"),
        ("ro.boot.vbmeta.avb_version", "1.0"),
        ("ro.boot.vbmeta.hash_alg", "sha256"),
        ("ro.boot.vbmeta.size", "4096"),
    ];

    for (key, value) in patch_list {
        if rp.get(key).is_none() {
            let _ = rp.set(key, value);
        }
    }

    info!("Hiding sensitive props");
    Ok(())
}
