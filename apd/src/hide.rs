//! Rewrite the props that give away an unlocked bootloader / debuggable build.
//!
//! Inspired by
//! <https://github.com/matsuzaka-yuki/FolkPatch/blob/main/FolkS/Hide.zig>

use anyhow::Result;
use log::info;
use std::fs;

use crate::defs;
use crate::resetprop::{get_prop, set_prop};

/// Props that are always forced to their stock values.
const CORE_PROPS: [(&str, &str); 20] = [
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

/// Boot-mode props: only rewritten when they still say "recovery".
const BOOT_MODE_PROPS: [&str; 3] = ["ro.bootmode", "ro.boot.bootmode", "vendor.boot.bootmode"];

/// AVB props that are only filled in when the device does not report them at
/// all; overwriting a real value here would itself look wrong.
const VBMETA_PROPS: [(&str, &str); 5] = [
    ("ro.boot.vbmeta.device_state", "locked"),
    ("ro.boot.vbmeta.invalidate_on_error", "yes"),
    ("ro.boot.vbmeta.avb_version", "1.0"),
    ("ro.boot.vbmeta.hash_alg", "sha256"),
    ("ro.boot.vbmeta.size", "4096"),
];

fn is_enabled() -> bool {
    fs::read_to_string(defs::FACTORY_PROPS_FILE)
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Hide sensitive props. A no-op unless the feature is switched on.
///
/// Individual failures are ignored on purpose: a prop that is read-only in
/// this kernel, or absent on this vendor, should not abort the rest.
pub fn hide_sensitive_props() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    for (key, value) in CORE_PROPS {
        let _ = set_prop(key, value);
    }

    for key in BOOT_MODE_PROPS {
        if let Some(val) = get_prop(key)
            && val.contains("recovery")
        {
            let _ = set_prop(key, "unknown");
        }
    }

    for (key, value) in VBMETA_PROPS {
        if get_prop(key).is_none() {
            let _ = set_prop(key, value);
        }
    }

    info!("factory props applied");
    Ok(())
}
