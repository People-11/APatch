use std::{
    collections::HashSet,
    fs::File,
    io::{self, BufRead},
    path::Path,
    sync::{Mutex, OnceLock},
    thread,
    time::Duration,
};

use log::warn;
use serde::{Deserialize, Serialize};

static KNOWN_PACKAGES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

#[derive(Deserialize, Serialize, Clone)]
pub struct PackageConfig {
    pub pkg: String,
    pub exclude: i32,
    pub allow: i32,
    pub uid: i32,
    pub to_uid: i32,
    pub sctx: String,
}

fn get_known_packages() -> &'static Mutex<HashSet<String>> {
    KNOWN_PACKAGES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn read_lines<P: AsRef<Path>>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> {
    File::open(filename).map(|file| io::BufReader::new(file).lines())
}

fn retry_operation<T, F>(max_retry: usize, mut operation: F) -> io::Result<T>
where
    F: FnMut() -> io::Result<T>,
{
    for attempt in 0..max_retry {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt < max_retry - 1 {
                    warn!("Operation failed (attempt {}/{}): {}", attempt + 1, max_retry, e);
                    thread::sleep(Duration::from_secs(1));
                } else {
                    return Err(e);
                }
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "Max retries exceeded"))
}

pub fn read_ap_package_config() -> Vec<PackageConfig> {
    retry_operation(5, || {
        let file = File::open("/data/adb/ap/package_config")?;
        let mut reader = csv::Reader::from_reader(file);
        reader.deserialize().collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })
    .unwrap_or_else(|e| {
        warn!("Failed to read package config: {}", e);
        Vec::new()
    })
}

pub fn write_ap_package_config(package_configs: &[PackageConfig]) -> io::Result<()> {
    retry_operation(5, || {
        let temp_path = "/data/adb/ap/package_config.tmp";
        let file = File::create(temp_path)?;
        let mut writer = csv::Writer::from_writer(file);
        
        for config in package_configs {
            writer.serialize(config)?;
        }
        
        writer.flush()?;
        std::fs::rename(temp_path, "/data/adb/ap/package_config")?;
        Ok(())
    })
}

pub fn initialize_package_baseline() -> io::Result<()> {
    retry_operation(5, || {
        let packages: HashSet<String> = read_lines("/data/system/packages.list")?
            .filter_map(|line| line.ok())
            .filter_map(|line| line.split_whitespace().next().map(String::from))
            .collect();
        
        if let Ok(mut guard) = get_known_packages().lock() {
            *guard = packages;
        }
        
        Ok(())
    })
}

pub fn get_package_changes() -> (Vec<String>, Vec<String>) {
    retry_operation(5, || {
        let current_packages: HashSet<String> = read_lines("/data/system/packages.list")?
            .filter_map(|line| line.ok())
            .filter_map(|line| line.split_whitespace().next().map(String::from))
            .collect();
        
        let mut added_packages = Vec::new();
        let mut removed_packages = Vec::new();
        
        if let Ok(mut guard) = get_known_packages().lock() {
            added_packages = current_packages.difference(&*guard).cloned().collect();
            removed_packages = guard.difference(&current_packages).cloned().collect();
            *guard = current_packages;
        }
        
        Ok((added_packages, removed_packages))
    })
    .unwrap_or_else(|e| {
        warn!("Failed to get package changes: {}", e);
        (Vec::new(), Vec::new())
    })
}

pub fn synchronize_package_uid() -> io::Result<Vec<String>> {
    retry_operation(5, || {
        let lines: Vec<_> = read_lines("/data/system/packages.list")?
            .filter_map(|line| line.ok())
            .collect();

        let mut package_configs = read_ap_package_config();
        let system_packages: HashSet<String> = lines
            .iter()
            .filter_map(|line| line.split_whitespace().next())
            .map(String::from)
            .collect();

        let removed_packages: Vec<String> = package_configs
            .iter()
            .filter(|config| !system_packages.contains(&config.pkg))
            .map(|config| config.pkg.clone())
            .collect();

        package_configs.retain(|config| system_packages.contains(&config.pkg));

        let mut updated = false;
        for line in &lines {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() < 2 {
                continue;
            }

            let pkg_name = words[0];
            let Ok(uid) = words[1].parse::<i32>() else { continue };

            for config in package_configs.iter_mut().filter(|c| c.pkg == pkg_name) {
                if config.uid % 100000 != uid % 100000 {
                    config.uid = config.uid / 100000 * 100000 + uid % 100000;
                    updated = true;
                }
            }
        }

        if updated || !removed_packages.is_empty() {
            write_ap_package_config(&package_configs)?;
        }

        Ok(removed_packages)
    })
}
