use super::{DetectResult, PkgAdapter, ResolvedPackage};
use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub struct NpmAdapter;

impl PkgAdapter for NpmAdapter {
    fn ecosystem(&self) -> &'static str {
        "npm"
    }

    fn detect(&self, save_path: &Path) -> Option<DetectResult> {
        if !save_path.is_dir() || save_path.file_name()?.to_str()? != "node_modules" {
            return None;
        }

        if save_path.join(".pnpm").is_dir() {
            return None;
        }

        let project_root = save_path.parent()?;
        let lockfile = if project_root.join("package-lock.json").is_file() {
            project_root.join("package-lock.json")
        } else if project_root.join("npm-shrinkwrap.json").is_file() {
            project_root.join("npm-shrinkwrap.json")
        } else {
            return None;
        };

        Some(DetectResult {
            ecosystem: self.ecosystem(),
            lockfile,
            install_root: save_path.to_path_buf(),
        })
    }

    fn enumerate(&self, detection: &DetectResult) -> Result<Vec<ResolvedPackage>> {
        let lockfile_bytes = fs::read(&detection.lockfile)
            .with_context(|| format!("Failed to read {}", detection.lockfile.display()))?;
        let lockfile: Value =
            serde_json::from_slice(&lockfile_bytes).context("Failed to parse npm lockfile")?;
        let packages = lockfile
            .get("packages")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("npm package CAS requires package-lock v2/v3 packages map"))?;

        let mut resolved = Vec::new();
        for (lock_path, package) in packages {
            if lock_path.is_empty() || !lock_path.starts_with("node_modules/") {
                continue;
            }
            if package
                .get("link")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(anyhow!(
                    "npm package CAS does not restore linked/workspace package {}",
                    lock_path
                ));
            }

            let Some(install_path) = install_path_from_lock_path(lock_path) else {
                continue;
            };
            let absolute = crate::cas_file::safe_join_path(&detection.install_root, &install_path)?;
            let metadata = match fs::symlink_metadata(&absolute) {
                Ok(metadata) => metadata,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("Failed to inspect {}", absolute.display()));
                }
            };
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "npm package CAS does not restore symlinked package {}",
                    lock_path
                ));
            }
            if !metadata.is_dir() {
                continue;
            }

            let package_name = package_name(package, &absolute, lock_path);
            let version = package
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let lock_integrity = package
                .get("integrity")
                .and_then(Value::as_str)
                .map(str::to_string);

            resolved.push(ResolvedPackage {
                package_key: format!("npm:{package_name}@{version}:{lock_path}"),
                no_integrity: lock_integrity.is_none(),
                lock_integrity,
                install_paths: vec![install_path],
            });
        }

        resolved.sort_by(|left, right| left.package_key.cmp(&right.package_key));
        Ok(resolved)
    }

    fn compatibility(
        &self,
        detection: &DetectResult,
    ) -> Result<Option<crate::cache::cas_pkg::PkgCompatibility>> {
        let lockfile_digest = crate::cache::cas_pkg::digest_file(&detection.lockfile).ok();
        let platform = crate::platform::Platform::detect()
            .ok()
            .map(|platform| platform.to_tag_suffix());

        Ok(Some(crate::cache::cas_pkg::PkgCompatibility {
            runtime: "node".to_string(),
            runtime_abi: None,
            platform,
            lockfile_digest,
        }))
    }
}

fn install_path_from_lock_path(lock_path: &str) -> Option<PathBuf> {
    lock_path
        .strip_prefix("node_modules/")
        .filter(|relative| !relative.is_empty())
        .map(PathBuf::from)
}

fn package_name(package: &Value, absolute: &Path, lock_path: &str) -> String {
    package
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| package_name_from_package_json(absolute))
        .unwrap_or_else(|| package_name_from_lock_path(lock_path))
}

fn package_name_from_package_json(package_dir: &Path) -> Option<String> {
    let package_json = fs::read(package_dir.join("package.json")).ok()?;
    let package: Value = serde_json::from_slice(&package_json).ok()?;
    package
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn package_name_from_lock_path(lock_path: &str) -> String {
    let relative = lock_path
        .strip_prefix("node_modules/")
        .unwrap_or(lock_path)
        .rsplit("/node_modules/")
        .next()
        .unwrap_or(lock_path);
    let parts = relative.split('/').collect::<Vec<_>>();
    if parts.first().is_some_and(|part| part.starts_with('@')) && parts.len() >= 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        parts.first().copied().unwrap_or(relative).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_node_modules_and_enumerates_package_lock_packages() {
        let temp_dir = tempfile::tempdir().unwrap();
        let project = temp_dir.path();
        let node_modules = project.join("node_modules");
        fs::create_dir_all(node_modules.join("lodash")).unwrap();
        fs::create_dir_all(node_modules.join("@scope/pkg")).unwrap();
        fs::write(
            project.join("package-lock.json"),
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "integrity": "sha512-lodash"
                    },
                    "node_modules/@scope/pkg": {
                        "version": "1.2.3",
                        "integrity": "sha512-scoped"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            node_modules.join("lodash/package.json"),
            r#"{"name":"lodash","version":"4.17.21"}"#,
        )
        .unwrap();
        fs::write(
            node_modules.join("@scope/pkg/package.json"),
            r#"{"name":"@scope/pkg","version":"1.2.3"}"#,
        )
        .unwrap();

        let adapter = NpmAdapter;
        let detection = adapter.detect(&node_modules).unwrap();
        let packages = adapter.enumerate(&detection).unwrap();

        assert_eq!(packages.len(), 2);
        assert!(
            packages
                .iter()
                .any(|package| package.package_key == "npm:lodash@4.17.21:node_modules/lodash")
        );
        assert!(packages.iter().any(|package| {
            package.package_key == "npm:@scope/pkg@1.2.3:node_modules/@scope/pkg"
        }));
    }

    #[test]
    fn rejects_linked_packages_for_archive_fallback() {
        let temp_dir = tempfile::tempdir().unwrap();
        let project = temp_dir.path();
        let node_modules = project.join("node_modules");
        fs::create_dir_all(node_modules.join("workspace-package")).unwrap();
        fs::write(
            project.join("package-lock.json"),
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/workspace-package": {
                        "version": "1.0.0",
                        "link": true
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let adapter = NpmAdapter;
        let detection = adapter.detect(&node_modules).unwrap();
        let error = adapter.enumerate(&detection).unwrap_err();

        assert!(error.to_string().contains("linked/workspace package"));
    }
}
