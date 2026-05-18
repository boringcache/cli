use super::{DetectResult, PkgAdapter, ResolvedPackage};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct BundlerAdapter;

impl PkgAdapter for BundlerAdapter {
    fn ecosystem(&self) -> &'static str {
        "bundler"
    }

    fn detect(&self, save_path: &Path) -> Option<DetectResult> {
        if !save_path.is_dir() || save_path.file_name()?.to_str()? != "bundle" {
            return None;
        }

        let vendor_dir = save_path.parent()?;
        if vendor_dir.file_name()?.to_str()? != "vendor" {
            return None;
        }
        let project_root = vendor_dir.parent()?;
        let lockfile = project_root.join("Gemfile.lock");
        if !lockfile.is_file() || !save_path.join("ruby").is_dir() {
            return None;
        }

        Some(DetectResult {
            ecosystem: self.ecosystem(),
            lockfile,
            install_root: save_path.to_path_buf(),
        })
    }

    fn enumerate(&self, detection: &DetectResult) -> Result<Vec<ResolvedPackage>> {
        let ruby_root = detection.install_root.join("ruby");
        let mut packages = Vec::new();

        for abi_dir in sorted_child_dirs(&ruby_root)? {
            let abi = abi_dir
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let gems_dir = abi_dir.join("gems");
            if !gems_dir.is_dir() {
                continue;
            }

            for gem_dir in sorted_child_dirs(&gems_dir)? {
                let gem_name = gem_dir
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if gem_name.is_empty() {
                    continue;
                }

                let mut install_paths = BTreeSet::new();
                insert_relative(&detection.install_root, &gem_dir, &mut install_paths)?;

                let specification = abi_dir
                    .join("specifications")
                    .join(format!("{gem_name}.gemspec"));
                if specification.is_file() {
                    insert_relative(&detection.install_root, &specification, &mut install_paths)?;
                }

                let cache_file = abi_dir.join("cache").join(format!("{gem_name}.gem"));
                if cache_file.is_file() {
                    insert_relative(&detection.install_root, &cache_file, &mut install_paths)?;
                }

                let build_info = abi_dir.join("build_info").join(format!("{gem_name}.info"));
                if build_info.is_file() {
                    insert_relative(&detection.install_root, &build_info, &mut install_paths)?;
                }

                let extensions_root = abi_dir.join("extensions");
                if extensions_root.is_dir() {
                    for extension_dir in matching_extension_dirs(&extensions_root, &gem_name)? {
                        insert_relative(
                            &detection.install_root,
                            &extension_dir,
                            &mut install_paths,
                        )?;
                    }
                }

                packages.push(ResolvedPackage {
                    package_key: format!("bundler:{abi}:{gem_name}"),
                    lock_integrity: None,
                    install_paths: install_paths.into_iter().collect(),
                    no_integrity: true,
                });
            }
        }

        packages.sort_by(|left, right| left.package_key.cmp(&right.package_key));
        Ok(packages)
    }

    fn compatibility(
        &self,
        detection: &DetectResult,
    ) -> Result<Option<crate::cache::cas_pkg::PkgCompatibility>> {
        let runtime_abi = first_ruby_abi(&detection.install_root);
        let lockfile_digest = crate::cache::cas_pkg::digest_file(&detection.lockfile).ok();
        let platform = crate::platform::Platform::detect()
            .ok()
            .map(|platform| platform.to_tag_suffix());

        Ok(Some(crate::cache::cas_pkg::PkgCompatibility {
            runtime: "ruby".to_string(),
            runtime_abi,
            platform,
            lockfile_digest,
        }))
    }
}

fn sorted_child_dirs(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.is_dir() {
        return Ok(Vec::new());
    }

    let mut children = fs::read_dir(path)
        .with_context(|| format!("Failed to read directory {}", path.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    children.sort_by(|left, right| {
        crate::cache::cas_pkg::normalize_path_for_pointer(left)
            .cmp(&crate::cache::cas_pkg::normalize_path_for_pointer(right))
    });
    Ok(children)
}

fn matching_extension_dirs(root: &Path, gem_name: &str) -> Result<Vec<PathBuf>> {
    let mut matches = Vec::new();
    collect_matching_extension_dirs(root, gem_name, &mut matches)?;
    matches.sort_by(|left, right| {
        crate::cache::cas_pkg::normalize_path_for_pointer(left)
            .cmp(&crate::cache::cas_pkg::normalize_path_for_pointer(right))
    });
    Ok(matches)
}

fn collect_matching_extension_dirs(
    path: &Path,
    gem_name: &str,
    matches: &mut Vec<PathBuf>,
) -> Result<()> {
    if path
        .file_name()
        .map(|name| name == gem_name)
        .unwrap_or(false)
        && path.is_dir()
    {
        matches.push(path.to_path_buf());
        return Ok(());
    }

    for child in sorted_child_dirs(path)? {
        collect_matching_extension_dirs(&child, gem_name, matches)?;
    }
    Ok(())
}

fn insert_relative(root: &Path, absolute: &Path, paths: &mut BTreeSet<PathBuf>) -> Result<()> {
    let relative = absolute
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", absolute.display(), root.display()))?;
    paths.insert(relative.to_path_buf());
    Ok(())
}

fn first_ruby_abi(install_root: &Path) -> Option<String> {
    let ruby_root = install_root.join("ruby");
    sorted_child_dirs(&ruby_root)
        .ok()?
        .first()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_vendor_bundle_and_enumerates_gem_closure() {
        let temp_dir = tempfile::tempdir().unwrap();
        let project = temp_dir.path();
        let bundle = project.join("vendor/bundle");
        fs::create_dir_all(bundle.join("ruby/3.4.0/gems/json-2.7.2/lib")).unwrap();
        fs::create_dir_all(bundle.join("ruby/3.4.0/specifications")).unwrap();
        fs::create_dir_all(bundle.join("ruby/3.4.0/cache")).unwrap();
        fs::create_dir_all(bundle.join("ruby/3.4.0/extensions/arm64-darwin-24/3.4.0/json-2.7.2"))
            .unwrap();
        fs::write(project.join("Gemfile.lock"), "GEM\n").unwrap();
        fs::write(
            bundle.join("ruby/3.4.0/gems/json-2.7.2/lib/json.rb"),
            "module JSON; end\n",
        )
        .unwrap();
        fs::write(
            bundle.join("ruby/3.4.0/specifications/json-2.7.2.gemspec"),
            "Gem::Specification.new\n",
        )
        .unwrap();
        fs::write(bundle.join("ruby/3.4.0/cache/json-2.7.2.gem"), "gem").unwrap();
        fs::write(
            bundle.join("ruby/3.4.0/extensions/arm64-darwin-24/3.4.0/json-2.7.2/json.bundle"),
            "native",
        )
        .unwrap();

        let adapter = BundlerAdapter;
        let detection = adapter.detect(&bundle).unwrap();
        let packages = adapter.enumerate(&detection).unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].package_key, "bundler:3.4.0:json-2.7.2");
        assert!(
            packages[0]
                .install_paths
                .contains(&PathBuf::from("ruby/3.4.0/gems/json-2.7.2"))
        );
        assert!(packages[0].install_paths.contains(&PathBuf::from(
            "ruby/3.4.0/specifications/json-2.7.2.gemspec"
        )));
        assert!(packages[0].install_paths.contains(&PathBuf::from(
            "ruby/3.4.0/extensions/arm64-darwin-24/3.4.0/json-2.7.2"
        )));
    }
}
