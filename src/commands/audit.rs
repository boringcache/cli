use crate::command_support::parse_save_format;
use crate::project_config::{
    RepoConfig, RepoEntryConfig, RepoProfileConfig, built_in_default_tag, canonical_entry_id,
    discover, normalize_profile_name,
};
use anyhow::{Context, Result};
use jwalk::WalkDir;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_AUDIT_FILE_BYTES: u64 = 512 * 1024;
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".next",
    "dist",
    "tmp",
    ".direnv",
    ".mise",
    "vendor",
];

#[derive(Debug, Clone, Serialize)]
struct AuditReport {
    root: String,
    config_path: String,
    scanned_paths: Vec<String>,
    wrote: bool,
    scanned_files: usize,
    discovered_entries: Vec<AuditEntryReport>,
    discovered_profiles: Vec<AuditProfileReport>,
    skipped_dynamic_pairs: usize,
    skipped_placeholder_pairs: usize,
    skipped_configured_entries: usize,
    skipped_configured_profiles: usize,
}

#[derive(Debug, Clone, Serialize)]
struct AuditEntryReport {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_path: Option<String>,
    sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AuditProfileReport {
    name: String,
    entries: Vec<String>,
    sources: Vec<String>,
}

#[derive(Debug, Clone)]
struct ScanReport {
    entries: BTreeMap<String, SuggestedEntry>,
    profiles: BTreeMap<String, SuggestedProfile>,
    scanned_files: usize,
    skipped_dynamic_pairs: usize,
    skipped_placeholder_pairs: usize,
}

#[derive(Debug, Clone)]
struct SuggestedEntry {
    config: RepoEntryConfig,
    sources: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct SuggestedProfile {
    entries: BTreeSet<String>,
    sources: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct ManualRunInvocation {
    tag_path_pairs: Vec<String>,
    command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipReason {
    Dynamic,
    Placeholder,
}

#[derive(Debug, Clone)]
pub struct RepoConfigWriteResult {
    pub config_path: PathBuf,
    pub wrote: bool,
    pub added_entries: usize,
    pub added_profiles: usize,
}

pub async fn execute(path: Option<String>, write: bool, json_output: bool) -> Result<()> {
    execute_with_paths(path, Vec::new(), write, json_output).await
}

fn discover_repo_root(start_dir: &Path) -> Result<PathBuf> {
    if let Some(loaded) = discover(start_dir)? {
        return Ok(loaded.root);
    }

    for directory in start_dir.ancestors() {
        if directory.join(".git").exists() {
            return Ok(directory.to_path_buf());
        }
    }

    Ok(start_dir.to_path_buf())
}

fn default_scan_paths(root: &Path) -> Vec<PathBuf> {
    ["images", "scripts"]
        .iter()
        .map(|path| root.join(path))
        .filter(|path| path.exists())
        .collect()
}

fn resolve_audit_root(root: Option<&Path>) -> Result<PathBuf> {
    let requested_root = match root {
        Some(value) => value.to_path_buf(),
        None => std::env::current_dir().context("Failed to read current directory")?,
    };
    let start_dir = if requested_root.is_dir() {
        requested_root
    } else {
        requested_root
            .parent()
            .map(Path::to_path_buf)
            .context("Audit path must point to a directory or a file inside the repo")?
    };
    discover_repo_root(&start_dir)
}

fn audit_repo(
    root: Option<&Path>,
    scan_paths: &[String],
    write: bool,
) -> Result<(AuditReport, RepoConfigWriteResult)> {
    let root = resolve_audit_root(root)?;
    let existing = discover(&root)?;
    let config_path = existing
        .as_ref()
        .map(|loaded| loaded.path.clone())
        .unwrap_or_else(|| root.join(".boringcache.toml"));
    let mut config = existing
        .as_ref()
        .map(|loaded| loaded.config.clone())
        .unwrap_or_default();
    let resolved_scan_paths = resolve_scan_paths(&root, scan_paths);
    let scan = scan_repo(&resolved_scan_paths)?;
    let merge = merge_suggestions(&mut config, &scan);

    let added_entries = merge.added_entries.len();
    let added_profiles = merge.added_profiles.len();
    let mut wrote = false;
    if write && (added_entries > 0 || added_profiles > 0) {
        let contents = toml::to_string_pretty(&config).context("Failed to render repo config")?;
        std::fs::write(&config_path, contents)
            .with_context(|| format!("Failed to write {}", config_path.display()))?;
        wrote = true;
    }

    let report = AuditReport {
        root: root.display().to_string(),
        config_path: config_path.display().to_string(),
        scanned_paths: resolved_scan_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        wrote,
        scanned_files: scan.scanned_files,
        discovered_entries: scan
            .entries
            .iter()
            .map(|(id, entry)| AuditEntryReport {
                id: id.clone(),
                tag: entry.config.tag.clone(),
                default_path: entry.config.default_path.clone(),
                sources: entry.sources.iter().cloned().collect(),
            })
            .collect(),
        discovered_profiles: scan
            .profiles
            .iter()
            .map(|(name, profile)| AuditProfileReport {
                name: name.clone(),
                entries: profile.entries.iter().cloned().collect(),
                sources: profile.sources.iter().cloned().collect(),
            })
            .collect(),
        skipped_dynamic_pairs: scan.skipped_dynamic_pairs,
        skipped_placeholder_pairs: scan.skipped_placeholder_pairs,
        skipped_configured_entries: merge.skipped_configured_entries,
        skipped_configured_profiles: merge.skipped_configured_profiles,
    };
    let write_result = RepoConfigWriteResult {
        config_path,
        wrote,
        added_entries,
        added_profiles,
    };

    Ok((report, write_result))
}

pub fn write_repo_config_for_paths(
    root: Option<&Path>,
    scan_paths: &[String],
) -> Result<RepoConfigWriteResult> {
    let (_, result) = audit_repo(root, scan_paths, true)?;
    Ok(result)
}

pub async fn execute_with_paths(
    root: Option<String>,
    scan_paths: Vec<String>,
    write: bool,
    json_output: bool,
) -> Result<()> {
    let requested_root = root.map(PathBuf::from);
    let (report, _) = audit_repo(requested_root.as_deref(), &scan_paths, write)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    render_report(&report, write);
    Ok(())
}

fn resolve_scan_paths(root: &Path, scan_paths: &[String]) -> Vec<PathBuf> {
    if scan_paths.is_empty() {
        return default_scan_paths(root);
    }

    scan_paths
        .iter()
        .map(|path| {
            let candidate = PathBuf::from(path);
            if candidate.is_absolute() {
                candidate
            } else {
                root.join(candidate)
            }
        })
        .collect()
}

fn scan_repo(scan_paths: &[PathBuf]) -> Result<ScanReport> {
    let mut report = ScanReport {
        entries: BTreeMap::new(),
        profiles: BTreeMap::new(),
        scanned_files: 0,
        skipped_dynamic_pairs: 0,
        skipped_placeholder_pairs: 0,
    };

    for file_path in candidate_files(scan_paths)? {
        report.scanned_files += 1;
        scan_file(&file_path, &mut report)?;
    }

    Ok(report)
}

fn candidate_files(scan_paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for base in scan_paths {
        if !base.exists() {
            continue;
        }

        if base.is_file() {
            if is_audit_candidate(base) {
                files.push(base.to_path_buf());
            }
            continue;
        }

        for entry in WalkDir::new(base) {
            let entry = entry?;
            if entry.file_type().is_dir()
                && entry
                    .file_name
                    .to_str()
                    .is_some_and(|name| SKIP_DIRS.contains(&name))
            {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            if is_audit_candidate(&path) {
                files.push(path.to_path_buf());
            }
        }
    }

    files.sort();
    Ok(files)
}

fn is_audit_candidate(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if file_name.contains("Dockerfile") {
        return true;
    }

    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| {
            ext.eq_ignore_ascii_case("sh")
                || ext.eq_ignore_ascii_case("yml")
                || ext.eq_ignore_ascii_case("yaml")
        })
}

fn scan_file(path: &Path, report: &mut ScanReport) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for {}", path.display()))?;
    if metadata.len() > MAX_AUDIT_FILE_BYTES {
        return Ok(());
    }

    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut in_multiline_double_quote = false;
    for (line_number, line) in logical_lines(&contents) {
        let trimmed = line.trim();
        let quote_count = count_unescaped_double_quotes(trimmed);
        if in_multiline_double_quote {
            if quote_count % 2 == 1 {
                in_multiline_double_quote = false;
            }
            continue;
        }
        if quote_count % 2 == 1 && !trimmed.starts_with("boringcache ") {
            in_multiline_double_quote = true;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || !trimmed.contains("boringcache") {
            continue;
        }

        let Some(invocation) = parse_manual_run_invocation(trimmed) else {
            continue;
        };

        let profile_name = suggested_profile_name(&invocation.command);
        let mut profile_entries = BTreeSet::new();

        for pair in invocation.tag_path_pairs {
            let spec = match parse_save_format(&pair) {
                Ok(spec) => spec,
                Err(_) => continue,
            };

            match classify_skip(&spec.tag, &spec.path) {
                Some(SkipReason::Dynamic) => {
                    report.skipped_dynamic_pairs += 1;
                    continue;
                }
                Some(SkipReason::Placeholder) => {
                    report.skipped_placeholder_pairs += 1;
                    continue;
                }
                None => {}
            }

            let suggestion = suggest_entry(&spec.tag, &spec.path);
            let source = format!("{}:{}", path.display(), line_number);
            report
                .entries
                .entry(suggestion.0.clone())
                .and_modify(|entry| {
                    merge_entry_config(&mut entry.config, &suggestion.1);
                    entry.sources.insert(source.clone());
                })
                .or_insert_with(|| SuggestedEntry {
                    config: suggestion.1,
                    sources: BTreeSet::from([source.clone()]),
                });
            profile_entries.insert(suggestion.0);
        }

        if let Some(name) = profile_name
            && !profile_entries.is_empty()
        {
            let source = format!("{}:{}", path.display(), line_number);
            report
                .profiles
                .entry(name)
                .and_modify(|profile| {
                    profile.entries.extend(profile_entries.clone());
                    profile.sources.insert(source.clone());
                })
                .or_insert_with(|| SuggestedProfile {
                    entries: profile_entries,
                    sources: BTreeSet::from([source]),
                });
        }
    }

    Ok(())
}

fn count_unescaped_double_quotes(value: &str) -> usize {
    let mut count = 0usize;
    let mut escaped = false;

    for ch in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            count += 1;
        }
    }

    count
}

fn logical_lines(contents: &str) -> Vec<(usize, String)> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut start_line = 1usize;

    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let trimmed_end = raw_line.trim_end();
        if current.is_empty() {
            start_line = line_number;
            current.push_str(trimmed_end.trim());
        } else {
            current.push(' ');
            current.push_str(trimmed_end.trim());
        }

        if trimmed_end.ends_with('\\') {
            current.pop();
            while current.ends_with(' ') {
                current.pop();
            }
            continue;
        }

        lines.push((start_line, current.trim().to_string()));
        current.clear();
    }

    if !current.trim().is_empty() {
        lines.push((start_line, current.trim().to_string()));
    }

    lines
}

fn parse_manual_run_invocation(line: &str) -> Option<ManualRunInvocation> {
    let tokens = shell_split(line);
    let run_index = tokens
        .windows(2)
        .position(|window| is_boringcache_binary(&window[0]) && window[1] == "run")?;

    let mut positionals = Vec::new();
    let mut command = Vec::new();
    let mut seen_double_dash = false;
    let mut seen_planned_flag = false;
    let mut index = run_index + 2;

    while index < tokens.len() {
        let token = &tokens[index];
        if seen_double_dash {
            command.push(token.clone());
            index += 1;
            continue;
        }

        if token == "--" {
            seen_double_dash = true;
            index += 1;
            continue;
        }

        if matches!(token.as_str(), "--profile" | "--entry") {
            seen_planned_flag = true;
            index += 2;
            continue;
        }
        if token.starts_with("--profile=") || token.starts_with("--entry=") {
            return None;
        }
        if matches!(
            token.as_str(),
            "--proxy" | "--recipient" | "--identity" | "--metadata-hint" | "--port" | "--host"
        ) {
            index += 2;
            continue;
        }
        if token.starts_with("--") {
            index += 1;
            continue;
        }

        positionals.push(token.clone());
        index += 1;
    }

    if seen_planned_flag {
        return None;
    }

    let tag_path_pairs = if positionals.len() == 1 && positionals[0].contains(':') {
        positionals[0]
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    } else if positionals.len() >= 2 && positionals[1].contains(':') {
        positionals[1]
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    if tag_path_pairs.is_empty() {
        return None;
    }

    Some(ManualRunInvocation {
        tag_path_pairs,
        command,
    })
}

fn shell_split(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            Some('"') => {
                if ch == '"' {
                    quote = None;
                } else if ch == '\\' {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                } else {
                    current.push(ch);
                }
            }
            Some(_) => {}
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '\\' => {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                }
                _ if ch.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(ch),
            },
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn is_boringcache_binary(token: &str) -> bool {
    Path::new(token)
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value == "boringcache")
}

fn classify_skip(tag: &str, path: &str) -> Option<SkipReason> {
    if (tag == "tag" && path == "path")
        || tag == "<tag>"
        || path == "<path>"
        || tag == "example-tag"
        || path == "example-path"
    {
        return Some(SkipReason::Placeholder);
    }

    if [tag, path].iter().any(|value| {
        value.contains('$')
            || value.contains("{{")
            || value.contains("}}")
            || value.contains("%(")
            || value.contains("<%")
    }) {
        return Some(SkipReason::Dynamic);
    }

    None
}

fn suggest_entry(tag: &str, path: &str) -> (String, RepoEntryConfig) {
    if let Some(entry_id) = built_in_entry_id(tag, path) {
        let mut config = RepoEntryConfig::default();
        if built_in_default_tag(&entry_id).is_some_and(|default_tag| default_tag != tag) {
            config.tag = Some(tag.to_string());
        }
        if entry_id == "mise" && path == "/mise/installs" {
            config.default_path = Some(path.to_string());
        }
        return (entry_id, config);
    }

    (
        sanitize_entry_id(tag),
        RepoEntryConfig {
            tag: Some(tag.to_string()),
            default_path: Some(path.to_string()),
            ..RepoEntryConfig::default()
        },
    )
}

fn built_in_entry_id(tag: &str, path: &str) -> Option<String> {
    let canonical_tag = canonical_entry_id(tag);
    if built_in_default_tag(&canonical_tag).is_some() {
        return Some(canonical_tag);
    }

    let normalized_path = path.trim_end_matches('/').replace('\\', "/");
    if normalized_path.ends_with("/vendor/bundle") || normalized_path == "vendor/bundle" {
        return Some("bundler".to_string());
    }
    if normalized_path.ends_with("/usr/local/bundle") || normalized_path == "/usr/local/bundle" {
        return Some("bundler".to_string());
    }
    if normalized_path.ends_with("/tmp/cache/bootsnap")
        || normalized_path.ends_with("/tmp/bootsnap")
    {
        return Some("bootsnap".to_string());
    }
    if normalized_path.ends_with("/mise/installs")
        || normalized_path.ends_with("/.local/share/mise/installs")
    {
        return Some("mise".to_string());
    }
    if normalized_path.ends_with("/node_modules") || normalized_path == "node_modules" {
        return Some("node_modules".to_string());
    }
    if normalized_path.ends_with("/.pnpm-store") || normalized_path == ".pnpm-store" {
        return Some("pnpm-store".to_string());
    }
    if normalized_path.ends_with("/.yarn-cache") || normalized_path == ".yarn-cache" {
        return Some("yarn-cache".to_string());
    }
    if normalized_path.ends_with("/.npm-cache") || normalized_path == ".npm-cache" {
        return Some("npm-cache".to_string());
    }
    if normalized_path.ends_with("/.uv-cache") || normalized_path == ".uv-cache" {
        return Some("uv-cache".to_string());
    }

    None
}

fn sanitize_entry_id(tag: &str) -> String {
    let mut value = String::new();
    let mut previous_dash = false;

    for ch in tag.chars().map(|ch| ch.to_ascii_lowercase()) {
        if ch.is_ascii_alphanumeric() {
            value.push(ch);
            previous_dash = false;
        } else if !previous_dash {
            value.push('-');
            previous_dash = true;
        }
    }

    value.trim_matches('-').to_string()
}

fn suggested_profile_name(command: &[String]) -> Option<String> {
    let binary = command.first()?;
    let command_name = Path::new(binary)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(binary.as_str())
        .to_ascii_lowercase();
    let subcommand = command
        .get(1)
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    match (command_name.as_str(), subcommand.as_str()) {
        ("bundle", "install") => Some("bundle-install".to_string()),
        ("mise", "install") => Some("mise-install".to_string()),
        ("yarn", "install") => Some("yarn-install".to_string()),
        ("npm", "ci") => Some("npm-ci".to_string()),
        ("npm", "install") => Some("npm-install".to_string()),
        ("pnpm", "install") | ("pnpm", "i") => Some("pnpm-install".to_string()),
        ("uv", "sync") => Some("uv-sync".to_string()),
        _ => None,
    }
}

fn merge_entry_config(existing: &mut RepoEntryConfig, suggested: &RepoEntryConfig) {
    if existing.tag.is_none() {
        existing.tag = suggested.tag.clone();
    }
    if existing.path.is_none() {
        existing.path = suggested.path.clone();
    }
    if existing.path_env.is_none() {
        existing.path_env = suggested.path_env.clone();
    }
    if existing.default_path.is_none() {
        existing.default_path = suggested.default_path.clone();
    }
}

struct MergeReport {
    added_entries: BTreeMap<String, SuggestedEntry>,
    added_profiles: BTreeMap<String, SuggestedProfile>,
    skipped_configured_entries: usize,
    skipped_configured_profiles: usize,
}

fn merge_suggestions(config: &mut RepoConfig, scan: &ScanReport) -> MergeReport {
    let mut added_entries = BTreeMap::new();
    let mut added_profiles = BTreeMap::new();
    let mut skipped_configured_entries = 0usize;
    let mut skipped_configured_profiles = 0usize;

    for (entry_id, suggestion) in &scan.entries {
        let canonical = canonical_entry_id(entry_id);
        if config
            .entries
            .keys()
            .any(|key| canonical_entry_id(key) == canonical)
        {
            skipped_configured_entries += 1;
            continue;
        }
        if suggestion.config == RepoEntryConfig::default() {
            continue;
        }

        config
            .entries
            .insert(entry_id.clone(), suggestion.config.clone());
        added_entries.insert(entry_id.clone(), suggestion.clone());
    }

    for (profile_name, suggestion) in &scan.profiles {
        let normalized = normalize_profile_name(profile_name);
        if config
            .profiles
            .keys()
            .any(|key| normalize_profile_name(key) == normalized)
        {
            skipped_configured_profiles += 1;
            continue;
        }

        let mut entries = suggestion.entries.iter().cloned().collect::<Vec<_>>();
        entries.sort();
        config.profiles.insert(
            profile_name.clone(),
            RepoProfileConfig {
                entries: entries.clone(),
            },
        );
        added_profiles.insert(profile_name.clone(), suggestion.clone());
    }

    MergeReport {
        added_entries,
        added_profiles,
        skipped_configured_entries,
        skipped_configured_profiles,
    }
}

fn render_report(report: &AuditReport, write_requested: bool) {
    crate::ui::blank_line();
    println!("Repo Audit");
    crate::commands::status::print_field("Root", &report.root);
    crate::commands::status::print_field("Config", &report.config_path);
    crate::commands::status::print_field("Scope", &report.scanned_paths.join(", "));
    crate::commands::status::print_field("Scanned files", &report.scanned_files.to_string());
    crate::ui::blank_line();

    println!("Discovered entries");
    if report.discovered_entries.is_empty() {
        println!("  none");
    } else {
        for entry in &report.discovered_entries {
            let mut parts = vec![entry.id.clone()];
            if let Some(tag) = &entry.tag {
                parts.push(format!("tag={tag}"));
            }
            if let Some(default_path) = &entry.default_path {
                parts.push(format!("default_path={default_path}"));
            }
            println!("  {}", parts.join("  "));
            for source in &entry.sources {
                println!("    from {source}");
            }
        }
    }
    crate::ui::blank_line();

    println!("Discovered profiles");
    if report.discovered_profiles.is_empty() {
        println!("  none");
    } else {
        for profile in &report.discovered_profiles {
            println!("  {}  entries={}", profile.name, profile.entries.join(","));
            for source in &profile.sources {
                println!("    from {source}");
            }
        }
    }
    crate::ui::blank_line();

    println!("Skipped");
    println!("  dynamic pairs: {}", report.skipped_dynamic_pairs);
    println!("  placeholder pairs: {}", report.skipped_placeholder_pairs);
    println!(
        "  already configured entries: {}",
        report.skipped_configured_entries
    );
    println!(
        "  already configured profiles: {}",
        report.skipped_configured_profiles
    );

    if report.wrote {
        crate::ui::blank_line();
        crate::ui::info(&format!("Wrote {}", report.config_path));
    } else if write_requested {
        crate::ui::blank_line();
        crate::ui::info("No new repo config entries were needed.");
    } else {
        crate::ui::blank_line();
        println!(
            "Run `boringcache audit --write` to merge these suggestions into the repo config."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manual_run_with_workspace_and_command() {
        let invocation = parse_manual_run_invocation(
            "boringcache run my-org/my-app bundler:/usr/local/bundle --no-platform -- bundle install",
        )
        .unwrap();

        assert_eq!(invocation.tag_path_pairs, vec!["bundler:/usr/local/bundle"]);
        assert_eq!(invocation.command, vec!["bundle", "install"]);
    }

    #[test]
    fn skips_placeholder_pairs() {
        assert_eq!(classify_skip("tag", "path"), Some(SkipReason::Placeholder));
        assert_eq!(classify_skip("bundler", "/usr/local/bundle"), None);
    }

    #[test]
    fn suggests_mise_default_path_override() {
        let (entry_id, config) = suggest_entry("mise-installs", "/mise/installs");
        assert_eq!(entry_id, "mise");
        assert_eq!(config.default_path.as_deref(), Some("/mise/installs"));
    }
}
