#[derive(Debug, Clone, clap::Args)]
pub struct AdapterArgs {
    #[arg(long, help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(long, help = "Proxy cache tag")]
    pub tag: Option<String>,

    #[arg(short, long, help = "Port to bind and advertise (default: 5000)")]
    pub port: Option<u16>,

    #[arg(long, help = "Bind host for the local proxy (default: 127.0.0.1)")]
    pub host: Option<String>,

    #[arg(
        long = "endpoint-host",
        help = "Advertised host for wrapped clients when it differs from --host"
    )]
    pub endpoint_host: Option<String>,

    #[arg(long, help = "Disable automatic platform suffix for cache tags")]
    pub no_platform: bool,

    #[arg(long, help = "Disable automatic git-based tag suffixing")]
    pub no_git: bool,

    #[arg(long, help = "Run proxy reads only and skip cache writes")]
    pub read_only: bool,

    #[arg(
        long,
        help = "Exit with error if cache operations encounter backend failures"
    )]
    pub fail_on_cache_error: bool,

    #[arg(
        long,
        value_name = "KEY=VALUE",
        help = "Attach low-cardinality metadata hints to proxy sessions (repeatable)"
    )]
    pub metadata_hint: Vec<String>,

    #[arg(
        long,
        value_name = "NAME@REFERENCE",
        help = "Resolve selected OCI repository refs during warm proxy startup (repeatable)"
    )]
    pub oci_prefetch_ref: Vec<String>,

    #[arg(
        long,
        hide = true,
        default_value = "metadata-only",
        value_parser = ["metadata-only", "bodies-before-ready", "bodies-background"],
        help = "Expert: OCI/Docker startup hydration policy for selected refs"
    )]
    pub oci_hydration: String,

    #[arg(long, help = "Skip startup warming and serve cache reads on demand")]
    pub on_demand: bool,

    #[arg(
        long,
        value_name = "ENTRY",
        value_delimiter = ',',
        help = "Project or built-in cache entry/entries to resolve (repeatable)"
    )]
    pub entry: Vec<String>,

    #[arg(
        long,
        value_name = "PROFILE",
        value_delimiter = ',',
        help = "Project cache profile(s) from .boringcache.toml (repeatable)"
    )]
    pub profile: Vec<String>,

    #[arg(long, help = "Skip restore phase for archive entries")]
    pub skip_restore: bool,

    #[arg(long, help = "Skip save phase for archive entries")]
    pub skip_save: bool,

    #[arg(long, help = "Run save phase even if command exits non-zero")]
    pub save_on_failure: bool,

    #[arg(long, help = "Docker cache export mode (default: max)")]
    pub cache_mode: Option<String>,

    #[arg(long, help = "Docker registry cache tag (default: buildcache)")]
    pub cache_ref_tag: Option<String>,

    #[arg(
        long = "cache-run-ref-tag",
        hide = true,
        help = "Expert: immutable Docker registry cache ref tag for this run"
    )]
    pub cache_run_ref_tag: Option<String>,

    #[arg(
        long = "cache-from-ref-tag",
        value_name = "TAG",
        hide = true,
        help = "Expert: Docker registry cache ref tag to import (repeatable)"
    )]
    pub cache_from_ref_tag: Vec<String>,

    #[arg(
        long = "cache-promote-ref-tag",
        value_name = "TAG",
        hide = true,
        help = "Expert: Docker registry cache alias ref tag to promote after export (repeatable)"
    )]
    pub cache_promote_ref_tag: Vec<String>,

    #[arg(
        long = "bazelrc-line",
        value_name = "LINE",
        hide = true,
        help = "Action integration: extra line to include in generated Bazel setup"
    )]
    pub bazelrc_line: Vec<String>,

    #[arg(
        long = "gradle-home",
        value_name = "PATH",
        hide = true,
        help = "Action integration: Gradle user home for generated setup"
    )]
    pub gradle_home: Option<String>,

    #[arg(
        long = "no-gradle-build-cache-property",
        hide = true,
        help = "Action integration: do not append org.gradle.caching=true"
    )]
    pub no_gradle_build_cache_property: bool,

    #[arg(
        long = "maven-local-repo",
        value_name = "PATH",
        hide = true,
        help = "Action integration: local Maven repository directory to create"
    )]
    pub maven_local_repo: Option<String>,

    #[arg(
        long = "maven-extensions-path",
        value_name = "PATH",
        hide = true,
        help = "Action integration: Maven extensions.xml path for generated setup"
    )]
    pub maven_extensions_path: Option<String>,

    #[arg(
        long = "maven-build-cache-config-path",
        value_name = "PATH",
        hide = true,
        help = "Action integration: Maven build-cache config path for generated setup"
    )]
    pub maven_build_cache_config_path: Option<String>,

    #[arg(
        long = "maven-build-cache-extension-version",
        value_name = "VERSION",
        hide = true,
        help = "Action integration: Maven build-cache extension version for generated setup"
    )]
    pub maven_build_cache_extension_version: Option<String>,

    #[arg(
        long = "maven-build-cache-id",
        value_name = "ID",
        hide = true,
        help = "Action integration: Maven remote build-cache id for generated setup"
    )]
    pub maven_build_cache_id: Option<String>,

    #[arg(long, help = "Print the resolved execution plan without running")]
    pub dry_run: bool,

    #[arg(
        short,
        long,
        requires = "dry_run",
        help = "Print machine-readable dry-run output"
    )]
    pub json: bool,

    #[arg(
        last = true,
        help = "Command to execute (after --); if omitted, use [adapters.<tool>].command from .boringcache.toml. Proxy-backed args may use {PORT}, {ENDPOINT}, and {CACHE_REF}"
    )]
    pub command: Vec<String>,
}
