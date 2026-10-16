# Changelog

All notable changes to BoringCache CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [1.42.1] - 2026-10-15

### Changed

- Successful cache operations are quiet by default across commands and adapters. Use `--verbose` for operation details on stderr or `RUST_LOG=boring_cache_cli=debug` for technical diagnostics. Requested reports, JSON, credentials, and wrapped program output remain available.
- Cache failures remain visible when a build succeeds, with repeated proxy failures reported once per session. Successful credential renewal is debug-only.
- Closing a pipe that receives command results exits quietly with status 141 instead of panicking.

## [1.42.0] - 2026-10-14

### Added

- `boringcache docker sign` publishes OCI signatures with local cosign or Notation keys; `docker attach` publishes OCI attachments. Standard signing tools can discover and verify the signatures.
- Shared Notation certificate publisher trust for Cache, compiler/KV, Artifacts and Registry, with pinned roots, signer identities and explicit offline revocation policy.
- `boringcache docker tag` preserves exact image manifests, and `docker index` assembles published platform manifests within a repository.

- Shared cosign local-key publisher trust for Cache, compiler/KV, Artifacts and Registry, with policy-pinned public keys and offline verification.

- Docker tool-cache receipts report the local cache policy the CLI set up for
  each tool as `local_cache`: `remote-only`, `ephemeral`, `tool-state` or
  `local-copy`. The field does not reflect a setting in the build that
  overrides it, such as `TURBO_FORCE`.
- `boringcache docker login` lets stock Docker and buildx get BoringCache
  Registry credentials. It installs `docker-credential-boringcache` next to the
  CLI and registers it for the Registry host in Docker's `config.json`. Stock
  Docker and buildx use these credentials to pull images; publish images with
  `boringcache docker push`. Under a Machine connection each credential request
  gets a new five-minute Registry capability with the session's grant. Without a
  Machine connection the helper uses the save token, or the restore token when no save token is set. A broker
  failure fails the request without falling back to a stored token. The helper
  rejects `docker login` password storage and ignores `docker logout`.
- `boringcache docker pull` names `boringcache docker login` when the Docker
  pull it runs fails.

- Cache session reports describe the machine: CPU model, available CPUs,
  memory limit, disk size and free space of the working directory, and whether
  GitHub hosts the runner. Reports also say when the CLI runs under emulation,
  such as an x86_64 binary on an ARM host or Rosetta on macOS, and name Linux
  guests of Apple's hypervisor `Apple virtual CPU`. On Linux they also include host CPU, disk and
  pressure-stall activity between CLI start and the report. Hostnames and
  environment values are not sent. The local session log now includes the same
  runner and machine fields.
- Track cache uploads and publications under one producer when the server
  advertises lifecycle support. Saves and writable proxies renew ownership
  for named unfinished operations independently of telemetry. Publication settles
  temporary ownership atomically; retries return the original result after later
  tag changes or process end. Expired work uses a new operation under the same
  authenticated process. Archive merges use a new operation for each changed
  snapshot; HTTP retries keep the same operation. Older servers continue using
  the existing write protocol.

- Eager startup predicts independent cache bodies from the last two completed
  sessions and gives new writes one warm trial. The default learns across
  runners when the server supports warm generations. Retention and on-demand
  lookup remain independent; incomplete history uses the current-version set.

- Cache session summaries report how each build used the blobs that proxy
  startup selected, including blobs already in the local cache:
  `startup_prefetch_used_blobs` and `_bytes` count startup
  blobs the build read, `startup_prefetch_unused_blobs` and `_bytes` count the
  rest, and `startup_prefetch_unplanned_blobs` and `_bytes` count blobs the
  build read that startup did not select. `startup_prefetch_demand_waits`,
  `startup_prefetch_demand_wait_ms` and `startup_prefetch_demand_max_wait_ms`
  count reads that waited for a storage download. Startup downloads and
  existence checks are not counted as reads. Bazel and REAPI action-cache hits
  still keep every referenced output in the cache, but only the bodies the
  proxy read are counted as used. Xcode is not covered: its startup copies
  blobs into the Apple CAS store through the same reads as the build, so its
  reads are reported as unplanned.

### Changed

- Reuse unchanged archive contents automatically when the server advertises v3;
  remove `BORINGCACHE_ARCHIVE_SELECTIVE_READS`. Restores still reconstruct the
  complete tree. Missing or unsupported local evidence uses a full read.
  Jobs sharing v3 archive tags require CLI 1.33.0 or later.

- `boringcache docker --tool-cache turbo` sets `TURBO_CACHE=remote:rw`
  (`remote:r` when read-only) in Docker builds. Turbo 2.3.0 and later then
  store task outputs only in BoringCache and no longer fill `.turbo/cache` or
  a cache mount over it; earlier versions ignore the setting. A `--cache` flag
  on the turbo command takes precedence. Turbo exits with "Cannot set `cache`
  config and other cache options" when the command also uses the deprecated
  `--no-cache`, `--remote-only` or `--remote-cache-read-only` flags, or sets
  `TURBO_REMOTE_CACHE_READ_ONLY=true` in a build that can write; Turbo 2.3.0
  also rejects `--force`, which 2.4.0 accepts. Remove `--remote-only` and replace the
  other flags with `--cache`, for example `--cache=remote:r`. `boringcache
  turbo` outside Docker is unchanged.
- With the next managed BuildKit image, `boringcache docker --tool-cache nx`
  and `--tool-cache maven` point the tool's local cache at a directory that
  each `RUN` step gets empty and that BuildKit removes when the step ends, so
  neither the image layer nor a cache mount keeps a second copy. With the
  current managed image, Nx and Maven keep their own local cache and receipts
  report `local-copy`. A cache location set in the directory where
  `boringcache` runs keeps the tool's own directory: `cacheDirectory` in
  `nx.json`, or `maven.build.cache.location` in `.mvn/maven.config` or
  `.mvn/jvm.config`.
- A `TURBO_CACHE` or `NX_CACHE_DIRECTORY` value the Dockerfile sets takes
  precedence over the value `--tool-cache` injects when the build sources the
  tool-cache env file without the managed BuildKit image, or uses the next
  managed image. With the current managed image, the injected `TURBO_CACHE`
  replaces a Dockerfile value.
- Archive exclude patterns from `exclude` lists and `--exclude-pattern` use
  `.gitignore`-style matching. `*` and `?` no longer match `/`, so `release/*`
  matches only entries directly inside `release`. `**` matches any number of
  directories, `[a-z]` and `[!a-z]` match one character, `\` makes the next
  glob character literal, and `!pattern` includes again a path that an earlier
  pattern left out; the last matching pattern decides. A directory pattern with
  an inner slash, such as `vendor/generated/`, now matches only from the top of
  the saved directory; write `**/vendor/generated/` to match it at any depth.
  Root patterns such as `./build/` are case-sensitive on Windows too. A
  malformed pattern stops the command before it runs. Command-line patterns
  follow an entry's own patterns in order, so `--dry-run --json` lists a
  repeated pattern twice. Built-in Cargo exclusions are applied after user
  patterns, so `!` cannot include them again. Unlike Git, `?` and character
  classes match Unicode characters, and only a segment of exactly `**`
  spans directories. Named classes such as `[[:digit:]]` are rejected; use
  `[0-9]` instead.
- Local records of unchanged archive saves from earlier CLI versions do not
  apply to the new matching rules. The first save of each archive entry on a
  machine that kept those records packages the directory again.

- Proxy startup no longer requests storage download URLs for blobs already in
  the local cache, and sizes its download concurrency on the blobs it still has
  to fetch. This applies to the current-version warmup, Bazel and REAPI
  action-result planning, and Xcode warmup.
- Eager startup can request a stalled storage download again. After every
  missing startup blob has been scheduled, a blob up to 8 MiB whose request is
  outstanding and has received no response headers or body bytes for one second
  is requested a second time, and the first complete, verified copy is kept.
  Waiting between retries does not count. Each startup wave allows one extra
  request per 100 scheduled blobs, rounded up, with a maximum of 16. Startup
  waits for the selected downloads to finish; incomplete warmup reports the
  missing blobs and serves them on demand. Cache session summaries report
  `startup_prefetch_hedges` and `startup_prefetch_hedge_wins`. Download records
  in the observability log include admission, response-header, first-byte,
  largest-gap and body times, and mark a second request with `hedge=1`.
- Cargo target pruning observes external plugins on Unix. `boringcache cargo
  fuzz build` and `boringcache cargo fuzz run` start the plugin with a temporary
  `cargo` shim first on `PATH`, so each Cargo command the plugin runs gets
  `--message-format=json-render-diagnostics` and its JSON stays out of the
  plugin's output. Pruning combines the usage of every recorded command, such as
  the `cargo build` and `cargo run` that `cargo fuzz run` starts. The target is
  preserved when one of those commands fails, is still running when the plugin
  exits, uses a non-JSON format or runs another plugin, when a command with its
  own JSON format runs beside another Cargo command, and when the plugin starts
  no Cargo command through `PATH`. A background Cargo command that starts
  before pruning takes Cargo's build lock also preserves the target. Cargo
  commands that a plugin starts through `$CARGO` or an absolute path are not
  seen.
- Managed Docker Cargo steps that run several Cargo commands with the added
  message format combine their usage and prune instead of preserving the
  target. A command with its own JSON format still preserves the target unless
  it is the step's only target-using Cargo command.
- Cargo target pruning recognizes the per-unit `build/<package>/<hash>/`
  target layout that nightly Cargo uses by default, including profiles that
  also contain classic `.fingerprint` and `deps` outputs. Nightly targets were
  previously preserved without pruning.

### Fixed

- `boringcache docker push` now compresses layers that Docker exports
  uncompressed. Docker Engine's classic image store, which GitHub-hosted
  runners use, exports every layer uncompressed, so earlier pushes stored and
  served the full uncompressed size. Layers are compressed with zstd while
  the export is read and upload during the export once the image manifest
  confirms them. In local tests capped at runner bandwidth, the PostHog image
  stored 1.87 GB instead of 6.36 GB, pushed in 49–53 s instead of 109 s, and a
  stock `docker pull` took 47 s instead of 80 s. Pulling zstd layers needs Docker Engine 23 or later,
  containerd 1.5 or later, or a current Podman or CRI-O. Images pushed from a
  daemon that exports compressed layers are unchanged.

- Keep Xcode cache connection settings out of Swift compiler arguments so
  fresh sessions and read-only restores can reuse project Swift compilation.

- Add opt-in Xcode 27 compiler path mapping for equivalent builds in different
  checkout and DerivedData directories. Xcode 26 still requires matching real
  paths. Mapping changes runtime source-file literals to virtual paths; existing
  behavior remains the default. Report the selected mapping strategy and the actual explicit build
  directory in cache evidence.

- Use managed BuildKit 0.33.1-bc.3, which prevents canceled uploads of image
  metadata after cache export, fixes concurrent cache-key snapshots and updates
  runtime security dependencies.

- Accept compatible project-selected sccache, ccache and HTTP helper versions
  in prerequisite checks instead of requiring the audited download pins.
  Report the installed version, preserve supported floors, and enforce exact
  explicit tool-version requests, including buildctl.

- Docker session write totals now include cache layers that BuildKit uploads in
  one request. Previously these sessions counted only the manifest, so a build
  that stored gigabytes of layers reported kilobytes written.
- Session summaries report layers and KV objects that the proxy uploads in the
  background before publication. Docker layers appear under
  `storage.writethrough` and `storage_writethrough_upload_bytes`; KV objects
  under `kv_upload_writethrough_uploaded_blobs` and
  `kv_upload_writethrough_uploaded_bytes`. The final KV flush reports
  `kv_upload_uploaded_bytes`. Publication upload counters and durations are
  unchanged.
- KV write-through failures and storage-pressure skips report under
  `kv_upload_writethrough_failure_*` and `kv_upload_writethrough_pressure_skip_*`
  instead of the Docker `oci_engine_*` counters.
- Saves and writable proxies continue using the existing write protocol when
  producer admission is disabled after capability discovery, before a producer
  has started. Writes already bound to a producer keep their ownership checks.
- Cache operation renewal retries transient failures after 15 seconds instead
  of waiting another five minutes, and restores the normal interval after success.

- `ci run` no longer stops a long build when OIDC session renewal fails. Renewal
  starts when half of each session's lifetime remains and retries temporary
  provider and BoringCache failures until it succeeds, including after the
  session expires. An expired session cannot issue new credentials. The wrapped
  command keeps running; `ci run` reports when authentication became unavailable
  and when it was restored, and exits with the command's status. Previously,
  renewal began 30 s before a five-minute session expired, and two 503 responses from GitHub's
  token endpoint stopped a 77-minute Docker build. No path falls back to a
  static credential. On Unix, `ci run` preserves the 30-second shutdown deadline
  after SIGINT or SIGTERM, including during session renewal and expiry.

- Avoid repeated upload-progress warnings when progress output is disabled.
  Upload errors and byte accounting are unchanged.

## [1.41.0] - 2026-10-09

### Added

- Opt-in Go source freshness for wrapped commands: set
  `source-freshness = true` under `[adapters.go.options]` to preserve unchanged
  tracked-input timestamps across checkouts at the same path. This can retain
  Go test-result cache hits for tests reading repository files. Action setup
  and Docker tool-cache injection require this option to remain disabled.

### Fixed

- sbt remote caching now stores and restores action outputs larger than 1 MB.
  sbt sends them through ByteStream with resource names that start with `/`
  when the instance name is empty; the REAPI endpoint rejected those names, so
  sbt rebuilt the affected actions on every run.
- Release unused glibc allocator pages before `run` and wrapped adapters start
  their command, reducing memory retained after archive restores on GNU/Linux.
- OCI download rates now include admission waits, response waits, retries, local writes and
  verification. Session summaries and events distinguish elapsed download
  rates from body-read wait rates and retain sub-millisecond timing.

## [1.40.2] - 2026-10-08

### Added

- Retain BuildKit CPU, I/O and memory admission counters, bounded body-spool
  measurements, available-memory minimum and sampled daemon RSS when reported
  by the managed image, including checkpoints from failed builds.
- Record the archive process's peak resident memory in `archive_graph_phase.v1`
  events and in the archive worker result.

### Changed

- Cargo target pruning no longer needs `--message-format=json`. A wrapped
  command without a message format gets `--message-format=json-render-diagnostics`
  after its subcommand when `cargo <command> --help` lists it (`cargo clippy`
  uses the `cargo check` options). The CLI reads Cargo's JSON and does not print
  it, so build output looks like a plain Cargo run. Aliases whose expansion is
  all options qualify; aliases with `--` or positional arguments and external
  plugins run unchanged and are not observed. An explicit JSON format still
  forwards stdout unchanged. `cargo doc` records usage instead of warning.
- Managed Docker Cargo target mounts no longer need
  `--message-format=json | tee "$BORINGCACHE_CARGO_MESSAGE_FILE"`. While pruning
  is enabled, the worker puts a `cargo` shim first on the RUN command's `PATH`,
  adds the message format to eligible commands and keeps the JSON out of the
  build log. A Cargo command in the step that is not observed and can use the
  target keeps the target for that step. Cargo invoked by absolute path is not
  seen. Steps with multiple target-using Cargo commands preserve the target,
  including commands with an explicit JSON format. The explicit `tee` form
  still works. A descendant keeping stdout open after Cargo exits stops
  observation after five seconds and preserves Cargo's exit status.

### Fixed

- Include delivery mode, source and edge location in Docker storage read events
  and verbose archive restore output when storage response headers provide them.
- Forward application JSON output without waiting for a newline after Cargo
  finishes building, and preserve procedural-macro JSON with an unknown
  `reason` when the message format is added automatically.

- Preserve Cargo build-script invalidation when ignored or generated directory
  inputs change. Reuse initialized submodule sources and rebuild dirty ones,
  including changes inside nested submodules that a parent `.gitmodules`
  marks as ignored. Submodule enumeration works with Git releases before 2.36.
  A checked-out submodule whose Git directory is missing stops the command
  with the submodule path and the commands that repair it.
- Verify standard-library sources against a snapshot taken before the first
  successful build, allowing the first read-only warm build to reuse them.
  Skip that snapshot when a restored target shows the previous build did not
  compile the standard library.
- Cache Cargo's separate build directory and recognize its build locks during
  pruning. Cargo recreates final outputs from the restored intermediate files.
- Report the absence of usage observation in Cargo cache phases and distinguish
  completed archive restores from missing or failed phase evidence. Restore
  phase entries name the planned tag as `resolved_tag`, including restores from
  a fallback tag, and report `restore_result` as `restored`, `not-found`,
  `failed` or `skipped`, with a `skip_reason` for skipped targets.
  Resolution errors and uploads still pending after retries report `failed`;
  failed restores cannot report an unchanged phase.
  `--phase-evidence-json` also works for a wrapped command, which writes its
  restore accounting before the command runs.
- Measure cgroup v2 memory headroom by working set (`memory.current` minus
  `inactive_file`). Clean page cache in a memory-limited container no longer
  reduces download admission or archive concurrency.
- Retain managed Docker cache-mount worker timeout reasons and the latest
  worker failure in run summaries, including failures after the sample limit.
- Count a managed Docker cache-mount save or restore as complete when its
  worker reported success before being stopped during exit. Remove a failed
  restore's partial files from the mount instead of building on them.
- Let managed cache-mount manifest commits finish within their request and
  retry budget. Remove worker temporary archives and restore staging after
  forced stops, including stops after a successful save.
- Reserve reused Docker cache blobs before acknowledging them to BuildKit. Keep
  reused local bodies until publication and upload again when remote reuse is
  unavailable.
- Retry GitHub Actions and BoringBuild OIDC token requests that fail to
  connect, time out, or return HTTP 408, 429 or a retryable 5xx response, up to
  five attempts with bounded backoff and `Retry-After`. Other responses still
  fail on the first attempt.
- Retry a transient workload-session exchange at `ci run` startup with a fresh
  assertion, as renewal already does. A stalled first exchange times out after
  10 seconds so it can retry before the broker-readiness deadline. Startup stops
  after 60 seconds and never falls back to static credentials.
- Keep cache downloads at full width when Linux I/O pressure comes from other
  work. Startup warmup after an archive restore no longer drops to one request
  while writeback from that restore finishes. Downloads still slow down when
  their own disk writes, including buffered flushes, stall or memory is low.
- Start cache warmup for working sets of small and medium objects at 64
  requests instead of 20. Bazel and REAPI warmups no longer inherit a lower
  starting width from a small planning pass unless that pass slowed down.
- Load the full cache index and the current working set concurrently when a
  cache proxy warms up, so the first downloads start sooner. Empty caches,
  failed index loads and fallback tags do not wait for an unused current
  working-set request.

## [1.40.1] - 2026-10-07

### Changed

- Add native REAPI adapter help examples, read-only commands, and links to the
  Bazel REAPI, Moon, Pants, Buck2, and sbt setup guides.

### Fixed

- Retry failed connections during OIDC workload-session exchange up to five
  times with bounded backoff. Keep assertion delivery single-use and stop on
  HTTP rejections or failures after sending the assertion. Preserve upstream
  HTTP status when the local broker reports a rejected renewal.
- Retry transient session-renewal failures with a fresh assertion each time,
  honoring bounded backoff and `Retry-After` before the current session expires.
- Select the managed pnpm store with pnpm 11 and 12 environment variables,
  while retaining store selection for older versions.
- Explain that an occupied restore target was preserved and requires an empty
  target directory, without changing strict restore failure behavior.

## [1.40.0] - 2026-10-06

### Added

- Add `runs list/show/explain/compare` with human output and versioned JSON for run evidence, suggested actions, and baseline comparisons.

- Add managed native `bazel-reapi`, `moon`, `pants`, `buck2`, and `sbt` caching with shared REAPI setup, typed repo options, and cleanup. Keep `bazel` on HTTP and download top-level Bazel outputs by default.

- Add Docker tool caches for `moon`, `pants`, `buck2`, `sbt`, and explicit
  `bazel-reapi`, with native configuration, command-scoped authentication,
  target selection, and read-only controls. `bazel` keeps HTTP support.

- Add offline `boringcache prune cargo` with preview and JSON output containing
  one `schema_version` field. A default 40 GiB target budget applies after observed
  Cargo commands with non-terminal output. Terminal commands inherit their
  streams. Nested or overlapping commands run without pruning. Protect groups containing symlinks and preserve the child
  exit status when descendants hold output open. Pruning also applies to
  read-only runs and runs without archive saves. Retain active and
  unknown outputs and report unmet budgets. Override `target-budget` or set it
  to `0` to disable pruning. Use
  `--target-scope` to protect outputs across several commands. GB and GiB both
  use binary bytes, matching other cache size settings. The job-window
  policy is removed.

- Add an opt-in Linux OverlayFS backend for local Cargo snapshot restores, with private worktree writes, mount recovery and explicit local cleanup.

- Record REAPI RPC outcomes, bounded client-reported names, and
  gRPC body bytes in the existing request-metrics JSONL output.

### Changed

- Multipart CAS uploads use the server's planned part size, so a final partial
  part does not make earlier S3 parts smaller than the required minimum.

- A cache save rejected because the cache storage allowance is full is reported
  once as `Skipped cache save for …`, publishes nothing, and keeps the command's
  exit status, including with `--fail-on-cache-error`. The previous version
  stays available. The proxy stops uploading a rejected batch and prints one summary at shutdown.
  HTTP 507 responses are no longer retried.

- Cargo target pruning requires explicit `--message-format=json` output. Commands and plugins that emit a complete Cargo build stream can record usage without a command-name allowlist. Command arguments and output are preserved; missing or incomplete evidence skips pruning.

- Managed Docker Cargo target mounts can record JSON through the worker-provided `BORINGCACHE_CARGO_MESSAGE_FILE` and prune before publication using the same local usage and budget rules.

- Use managed BuildKit `v0.33.1-bc.1` and buildctl 0.33.1, with containerd
  2.3.6, Go 1.26.8, and the PCRE2 10.49 security fix.

- Adapter commands keep their previous cache tag when no tag is configured,
  and print the resolved name with the setting to add to `.boringcache.toml`.
  Explicit configuration and `--tag` take precedence. Dry-run JSON includes
  `tag_source`; Cargo without a compiler cache needs no adapter tag.

- `.boringcache.toml` rejects unrecognized keys with an `unknown field` error
  instead of ignoring them. Entry keys accept `path-env` and `default-path`
  like other kebab-case keys; `path_env` and `default_path` still work, and
  `audit --write` now writes the kebab-case spelling.

- `BORINGCACHE_TELEMETRY_DISABLED=0` (or `false`, `no`, `off`) no longer
  disables telemetry. Any other value still disables it.

- `boringcache config get token` prints a masked preview and the token source.
  Add `--reveal` to print the full token. `config get token --json` now
  requires `--reveal`; its output is unchanged when the flag is present.
  Token previews fully mask short and non-ASCII values in both `config get`
  and `config list`.

### Removed

- Remove Kache and mbx Cargo compiler integrations and managed-tool installs.
  Cargo target snapshots and sccache remain supported.

- Remove the terminal `dashboard`. Use `status`, `runs`, and the focused inspection commands.

- Remove the development-only environment, checkpoint, snapshot, agent-continuation
  and remote execution commands. Cache, Artifacts and Registry remain supported.

- Remove the `boringcache check --exact` flag. It had no effect: `check`
  already resolves only the effective scoped tag. BoringCache One releases
  before v1.20.0 pass it, so those releases need their default CLI or an
  Action upgrade.

### Fixed

- Allow concurrent sbt adapters to share global settings without file conflicts or applying another invocation’s cache configuration. Preserve Windows path separators when selecting global settings and plugins through `SBT_OPTS`.

- Configure a local Docker build when onboarding finds a root Dockerfile,
  including when the optional CI scan is skipped. Preserve existing commands.

- Check token access before interactive onboarding uses a repository workspace;
  leave repo configuration unchanged when access cannot be verified.

- Identify unsupported GitHub cache paths and provide manual migration steps.

- Identify write-only sessions as stored, explain Workspace selection in inspection reports, align `doctor` with project Workspace selection, and preserve session tool insights in JSON.

- Allow a new conditional metadata update after a verified read of a remote
  conflict winner, while rejecting stale comparisons and invalidating dependent
  local writes. Unrelated metadata publications continue after a conflict.

- Preserve Cargo outputs when a plugin emits multiple build streams in one invocation.

- Run managed Docker commands with their message file and original exit status when pruning usage metadata cannot be read.

- Reserve reused cache blobs before publication so concurrent cleanup cannot
  remove them during upload. Rebuild an archive once if reused chunks disappear
  before reservation, and report failed upload receipts before attempting to
  publish the cache. GitHub Actions-compatible cache saves reserve reused blobs
  through the same path.

- Keep KV preload membership unchanged until every publication batch commits.
  Abandoned attempts do not consume the recent-publication window, and
  superseded publishers receive a conflict. Warmup does not renew retention
  on servers that support read reporting. Strict runs fail when current-version
  publication fails.

- Keep the KV read-reporting compatibility decision for each API client, so
  failed capability discovery does not delay every download-URL batch.

- Verify standard-library source snapshots against successful Cargo builds before
  restoring timestamps for `-Z build-std` targets. The first snapshot requires
  one additional rebuild. Backdated edits, symlinks, and failed source recording
  cannot preserve trusted target fingerprints.

- Preserve Cargo fingerprints for MSVC executables and shared libraries whose
  output names have no hash, so target retention can prune stale dependencies.

- Keep accepted CAS files visible while background publication moves them
  between local stores, including cancelled flushes. Bazel HTTP and candidate
  REAPI validation no longer reject an available output during spool cleanup.

- Finish reading Docker image exports before closing their output pipe, so
  valid tar padding cannot cause a successful export to fail with SIGPIPE.

- Reuse the HTTP proxy's warmed index, download URLs, local blobs, and
  dependency checks for REAPI reads. Bazel eager startup now also
  warms REAPI action results and their reachable CAS dependencies.

- Use the HTTP proxy's local spool, background write-through, batched
  publication, and shutdown settlement for REAPI writes. Accepted
  writes are immediately readable through the same proxy. Uploads rejected by
  a full pending spool remain resumable.

- Allow the REAPI endpoint to write and resume uploads on Windows.
  Spool files now use write access so interrupted writes can be truncated
  before resuming at the committed offset.

- Bound connection shutdown for the REAPI cache endpoint with the
  proxy's five-second drain policy. Stalled client streams and backend requests
  are cancelled so queued cache publications can reach their shutdown phase.

## [1.33.0] - 2026-09-25

### Added

- Verify customer-controlled Sigstore publisher attestations for Archive,
  Archive Graph, and OCI cache entries. Repository policy selects exact GitHub
  repository, workflow, ref, and event identities, including a reusable
  workflow through `job-workflow-ref`; a protected SHA-256 pin authenticates the
  policy bytes. Setting that pin requires the exact policy it names, so removing
  `[trust]` from a checkout cannot turn verification off. A cache entry can carry
  attestations from several authorized publishers, and restore accepts the entry
  when any of them satisfies the policy. Publishing content that already carries
  a trusted attestation reuses it instead of signing again, and publishing
  content that carries none attests it even when the upload itself is skipped.
  Rejected entries become cache misses by default, and strict policy can fail
  the operation. Cryptographic work remains in a bounded external provider, so
  the CLI adds no Sigstore or cloud KMS SDK. The policy also supports a
  BoringBuild OIDC publisher whose signed token binds the exact subject kind
  and digest, with a customer-pinned issuer key, forge origin, repository,
  workflow, ref, and event. Protected remote compiler/KV reads, native
  Artifacts, the GitHub Actions-compatible Cache and Artifact service, and
  `boringcache docker pull` apply the same policy. Results created in the same
  local proxy process remain reusable. `boringcache check` does not report
  unverified remote KV rows as usable.

### Fixed

- Experimental archive selective reads honor format changes on unchanged saves
  and run explicit full-read verification instead of republishing a pointer.
  Files on other devices are read in full rather than trusted through the
  selected root filesystem.

- Restore enabled local Cargo target snapshots into empty targets even when the
  selected profile contains only dependencies. These runs preserve populated
  targets and do not capture snapshots or transfer remote target archives.

- `boringcache cargo` and `boringcache sccache -- cargo …` preserve the caller's
  `CARGO_TARGET_DIR`, including when it is absent. Target archive selection no
  longer adds an absolute override to Cargo's environment. sccache includes
  `CARGO_TARGET_DIR` in Rust cache keys, so Rust entries remain readable when
  jobs select different Cargo cache layers. Existing keys written with an
  automatically added target directory will need one new cache write.

## [1.32.0] - 2026-09-22

### Added

- Opt-in local Cargo target snapshots for empty worktrees, with independent
  files and a disk budget.

- Accept provider-issued multipart receipts when a storage upload succeeds
  without an ETag, enabling Azure Blob block uploads while preserving S3
  completion behavior.

### Fixed

- A brokered Machine connection now supplies its approved workspace for archive,
  Cargo, sccache, Docker, GHA compatibility, and direct commands. Conflicting
  explicit workspaces fail. Local and static-token use keeps the repository
  workspace. Older supervisors that cannot report the approved workspace
  require an upgrade.
- Keep macOS filesystem observation markers outside the source checkout so they
  do not prevent Cargo target publication.
- Prevent archive restores from hanging after a large blob downloads successfully
  while later blobs fill the memory buffer. Early extraction errors also stop
  waiting downloads and report the original error.
- Cache prefetch and KV demand reads now share archive download concurrency policy. Recovered
  slow-read retries retain their byte progress without independently halving
  concurrency, and retained bytes enter throughput measurements only once.
  Startup prefetch no longer collapses to one download because of an elevated
  CPU load average; memory and I/O pressure still limit admission. Download
  defaults and archive transfer planning also stop using CPU load history.

## [1.31.0] - 2026-09-18

### Added

- Publish any single file at an immutable public path with
  `boringcache artifact publish`. Publication works with managed or BYOC
  storage and reuses Artifact workload identity, provider checksums, and signed
  Artifact receipts. Static tokens require admin access. The command checks
  public response headers after upload; `--verify-download` also downloads and
  hashes the public object.
- Address Docker and BuildKit cache mounts under their own namespace with
  `--mount-namespace` (repo plan `mount-namespace`), so two jobs that need
  independent image graphs can still share cache mounts: give each job its own
  `--tag` and both the same namespace. A bare value covers every mount and
  `MOUNT_ID=NAMESPACE` addresses one `--mount=type=cache` id, so a shared
  registry can sit beside separate target directories. Mounts you do not name
  keep the tag's identity. Requires `--mount-cache`.
- Publish a shared cache-mount namespace without losing another job's files.
  A job that finds the namespace published since its own restore merges the
  published files it does not have, keeps its own copy of every shared path,
  and commits against the snapshot it merged. A job that loses that race
  merges again and retries instead of skipping its save. A publication the
  server declines to promote fails the save rather than reporting success, and
  the merge restore honors the same signed-cache-hit requirement as the job's
  own restore. Deleted files are not propagated between jobs.
- `boringcache cargo --phase restore` and `boringcache cargo --phase save` run
  one cache phase around a job's own Cargo commands instead of wrapping a single
  command. A phase runs no Cargo command and ignores `[adapters.cargo].command`,
  so a job that runs several Cargo commands caches all of them. The restore
  phase records whether the checkout was clean in a job-scoped document under
  the system temporary directory, keyed by the target path, so the save phase
  cannot publish a target restored into a dirty checkout that was later tidied
  up. The record stays out of the target directory, so a restore miss leaves
  the target empty for the retry. That record only withdraws publication; the
  save phase still checks the checkout itself.
  `--phase` is Cargo-only, rejects a command, and rejects
  `--skip-restore`/`--skip-save`. A cache phase with no token reports the
  missing token instead of trying to run an empty command.
- `--phase-evidence-json` writes a `cache_phase_evidence.v1` document for a
  cache phase: its duration, transferred and logical bytes, snapshot and
  transfer durations, entry count, and whether the publish moved any bytes.
  A publish that transferred nothing is reported as unchanged.

### Changed

- Download stable BoringCache release assets from
  `artifacts.boringcache.com` first, with the exact GitHub release as a
  same-version fallback. Installer downloads use bounded timeouts and retries.
- `gha` takes its workspace from the approved workload binding when the broker
  reports one, so a separately configured workspace cannot drift out of
  agreement with the binding. An explicit `--workspace` remains valid for the
  static token mode and as an override, and one that disagrees with the binding
  refuses readiness instead of being attempted.
- `gha` reports a backend refusal as a typed Twirp error naming the workspace
  and the operation: 401 as `unauthenticated`, 403 as `permission_denied`, and
  404 as `not_found`. Only transport failures and unexpected responses remain
  `internal`. Cache actions previously saw a bare 500 with no cause.
- `gha` makes one bounded workspace check at startup. A workspace the workload
  capability cannot see now publishes a refusal to its ready file and exits,
  so the supervisor can run the job without a cache instead of answering every
  cache call with an error.
- Record whether managed BuildKit step timing was reported, still pending, or
  unavailable after the build command. Cache-session reports can distinguish
  interrupted builds from builds with complete vertex timing.
- Collect aggregate task outcomes for Turbo, Nx, and Gradle adapter commands
  and attach them to cache-session summaries. Run reports separate remote or
  build-cache hits, local hits, already-current tasks, skipped tasks, executed
  tasks, and failures without storing task names or cache keys.
- Add runner OS and architecture, CLI version, and post-build publication drain
  duration to structured cache-session summaries so run reports can separate
  environment and save work from the remaining workflow span.
- Verify BoringCache-signed in-toto/DSSE publication receipts after Artifact
  uploads and before Artifact restores. Older Artifacts without a receipt
  remain usable with a warning, and JSON output reports the verification
  result.
- Update the managed ccache HTTP storage helper to `0.10`.
- Update mise in the runtime and build base images to `2026.9.7`.
- Update the managed Docker builder to BuildKit `v0.33.0-bc.4`. One
  daemon-wide limit admits one to four cache-mount archive worker processes
  from the BuildKit CPU budget and reports active, queued, peak, and wait
  metrics.
- A live OCI stream that fails to reopen and keeps its original response no
  longer reports the reopen attempt's sleep and header wait as a peer pause,
  so other proxy-session reads do not widen their slow-read windows for it.
- Size adaptive buffers and concurrency from cgroup v2 memory limits and live
  usage on Linux. Ancestor limits are included, and `memory.high` reduces new
  allocation admission without being treated as the hard memory limit.
- Keep OCI and KV demand, prefetch, sequential, and ranged storage reads within
  one proxy-session request budget. Slow-read recovery now considers concurrent
  peer throughput and pauses. Archive and CAS restores retain their separate
  command-wide adaptive budget. OCI range rescue fans out to its configured
  stream count under that session budget and no longer runs a per-rescue
  byte-shaped adaptive limiter.
- Download and unpack an archive cache in one phase instead of waiting for
  every blob before extraction starts. Blobs are fetched in the order the tar
  stream consumes them, each chunk is decoded as soon as its own blob lands,
  and restore reports unpacked bytes with speed and ETA while the remaining
  blobs arrive. Storage pressure produced by a restore's own extraction no
  longer reduces that restore's download concurrency.

### Fixed

- Retry a transient brokered workload capability refresh with bounded backoff
  instead of failing the publication. A single gateway or server error during a
  long build no longer discards the whole build's cache export. A denied
  capability is still reported immediately and is never retried.
- Bound the first automatic eager-startup burst for large small-object caches,
  wait for a reduced limit to take effect before reducing it again, and carry
  Bazel's learned action-result limit into closure hydration.
- Recover a stalled `artifact pull` by refreshing its signed download request
  after repeated zero progress and restarting the verified representation from
  byte zero when the refreshed range also stalls.
- Write tracing diagnostics to stderr so `RUST_LOG` output does not corrupt
  structured command output on stdout.
- Apply and verify valid ad hoc code signatures after assembling the universal
  macOS CLI and Xcode adapter release assets.

## [1.30.4] - 2026-09-10

### Fixed

- Reuse archive graph decoder threads and zstd contexts across chunks to reduce
  large archive restore materialization time.

## [1.30.3] - 2026-09-10

### Fixed

- Align BuildKit smoke and end-to-end test defaults with the managed
  `v0.33.0-bc.2` image.

## [1.30.2] - 2026-09-10

### Changed

- Update the managed Docker builder to BuildKit `v0.33.0-bc.2`. Cache-mount
  archives use stable, readable mount names across workers. Archives saved
  under older mount names remain stored but are not selected by the new names.
- Update mise in the runtime and build base images to `2026.9.4`.
- Adapt automatic download and prefetch admission to live OS memory and I/O
  pressure, including when fewer requests are needed than at startup. Range
  downloads share the same admission policy.
- Overlap archive verification and decoding with extraction. Adapt decoder
  admission to measured delivery, live memory and I/O pressure within the CPU
  and operator limits; join workers before cleanup when extraction stops.

- Reuse Cargo target tags across package version, manifest, and lockfile changes.
  Target tags retain the configured Git/platform scope; Cargo rebuilds affected
  crates when their inputs or compiler change. Existing remote snapshots
  with a graph suffix remain under their old tags and are not selected by the
  new key. Populated local targets remain usable. No automatic target rotation
  or pruning is added.
- Honor `CARGO_INCREMENTAL=1` for Cargo target entries and preserve incremental
  directories in archive saves when enabled. The default remains `0`; use
  `compiler-cache = "none"` for incremental compilation. The rustc query cache
  and obsolete BoringCache artifact receipt remain excluded.

### Fixed

- Use retained byte progress to adapt shared download admission after a slow-body
  probe retries. A probe no longer independently halves capacity for unrelated
  objects; transport failures and native resource pressure retain their backoff.

- Use the same download recovery for archive chunks and proxy files. Retry
  stalled response headers within bounded budgets, honor bounded server retry
  delays, and refresh rejected cached URLs without restarting the retry budget.
  Keep startup prefetch within that budget and use actual retries to adapt its
  concurrency. After recovery opens a fresh connection, subsequent downloads
  use its replacement pool. Print terminal transport causes without signed
  storage URLs.

- Retry slow archive and OCI chunk downloads even when the chunk or resumed
  remainder is small. Check throughput within two seconds of collecting bytes,
  keep completed downloads, and report recovered download retries accurately.
- Recover slow live OCI reads and proxy file downloads, including slow resumed
  tails and sequential fallback after range rescue fails. Use the shared
  progress policy after every reopen and avoid repeating a failed range fan-out.
  Preserve byte progress and let the final attempt finish while its idle
  deadline and integrity checks remain active.

- Preserve changed source timestamps after successful Cargo commands so repeated
  `--skip-save` builds can reuse their local artifacts.
- Compress and stage identical chunks only once within each archive save.
- Use Action 1.30.1 in generated GitHub Actions workflows and workflow diagnostics.

## [1.30.1] - 2026-09-09

### Added

- Configure managed Docker and BuildKit workers with a native `buildkitd.toml`.
  The CLI discovers the nearest file within the project; `--buildkitd-config`
  or an adapter's `buildkitd-config` repo setting selects another file.
  Workers are recreated when settings or referenced registry certificates change.
- Limit the managed BuildKit worker's CPU quota and CPU affinity with
  `BORINGCACHE_MANAGED_BUILDKIT_CPUS` and
  `BORINGCACHE_MANAGED_BUILDKIT_CPUSET_CPUS`.

### Fixed

- Use Action 1.30.0 in generated GitHub Actions workflows and workflow diagnostics.


## [1.30.0] - 2026-09-09

### Changed

- Update the managed Docker builder to BuildKit 0.33.0 with the BoringCache
  backend, retaining an immutable image digest and existing cache behavior.

### Fixed

- Use Action 1.21.0 in generated GitHub Actions workflows.

## [1.21.0] - 2026-09-08

### Added

- Configure archive exclusions with `exclude` in `.boringcache.toml` entries,
  or add patterns with `--exclude-pattern` when an adapter such as Cargo saves
  archive entries.

### Fixed

- Publish Artifacts from OIDC jobs using authenticated workload provenance,
  including providers whose job identity differs from the job name.
- Report missing Docker cache references without implying the entire build has
  no cache, and explain cache startup waits and retries in plain language.
- Refresh OIDC credentials inside Docker cache-mount workers throughout long
  builds, preserving restore-only permissions and normal cache publication.
- Refresh product credentials on HTTP retries and use Registry-scoped OIDC
  credentials for Docker image publication.
- Share compiler cache Git and platform scoping between Cargo and sccache while
  keeping Cargo archive scoping independent.
- Bound captured-output draining after a command exits, so background processes
  retaining its output pipes cannot leave the cache lifecycle waiting forever.
- Update the embedded zstd library to 0.14.0 while retaining the existing
  archive format and canonical cache identity.
- Keep archive and CAS restore download concurrency steady across overlapping
  transfers, while retaining immediate backoff when a transfer fails.
- Record archive save and restore phase timings and available resource counters
  so slow local processing can be distinguished from network transfer time.

## [1.20.5] - 2026-09-07

### Fixed

- Keep native CI cache startup reliable across normal control-plane and broker
  response latency by clamping each workload capability to the remaining
  parent session lifetime.

## [1.20.4] - 2026-09-06

### Fixed

- Accept server-issued workload capabilities across normal request latency by
  clamping their local lifetime to the remaining parent session lifetime.
- Start the Actions compatibility service in restore-only mode whenever the
  brokered workload session is restore-only, so Workspace publication policy
  narrows a job without failing runner readiness.
- Explain when a valid CI workload is restore-only and direct users to a
  trusted job or the Machine connection publication policy instead of showing
  only a local broker 403 response.

## [1.20.3] - 2026-09-04

### Added

- Enroll native BoringBuild workload identity with
  `boringcache ci connect --oidc-provider boringbuild`, using the job's
  controller-issued renewable assertion and browser-approved Workspace
  selection without a stored BoringCache secret.
- Acquire renewable CircleCI OIDC assertions with `--oidc-provider circleci`
  through the in-job Environment CLI, BoringCache's audience, and CircleCI's
  root issuer, without a CircleCI API token or stored BoringCache secret.
- Use GitLab.com's job-scoped `BORINGCACHE_OIDC_TOKEN` directly with
  `--oidc-provider gitlab`, binding immutable job namespace/project identity
  while keeping merge-request and fork source jobs restore-only.

### Changed

- Keep native GitLab's private broker session for the bounded lifetime of its
  job assertion, up to one hour, while continuing to issue five-minute product
  capabilities and recheck live publication policy on every issuance. This
  lets ordinary GitLab jobs run without exposing or replaying their OIDC token
  and keeps existing providers compatible with released clients.

## [1.20.2] - 2026-09-03

### Changed

- Checkpoint cumulative proxy diagnostics every five minutes while continuing
  to deliver completed cache-operation rollups every 30 seconds, bounding
  retained session state and repeated reporting work in long builds.

### Fixed

- Keep Windows archive monitor requests on bounded blocking connections so a
  partially delivered local observation cannot prematurely stop unchanged-cache
  reuse.
- Route archive monitor failures through the configured diagnostic output so a
  fail-closed reuse decision retains its actionable cause.
- Preserve each cache-operation rollup's idempotency identity across delivery
  retries so a transient reporting failure cannot duplicate its counters.

## [1.20.1] - 2026-09-03

### Added

- Let Docker and BuildKit repo plans own optional native tool-cache and
  cache-mount composition used by local runs and the thin GitHub Action.

### Fixed

- Preserve managed Docker Cargo target reuse when an unchanged source tree is
  materialized with newer mtimes.
- Forward `SCCACHE_IDLE_TIMEOUT` into Docker-native sccache builds so long link
  phases do not let the compiler-cache daemon exit early.

## [1.20.0] - 2026-09-02

### Added

- Publish customer-facing CLI release notes from this changelog as part of every release.
- Add `boringcache system requirements <adapter> --check` so automation can
  fail before cache setup when a required helper is missing or incompatible.
- Let an interactive administrator enroll an exact provider-neutral OIDC
  issuer through `boringcache onboard` without creating a fallback CI token.
- Add `boringcache ci run` to acquire renewable provider OIDC assertions,
  supervise one runner-local workload broker, and run Cache or Artifact
  commands without exposing or falling back to static BoringCache credentials.
- Add `boringcache ci connect` with browser-approved Workspace selection and
  in-memory enrollment for native CI providers, plus explicit stdin enrollment
  for registered issuers and automation. Neither path creates a reusable
  BoringCache credential.
- Acquire renewable Buildkite OIDC assertions with `--oidc-provider buildkite`
  and no hand-written token command, forge connection, or BoringCache secret.
- Acquire renewable GitHub Actions OIDC assertions with
  `--oidc-provider github-actions` and the job's native `id-token: write`
  permission, without a GitHub App or stored BoringCache secret.

### Changed

- Resolve GHA cache workspace from the committed repo plan when `gha-cache`
  receives no explicit workspace, and include that resolved workspace in the
  service ready document consumed by GitHub integrations.
- Name credentials created by the provider-neutral onboarding path for CI
  instead of GitHub Actions.
- Update the managed ccache HTTP storage helper to 0.9.
- Tell users to install adapter prerequisites through their normal project or
  workflow setup instead of claiming that BoringCache One installs them.

### Fixed

- Accept exact version output from tools such as `ccache-storage-http` that
  return a nonzero status for their version probe.

## [1.19.7] - 2026-08-29

### Added

- Allow a workflow job to download artifacts produced by another job in the same workflow run while keeping cross-run access denied.

### Fixed

- Retry temporary cache publication conflicts without misreporting them as permanent tag conflicts.

## [1.19.6] - 2026-08-28

### Changed

- Promote the exact tested CLI candidate bytes into the public release instead of rebuilding platform artifacts during publication.

### Fixed

- Preserve project-selected Maven extension versions when enabling Maven cache support.

[Unreleased]: https://github.com/boringcache/cli/compare/v1.42.1...HEAD
[1.42.1]: https://github.com/boringcache/cli/compare/v1.42.0...v1.42.1
[1.42.0]: https://github.com/boringcache/cli/compare/v1.41.0...v1.42.0
[1.41.0]: https://github.com/boringcache/cli/compare/v1.40.2...v1.41.0
[1.40.2]: https://github.com/boringcache/cli/compare/v1.40.1...v1.40.2
[1.40.1]: https://github.com/boringcache/cli/compare/v1.40.0...v1.40.1
[1.40.0]: https://github.com/boringcache/cli/compare/v1.33.0...v1.40.0
[1.33.0]: https://github.com/boringcache/cli/compare/v1.32.0...v1.33.0
[1.32.0]: https://github.com/boringcache/cli/compare/v1.31.0...v1.32.0
[1.31.0]: https://github.com/boringcache/cli/compare/v1.30.4...v1.31.0
[1.30.4]: https://github.com/boringcache/cli/compare/v1.30.3...v1.30.4
[1.30.3]: https://github.com/boringcache/cli/compare/v1.30.2...v1.30.3
[1.30.2]: https://github.com/boringcache/cli/compare/v1.30.1...v1.30.2
[1.30.1]: https://github.com/boringcache/cli/compare/v1.30.0...v1.30.1
[1.30.0]: https://github.com/boringcache/cli/compare/v1.21.0...v1.30.0
[1.21.0]: https://github.com/boringcache/cli/compare/v1.20.5...v1.21.0
[1.20.5]: https://github.com/boringcache/cli/compare/v1.20.4...v1.20.5
[1.20.4]: https://github.com/boringcache/cli/compare/v1.20.3...v1.20.4
[1.20.3]: https://github.com/boringcache/cli/compare/v1.20.2...v1.20.3
[1.20.2]: https://github.com/boringcache/cli/compare/v1.20.1...v1.20.2
[1.20.1]: https://github.com/boringcache/cli/compare/v1.20.0...v1.20.1
[1.20.0]: https://github.com/boringcache/cli/compare/v1.19.7...v1.20.0
[1.19.7]: https://github.com/boringcache/cli/releases/tag/v1.19.7
[1.19.6]: https://github.com/boringcache/cli/releases/tag/v1.19.6
