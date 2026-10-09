# Changelog

All notable changes to BoringCache CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


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

[Unreleased]: https://github.com/boringcache/cli/compare/v1.40.2...HEAD
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
