# Comprehensive QA Plan: CLI Encryption, Signing & Security

## Executive Summary

This QA plan covers critical CLI security features for production launch:
1. **Client-Side Encryption** - Age X25519 encryption (workspace-scoped)
2. **Server-Driven Signing** - Ed25519 artifact signing (workspace-scoped)
3. **Adaptive Controls** - Performance tuning from small CI runners to large machines
4. **CLI Command Structure** - Positional arguments, env overrides, config precedence
5. **Security Hardening** - File permissions, key management, TLS

**Core Requirements**:
- Encryption MUST be workspace-scoped and automatically applied when configured
- Signature verification failures should WARN, not block (server-signed)
- Adaptive controls must gracefully handle 1-core/512MB CI runners to 64-core workstations
- Config precedence: CLI args > env vars > config file > defaults

---

## Part 1: Architecture Overview

### 1.1 Encryption Architecture

```
+------------------------------------------------------------------+
|                    CLIENT-SIDE ENCRYPTION FLOW                     |
+------------------------------------------------------------------+
|                                                                    |
|  boringcache setup-encryption <workspace>                          |
|           |                                                        |
|           v                                                        |
|  +------------------------+                                        |
|  | Generate Age Keypair   |                                        |
|  | (X25519 ECDH)          |                                        |
|  +------------------------+                                        |
|           |                                                        |
|           v                                                        |
|  +-----------------------------+   +----------------------------+  |
|  | Save Identity (Private Key) |   | Store Recipient in Config  |  |
|  | ~/.boringcache/age-identity |   | workspace_encryption map   |  |
|  | Permissions: 0o600          |   | { workspace: { enabled,    |  |
|  +-----------------------------+   |   recipient: "age1..." } } |  |
|                                    +----------------------------+  |
|                                                                    |
+------------------------------------------------------------------+
|                                                                    |
|                       SAVE FLOW (Encrypt)                          |
|                                                                    |
|  Files --> TAR+ZSTD --> Age Encrypt --> Upload                    |
|                   (using workspace recipient)                      |
|                                                                    |
|  Manifest --> CBOR --> ZSTD --> Age Encrypt --> Upload            |
|                                                                    |
+------------------------------------------------------------------+
|                                                                    |
|                     RESTORE FLOW (Decrypt)                         |
|                                                                    |
|  Download --> Detect Age Header --> Load Identity --> Decrypt      |
|                      |                                             |
|                      v                                             |
|  Identity Resolution:                                              |
|    1. --identity flag                                              |
|    2. config.default_age_identity                                  |
|    3. ~/.boringcache/age-identity.txt                              |
|                                                                    |
+------------------------------------------------------------------+
```

### 1.2 Server-Driven Signing Architecture

```
+------------------------------------------------------------------+
|                    SERVER-DRIVEN SIGNING FLOW                      |
+------------------------------------------------------------------+
|                                                                    |
|  Server Side (Per-Workspace):                                      |
|  +---------------------------+                                     |
|  | Generate Ed25519 Keypair  |                                     |
|  | - Private key: server-only|                                     |
|  | - Public key: sent to CLI |                                     |
|  +---------------------------+                                     |
|           |                                                        |
|           v                                                        |
|  On Cache Save (Server):                                           |
|  +---------------------------+                                     |
|  | Sign: "{tag}:{digest}"    |                                     |
|  | Store signature in entry  |                                     |
|  +---------------------------+                                     |
|                                                                    |
|  On Cache Restore (CLI):                                           |
|  +---------------------------+                                     |
|  | Response includes:        |                                     |
|  | - workspace_signing_key   |                                     |
|  | - server_signature        |                                     |
|  +---------------------------+                                     |
|           |                                                        |
|           v                                                        |
|  +---------------------------+                                     |
|  | verify_server_signature() |                                     |
|  | - Parse public key        |                                     |
|  | - Verify "{tag}:{digest}" |                                     |
|  | - WARN on failure         |                                     |
|  +---------------------------+                                     |
|                                                                    |
+------------------------------------------------------------------+
```

### 1.3 Config Precedence

```
Priority (highest to lowest):
1. CLI Flag:           --recipient "age1..."
2. Environment Var:    BORINGCACHE_API_TOKEN, BORINGCACHE_DEFAULT_WORKSPACE
3. Config File:        ~/.boringcache/config.json
4. Default Value:      API URL = https://api.boringcache.com/v1
```

---

## Part 2: CLI Command Structure Review

### 2.1 Command Structure Matrix

| Command | Positional Args | Env Override | Config Fallback |
|---------|-----------------|--------------|-----------------|
| `auth` | None (--token required) | BORINGCACHE_API_TOKEN | config.token |
| `save` | `<workspace> <tag:path,...>` | BORINGCACHE_DEFAULT_WORKSPACE | config.default_workspace |
| `restore` | `<workspace> <tag:path,...>` | BORINGCACHE_DEFAULT_WORKSPACE | config.default_workspace |
| `check` | `<workspace> <tags,...>` | BORINGCACHE_DEFAULT_WORKSPACE | config.default_workspace |
| `delete` | `<workspace> <tags,...>` | BORINGCACHE_DEFAULT_WORKSPACE | config.default_workspace |
| `ls` | `[workspace]` | BORINGCACHE_DEFAULT_WORKSPACE | config.default_workspace |
| `mount` | `<workspace> <tag:path>` | BORINGCACHE_DEFAULT_WORKSPACE | config.default_workspace |
| `setup-encryption` | `[workspace]` | BORINGCACHE_DEFAULT_WORKSPACE | config.default_workspace |
| `config get/set/list` | `<key> [value]` | N/A | N/A |
| `workspaces` | None | N/A | N/A |

### 2.2 Workspace Injection Logic (main.rs:48-85)

```rust
// Commands with automatic workspace injection:
// - save, restore: when 1 positional arg contains ':'
// - delete, check: when 1 positional arg doesn't contain '/'
// - ls: when no positional args
```

### 2.3 Environment Variables

| Variable | Purpose | Used In |
|----------|---------|---------|
| `BORINGCACHE_API_TOKEN` | API authentication | config.rs:45 |
| `BORINGCACHE_API_URL` | API endpoint override | config.rs:46-47 |
| `BORINGCACHE_DEFAULT_WORKSPACE` | Default workspace | main.rs:15, config.rs:51,77 |
| `BORINGCACHE_TELEMETRY_DISABLED` | Disable telemetry | telemetry.rs |
| `BORINGCACHE_DEBUG_TELEMETRY` | Debug telemetry output | telemetry.rs |
| `BORINGCACHE_NO_GIT` | Disable git-based tagging | git.rs |
| `CI` | CI environment detection | resources.rs:87, restore.rs:1415 |
| `HOME` | Home directory fallback | config.rs:248 |

---

## Part 3: Encryption QA Tests

### 3.1 Workspace-Scoped Encryption Configuration

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| ENC-001 | `setup-encryption <workspace>` first time | Generates keypair, saves identity, stores recipient in config | P0 |
| ENC-002 | `setup-encryption` with existing identity | Uses existing identity, extracts recipient | P0 |
| ENC-003 | `setup-encryption --identity-output /custom/path` | Saves to custom path | P1 |
| ENC-004 | Verify identity file permissions (Unix) | 0o600 enforced | P0 |
| ENC-005 | Verify config file permissions (Unix) | 0o600 enforced | P0 |
| ENC-006 | **Encryption auto-enabled per workspace** | `workspace_encryption[ws].enabled = true` | **P0** |
| ENC-007 | **Different encryption keys per workspace** | Each workspace can have unique recipient | **P0** |
| ENC-008 | setup-encryption without workspace arg | Falls back to default_workspace | P1 |
| ENC-009 | setup-encryption with no default workspace | Clear error message | P1 |

### 3.2 Encryption During Save

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| ENC-010 | Save with workspace encryption enabled | Archive + manifest encrypted | P0 |
| ENC-011 | Save with --recipient override | Uses explicit recipient | P0 |
| ENC-012 | Save to workspace without encryption config | No encryption applied | P0 |
| ENC-013 | **Verify Age header in encrypted archive** | Starts with `age-encryption.org/` | **P0** |
| ENC-014 | Verify encryption_metadata in manifest | algorithm, recipient_hint, encrypted_at | P0 |
| ENC-015 | Save request includes encrypted=true | API knows entry is encrypted | P0 |
| ENC-016 | Recipient hint truncation | Shows `age1ql...ac8p` format | P1 |

### 3.3 Decryption During Restore

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| ENC-020 | Restore encrypted cache with correct identity | Decrypts successfully | P0 |
| ENC-021 | Restore encrypted cache with --identity flag | Uses specified identity | P0 |
| ENC-022 | Restore encrypted cache with config identity | Uses config.default_age_identity | P0 |
| ENC-023 | Restore encrypted cache with default path | Uses ~/.boringcache/age-identity.txt | P0 |
| ENC-024 | **Restore encrypted cache without identity** | Clear error: "requires an identity file" | **P0** |
| ENC-025 | Restore with wrong identity | Error: "wrong key" | P0 |
| ENC-026 | Auto-detect encryption (is_age_encrypted) | Checks AGE_MAGIC bytes | P0 |
| ENC-027 | Restore non-encrypted to encrypted workspace | Works (no decryption needed) | P1 |

### 3.4 Passphrase-Protected Identities

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| ENC-030 | Restore with passphrase-protected identity (terminal) | Prompts for passphrase | P1 |
| ENC-031 | Restore with passphrase (non-terminal/CI) | Skips prompt, returns None | P1 |
| ENC-032 | **PassphraseCache prevents repeated prompts** | Single prompt per session | **P1** |
| ENC-033 | Empty passphrase entered | Treated as skip | P1 |
| ENC-034 | Wrong passphrase entered | Error: "wrong passphrase" | P1 |

### 3.5 Encryption Edge Cases

| ID | Scenario | Risk | Expected Behavior | Priority |
|----|----------|------|-------------------|----------|
| ENC-040 | **Identity file with insecure permissions** | Security | Error on load: "chmod 600" | **P0** |
| ENC-041 | Identity file not found at explicit path | Config error | Clear file path in error | P0 |
| ENC-042 | Malformed identity file | Parsing | Error: "Invalid Age identity" | P0 |
| ENC-043 | Invalid recipient string | Parsing | Error: "Invalid Age recipient" | P0 |
| ENC-044 | Very large file encryption | Memory | Stream encryption works | P1 |
| ENC-045 | Unicode in paths with encryption | Compatibility | Works correctly | P1 |
| ENC-046 | Windows path separators with encryption | Cross-platform | Works correctly | P1 |

---

## Part 4: Server-Driven Signing QA Tests

### 4.1 Signature Verification on Restore

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| SIG-001 | Restore with valid signature | Signature verified, verbose shows fingerprint | P0 |
| SIG-002 | **Restore with invalid signature** | WARNING shown, restore continues | **P0** |
| SIG-003 | Restore with missing signature | WARNING: "signature missing" | P0 |
| SIG-004 | Restore with missing workspace key | WARNING: "cannot verify" | P0 |
| SIG-005 | Restore with both key and signature missing | No warning (unsigned entry) | P1 |
| SIG-006 | Verify signed data format | `"{tag}:{manifest_root_digest}"` | P0 |

### 4.2 Signature Format Tests

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| SIG-010 | Parse ed25519: prefixed public key | Extracts base64, decodes 32 bytes | P0 |
| SIG-011 | Parse raw base64 public key | Works without prefix | P1 |
| SIG-012 | Invalid public key length (!= 32) | Error: "expected 32 bytes" | P0 |
| SIG-013 | Invalid signature length (!= 64) | Error: "expected 64 bytes" | P0 |
| SIG-014 | Base64 decode failure | Error: "Failed to decode" | P0 |
| SIG-015 | Public key fingerprint format | `ed25519:XXXX...YYYY` | P1 |

### 4.3 Signing Key Operations (for testing)

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| SIG-020 | generate_keypair() | Returns valid SigningKey + VerifyingKey | P0 |
| SIG-021 | sign_data() + verify_signature() roundtrip | Verification succeeds | P0 |
| SIG-022 | Verify with wrong data | Verification fails | P0 |
| SIG-023 | Verify with wrong key | Verification fails | P0 |
| SIG-024 | Signing key save with 0o600 permissions | Permissions set correctly | P1 |

---

## Part 5: Adaptive Controls QA Tests

### 5.1 System Resource Detection

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| ADP-001 | Detect CPU cores | Returns positive integer | P0 |
| ADP-002 | Detect available memory (macOS) | Parses sysctl hw.memsize | P0 |
| ADP-003 | Detect available memory (Linux) | Parses /proc/meminfo MemAvailable | P0 |
| ADP-004 | Detect CPU load (Unix) | Parses uptime load average | P1 |
| ADP-005 | Detect disk type (macOS) | system_profiler SPStorageDataType | P1 |
| ADP-006 | Detect disk type (Linux) | /sys/block/*/queue/rotational | P1 |
| ADP-007 | **Fallback when detection fails** | Safe defaults (2GB RAM, 50% CPU) | **P0** |

### 5.2 Memory Strategy Selection

| ID | Scenario | Strategy | Buffer Size | Multipart Threshold |
|----|----------|----------|-------------|---------------------|
| ADP-010 | RAM < 12GB | Balanced | 64 MB | 2 MB |
| ADP-011 | RAM 12-24GB | Aggressive | 256 MB | 1 MB |
| ADP-012 | RAM >= 24GB | UltraAggressive | 512 MB | 512 KB |

### 5.3 Parallel Chunk Calculation

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| ADP-020 | Balanced + 4 cores | min(4, 8) = 4 chunks | P0 |
| ADP-021 | Aggressive + 8 cores | min(8+2, 12) = 10 chunks | P0 |
| ADP-022 | UltraAggressive + 16 cores | min(16+4, 16) = 16 chunks | P0 |
| ADP-023 | **High CPU load (>80%)** | Chunks halved | **P0** |
| ADP-024 | 1-core machine | At least 1 chunk | P0 |

### 5.4 Download Concurrency (CI vs Local)

| ID | Scenario | Expected Range | Priority |
|----|----------|----------------|----------|
| ADP-030 | CI + 2 cores + 4GB RAM | 2 | P0 |
| ADP-031 | CI + 8 cores + 16GB RAM | 4 (capped for CI) | P0 |
| ADP-032 | Local + 8 cores + 32GB RAM + NVMe | 8-12 | P0 |
| ADP-033 | Local + 4 cores + 8GB RAM + SATA | 4 (SATA cap) | P0 |
| ADP-034 | **Memory < 4GB** | Capped at 2 | **P0** |
| ADP-035 | **Memory < 8GB** | Capped at 4 | **P0** |
| ADP-036 | **CPU load > 75%** | Reduced by 1 | **P0** |

### 5.5 Parallel Extraction Control

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| ADP-040 | CI environment | Parallel extraction disabled | P0 |
| ADP-041 | Memory < 4GB | Parallel extraction disabled | P0 |
| ADP-042 | >= 2 cores + >= 4GB + non-CI | Parallel extraction enabled | P0 |
| ADP-043 | 1 core machine | Parallel extraction disabled | P1 |

### 5.6 Small Machine Edge Cases (CI Runners)

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| ADP-050 | **GitHub Actions runner (2 cores, 7GB)** | Balanced strategy, 2 concurrent downloads | **P0** |
| ADP-051 | **CircleCI small (1 core, 2GB)** | Balanced, 1-2 concurrent, no parallel extract | **P0** |
| ADP-052 | **Self-hosted runner (32 cores, 64GB)** | UltraAggressive, up to 16 concurrent | **P0** |
| ADP-053 | Container with cgroup limits | Respects visible cores/memory | P1 |
| ADP-054 | ARM64 CI runner (e.g., Buildjet) | Same adaptive logic applies | P1 |

### 5.7 Disk Type Impact

| ID | Scenario | Max Concurrency | Priority |
|----|----------|-----------------|----------|
| ADP-060 | NVMe SSD detected | Up to 12 | P0 |
| ADP-061 | SATA SSD detected | Up to 4 | P0 |
| ADP-062 | Unknown disk type | Defaults to SATA SSD | P1 |

---

## Part 6: CLI Command Structure & Parsing Tests

### 6.1 Positional Argument Parsing

| ID | Command | Input | Expected Parse | Priority |
|----|---------|-------|----------------|----------|
| CLI-001 | `save` | `org/ws ruby:vendor` | workspace=org/ws, pairs=ruby:vendor | P0 |
| CLI-002 | `save` | `ruby:vendor` (default ws) | workspace=env/config, pairs=ruby:vendor | P0 |
| CLI-003 | `save` | `ruby:vendor,node:node_modules` | Multiple pairs parsed | P0 |
| CLI-004 | `restore` | `org/ws deps:./vendor` | workspace=org/ws, pairs=deps:./vendor | P0 |
| CLI-005 | `restore` | `deps` (tag only) | path defaults to "." | P0 |
| CLI-006 | `check` | `org/ws tag1,tag2` | Multiple tags parsed | P0 |
| CLI-007 | `delete` | `org/ws tag1,tag2` | Multiple tags parsed | P0 |
| CLI-008 | `ls` | (no args) | Uses default workspace | P0 |
| CLI-009 | `ls` | `org/ws` | Uses specified workspace | P0 |

### 6.2 Tag:Path Format Parsing

| ID | Input | Tag | Path | Priority |
|----|-------|-----|------|----------|
| CLI-010 | `ruby-deps:vendor/bundle` | ruby-deps | vendor/bundle | P0 |
| CLI-011 | `node_modules:./node_modules` | node_modules | ./node_modules | P0 |
| CLI-012 | `cache:~/Library/Caches` | cache | ~/Library/Caches (expanded) | P0 |
| CLI-013 | `win:C:\Users\Cache` | win | C:\Users\Cache | P0 |
| CLI-014 | `complex:path:with:colons` | complex | path:with:colons | P0 |
| CLI-015 | `:missing-tag` | Error | MissingTag | P0 |
| CLI-016 | `missing-path:` | Error | MissingPath | P0 |
| CLI-017 | `(empty)` | Error | InvalidFormat | P0 |

### 6.3 Environment Override Tests

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| CLI-020 | BORINGCACHE_API_TOKEN set, no config | Uses env token | P0 |
| CLI-021 | Both env token and config token | Env takes precedence | P0 |
| CLI-022 | BORINGCACHE_API_URL override | Uses env URL | P0 |
| CLI-023 | BORINGCACHE_DEFAULT_WORKSPACE set | Uses for workspace injection | P0 |
| CLI-024 | CI=true environment | CI detection triggers | P0 |
| CLI-025 | BORINGCACHE_NO_GIT set | Git tagging disabled | P1 |

### 6.4 Config Loading Tests

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| CLI-030 | Config file missing | ConfigNotFound error | P0 |
| CLI-031 | Config file malformed JSON | Parse error | P0 |
| CLI-032 | Config missing token field | Error on API call | P0 |
| CLI-033 | Config with workspace_encryption | Loads HashMap correctly | P0 |
| CLI-034 | Config with default_age_identity | Path available for decryption | P0 |
| CLI-035 | **Env vars merge with config** | Token from env, encryption from file | **P0** |

### 6.5 Workspace Slug Validation

| ID | Input | Expected | Priority |
|----|-------|----------|----------|
| CLI-040 | `org/project` | Valid | P0 |
| CLI-041 | `user/repo` | Valid | P0 |
| CLI-042 | `invalid` (no slash) | Error | P0 |
| CLI-043 | `/no-namespace` | Error | P0 |
| CLI-044 | `namespace/` | Error | P0 |
| CLI-045 | `org/project/extra` | Error | P0 |

---

## Part 7: Security QA Tests

### 7.1 File Permission Tests (Unix)

| ID | File | Expected Permission | Priority |
|----|------|---------------------|----------|
| SEC-001 | ~/.boringcache/config.json | 0o600 | P0 |
| SEC-002 | ~/.boringcache/age-identity.txt | 0o600 | P0 |
| SEC-003 | Signing key files | 0o600 | P0 |
| SEC-004 | **Reject identity with 0o644** | Error with chmod hint | **P0** |
| SEC-005 | **Reject identity with 0o666** | Error with chmod hint | **P0** |

### 7.2 TLS and Network Security

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| SEC-010 | API requests use HTTPS | Default URL is https:// | P0 |
| SEC-011 | Certificate validation | rustls with webpki-roots | P0 |
| SEC-012 | Bearer token in header | Authorization: Bearer <token> | P0 |
| SEC-013 | Token not logged | Not in debug/trace logs | P0 |
| SEC-014 | Secrets not in error messages | Token redacted | P0 |

### 7.3 Key Material Handling

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| SEC-020 | Identity uses SecretString | Zeroized on drop | P0 |
| SEC-021 | Passphrase uses SecretString | Zeroized on drop | P0 |
| SEC-022 | Private key not in logs | Never printed | P0 |
| SEC-023 | Recipient (public) can be logged | Safe to expose | P0 |
| SEC-024 | Identity.to_string() is secret | Uses ExposeSecret | P0 |

### 7.4 Path Traversal Prevention

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| SEC-030 | Tag with `../` | Rejected or sanitized | P0 |
| SEC-031 | Path with `../../etc/passwd` | Not written outside target | P0 |
| SEC-032 | Symlink in archive pointing outside | Handled safely | P1 |
| SEC-033 | Absolute path in tar entry | Extracted relative to target | P0 |

### 7.5 Authentication & Authorization

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| SEC-040 | Invalid token | 401 Unauthorized | P0 |
| SEC-041 | Expired token | 401 with clear message | P0 |
| SEC-042 | Token for wrong workspace | 403 Forbidden | P0 |
| SEC-043 | Rate limited | 429 with retry hint | P0 |

---

## Part 8: Performance & Edge Case Tests

### 8.1 Large File Handling

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| PERF-001 | Save 1GB cache | Streaming, no OOM | P0 |
| PERF-002 | Save 10GB cache | Multipart upload | P0 |
| PERF-003 | Restore 10GB cache | Parallel download | P0 |
| PERF-004 | 100,000 small files | Manifest handles correctly | P1 |
| PERF-005 | Single 5GB file | Works with multipart | P1 |

### 8.2 Network Resilience

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| PERF-010 | Transient 503 during upload | Retry with backoff | P0 |
| PERF-011 | Transient 429 during download | Retry with backoff | P0 |
| PERF-012 | Connection reset mid-transfer | Retry or clear error | P0 |
| PERF-013 | DNS resolution failure | Clear error message | P1 |
| PERF-014 | Timeout during large upload | Retry or resume | P1 |

### 8.3 Concurrent Operations

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| PERF-020 | 10 parallel saves to same workspace | All succeed or clear conflict | P0 |
| PERF-021 | Save and restore same tag concurrently | No corruption | P0 |
| PERF-022 | Multiple CLI instances same machine | No lock file conflicts | P1 |

### 8.4 Boundary Conditions

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| EDGE-001 | Empty directory save | Error: "0 bytes" | P0 |
| EDGE-002 | Path doesn't exist | Warning, skip | P0 |
| EDGE-003 | Restore to non-empty directory | Skip with warning | P0 |
| EDGE-004 | Restore to file (not directory) | Error | P0 |
| EDGE-005 | Tag with special characters | Validated or rejected | P0 |
| EDGE-006 | Very long tag (>256 chars) | Validated or rejected | P1 |
| EDGE-007 | Unicode in tag | Handled correctly | P1 |
| EDGE-008 | Manifest digest mismatch | Entry ignored with warning | P0 |

---

## Part 9: Platform Detection Tests

### 9.1 OS/Arch Detection

| ID | Platform | Expected Suffix | Priority |
|----|----------|-----------------|----------|
| PLAT-001 | Ubuntu 22.04 x86_64 | ubuntu-22-x86_64 | P0 |
| PLAT-002 | macOS 14 arm64 | macos-14-arm64 | P0 |
| PLAT-003 | Windows 11 x86_64 | windows-11-x86_64 | P0 |
| PLAT-004 | Alpine 3.18 x86_64 | alpine-3-x86_64 | P0 |
| PLAT-005 | Debian 12 arm64 | debian-12-arm64 | P0 |
| PLAT-006 | Arch Linux x86_64 | arch-rolling-x86_64 | P1 |

### 9.2 Distro Normalization

| ID | Detected ID | Normalized | Priority |
|----|-------------|------------|----------|
| PLAT-010 | pop | ubuntu | P1 |
| PLAT-011 | elementary | ubuntu | P1 |
| PLAT-012 | linuxmint | ubuntu | P1 |
| PLAT-013 | kali | debian | P1 |
| PLAT-014 | raspbian | debian | P1 |

### 9.3 Container Detection

| ID | Scenario | Detection Method | Priority |
|----|----------|------------------|----------|
| PLAT-020 | Docker container | /.dockerenv exists | P0 |
| PLAT-021 | Podman container | /run/.containerenv exists | P0 |
| PLAT-022 | Kubernetes pod | KUBERNETES_SERVICE_HOST set | P0 |
| PLAT-023 | Generic container | `container` env var set | P1 |
| PLAT-024 | Cgroup-based detection | /proc/1/cgroup patterns | P1 |

### 9.4 Platform Suffix Handling

| ID | Scenario | Expected Behavior | Priority |
|----|----------|-------------------|----------|
| PLAT-030 | Tag already has suffix | Don't double-append | P0 |
| PLAT-031 | --no-platform flag | No suffix appended | P0 |
| PLAT-032 | has_platform_suffix() detection | Recognizes -x86_64, -arm64, etc. | P0 |

---

## Part 10: Test Environment & Setup

### 10.1 Test Matrix

| Dimension | Values |
|-----------|--------|
| OS | Ubuntu 22.04, macOS 14, Windows 11 |
| Arch | x86_64, arm64 |
| Memory | 2GB, 8GB, 32GB |
| Cores | 1, 4, 16 |
| Disk | SATA SSD, NVMe |
| Network | Fast (1Gbps), Slow (10Mbps), Flaky |

### 10.2 CI Environment Simulation

```bash
# Simulate GitHub Actions runner
export CI=true
ulimit -v 7340032  # ~7GB memory limit
taskset -c 0,1 ./boringcache ...  # 2 cores

# Simulate minimal CI runner
export CI=true
ulimit -v 2097152  # ~2GB memory limit
taskset -c 0 ./boringcache ...  # 1 core
```

### 10.3 Mock Services Required

| Service | Purpose | Tool |
|---------|---------|------|
| S3-compatible storage | Upload/download testing | MinIO |
| API server | Mock responses | wiremock-rs |
| Slow network | Latency/timeout testing | tc/netem |

---

## Part 11: Identified Risks & Mitigations

### 11.1 Critical Risks

| Risk | Description | Impact | Mitigation | Status |
|------|-------------|--------|------------|--------|
| **R1: Identity file leaked** | Private key exposed | Full data access | 0o600 permissions, user education | Active |
| **R2: Wrong identity on restore** | Decryption fails | Data inaccessible | Clear error messages, identity resolution chain | Active |
| **R3: OOM on small CI runners** | Memory exhaustion | Build failures | Adaptive memory strategy, CI detection | Active |
| **R4: Signature bypass** | Tampered cache not detected | Supply chain risk | Warn-only is intentional (server-signed) | Acceptable |

### 11.2 Medium Risks

| Risk | Description | Impact | Mitigation | Status |
|------|-------------|--------|------------|--------|
| R5: Concurrent access to identity file | Race condition | Corruption | File locking not implemented | Monitor |
| R6: Platform detection fails in container | Wrong cache used | Cache miss | Fallback to ubuntu-22 in containers | Mitigated |
| R7: Disk type detection fails | Suboptimal concurrency | Slower transfers | Defaults to SATA SSD (conservative) | Acceptable |

---

## Part 12: Test Execution Checklist

### 12.1 Pre-Release Checklist

- [ ] All P0 encryption tests pass
- [ ] All P0 signing tests pass
- [ ] Adaptive controls tested on 2GB/1-core machine
- [ ] Adaptive controls tested on 32GB/16-core machine
- [ ] All CLI argument parsing tests pass
- [ ] All env override tests pass
- [ ] Security file permission tests pass (Unix)
- [ ] Large file (10GB) save/restore works
- [ ] CI environment (GitHub Actions) tested
- [ ] macOS, Linux, Windows binaries tested

### 12.2 Regression Tests (Run on Every Release)

| Area | Test Count | Est. Duration |
|------|------------|---------------|
| Encryption | 46 tests | 5 min |
| Signing | 24 tests | 2 min |
| Adaptive | 36 tests | 3 min |
| CLI Parsing | 45 tests | 1 min |
| Security | 25 tests | 2 min |
| Performance | 22 tests | 15 min |
| Platform | 24 tests | 3 min |
| **Total** | **222 tests** | **~31 min** |

---

## Appendix A: Code Reference Locations

| Feature | File | Key Lines |
|---------|------|-----------|
| Encryption config | src/config.rs | 16-103 |
| Age encryption | src/encryption.rs | 1-343 |
| Ed25519 signing | src/signing.rs | 1-201 |
| System resources | src/platform/resources.rs | 1-325 |
| Platform detection | src/platform/detection.rs | 1-406 |
| Container detection | src/platform/container.rs | 1-73 |
| CLI definition | src/cli.rs | 1-186 |
| Workspace injection | src/main.rs | 48-85 |
| Save command | src/commands/save.rs | 1-1035 |
| Restore command | src/commands/restore.rs | 1-1707 |
| Encryption setup | src/commands/setup_encryption.rs | 1-72 |
| Utils (parsing) | src/commands/utils.rs | 1-249 |

---

## Appendix B: Existing Unit Tests

| File | Test Count | Coverage |
|------|------------|----------|
| src/encryption.rs | 3 | ~70% |
| src/signing.rs | 4 | ~80% |
| src/platform/resources.rs | 2 | ~50% |
| src/config.rs | 6 | ~75% |
| src/commands/utils.rs | 8 | ~85% |
| src/commands/restore.rs | 8 | ~60% |

**Recommended Coverage Target**: 90% for security-critical code (encryption, signing, permissions)

---

## Sign-off

| Role | Name | Date | Status |
|------|------|------|--------|
| Security Review | | | Pending |
| QA Lead | | | Pending |
| Engineering Lead | | | Pending |
