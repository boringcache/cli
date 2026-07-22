# BoringCache CLI Installation

This repository publishes the installer and GitHub Release assets used by the
BoringCache CLI. The normal install command is:

```bash
curl -sSL https://install.boringcache.com/install.sh | sh
```

The installer always verifies `SHA256SUMS`. When `cosign` is available it also
verifies `SHA256SUMS.bundle` automatically. To make Sigstore verification
mandatory, install `cosign` first and run:

```bash
curl -sSL https://install.boringcache.com/install.sh | BORINGCACHE_VERIFY_SIGNATURE=1 sh
```

When testing the installer itself, use:

```bash
curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" https://install.boringcache.com/install.sh | sh
```

The explicit no-cache headers ensure Cloudflare or another intermediary CDN
revalidates the script on each test install.

## Files

- `install.sh` - installer script served by `install.boringcache.com`
- `install-web/` - static install page
- `README.md` and `docs/` - public CLI usage docs
- GitHub Releases - platform binaries and `SHA256SUMS`

## Testing

Test the script URL:

```bash
curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
  https://install.boringcache.com/install.sh
```

Test the latest release asset URL:

```bash
curl -I https://github.com/boringcache/cli/releases/latest/download/boringcache-linux-amd64
```

## Platform Support

Release assets currently target:

- Linux glibc: AMD64, ARM64
- Linux musl: AMD64, ARM64
- macOS universal
- Windows: AMD64, ARM64

## Binary Names

The release workflow publishes:

- `boringcache-linux-amd64`
- `boringcache-linux-arm64`
- `boringcache-linux-musl-amd64`
- `boringcache-linux-musl-arm64`
- `boringcache-macos-universal`
- `boringcache-windows-amd64.exe`
- `boringcache-windows-arm64.exe`
- `SHA256SUMS`
- `SHA256SUMS.bundle`

## Installation Locations

The script installs to the first writable location:

1. `/usr/local/bin` with `sudo` when needed
2. `$HOME/.local/bin`
3. `$HOME/bin`

## Security Notes

- Downloads use HTTPS.
- The installer always verifies the binary against `SHA256SUMS`.
- When `cosign` is available, the installer verifies `SHA256SUMS.bundle`
  automatically; `BORINGCACHE_VERIFY_SIGNATURE=1` makes this fail closed.
- Sigstore verification accepts only the monorepo CLI release workflow on a
  semantic-version tag or the checksum-repair workflow on `main`.
- The installer verifies the downloaded binary can run before finishing.
- Product source is maintained in the BoringCache monorepo; this public repo is
  the distribution channel.
- Potential vulnerabilities should be reported through the private process in
  [the security policy](.github/SECURITY.md), not a public issue.
