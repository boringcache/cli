# BoringCache CLI Installation Setup

This document describes how to set up the
`curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" https://install.boringcache.com/install.sh | sh`
installation method for the BoringCache CLI. The explicit no-cache headers ensure
Cloudflare (or any intermediary CDN) revalidates the script on each install.

## Files Overview

- `install.sh` - The installation script that users will curl and execute
- `install-web/` - Static website files for the installation page
- `install-web/index.html` - Landing page with installation instructions and manual download links

## Setup Instructions

### 1. Domain Setup

You'll need to configure `install.boringcache.com/install.sh` to serve the installation script. Here are a few options:

#### Option A: GitHub Pages (Recommended)
1. Create a new repository `boringcache/install` 
2. Upload `install.sh` and `install-web/` contents to the repository
3. Enable GitHub Pages to serve from the main branch
4. Configure custom domain `install.boringcache.com/install.sh` in repository settings
5. Add CNAME record in DNS: `install.boringcache.com/install.sh` → `boringcache.github.io`

#### Option B: Cloudflare Pages
1. Connect the CLI repository to Cloudflare Pages
2. Set build command to copy installation files to output directory
3. Configure custom domain `install.boringcache.com/install.sh`

#### Option C: Simple Static Hosting
Use any static file hosting service (Netlify, Vercel, etc.) to serve:
- Root path `/` serves `install.sh` with `Content-Type: text/plain`
- Path `/web` serves `install-web/index.html`

### 2. Web Server Configuration

The installation script should be served with proper headers:

```nginx
# Nginx example
location = / {
    add_header Content-Type text/plain;
    try_files /install.sh =404;
}

location /web/ {
    try_files $uri $uri/ /install-web/index.html;
}
```

### 3. DNS Configuration

Add these DNS records:
```
install.boringcache.com/install.sh  CNAME  your-hosting-provider.com
```

### 4. SSL Certificate

Ensure HTTPS is enabled since users will be downloading and executing scripts.

## Testing the Installation

### Test the script URL:
```bash
curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
  https://install.boringcache.com/install.sh
```

Should return the installation script content.

### Test the installation:
```bash
curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
  https://install.boringcache.com/install.sh | sh
```

Should detect platform, download appropriate binary, and install it.

### Test manual download links:
```bash
# Should redirect to latest release
curl -I https://github.com/boringcache/cli/releases/latest/download/boringcache-linux-amd64
```

## Platform Support

The installation script supports:

- **Linux**: AMD64, ARM64
- **macOS**: Apple Silicon (ARM64)
- **Windows**: AMD64 (experimental, manual download recommended)

## Binary Names

The GitHub release workflow creates these binaries:
- `boringcache-linux-amd64`
- `boringcache-linux-arm64`
- `boringcache-ubuntu-22.04-amd64`
- `boringcache-ubuntu-22.04-arm64`
- `boringcache-ubuntu-24.04-amd64`
- `boringcache-ubuntu-24.04-arm64`
- `boringcache-ubuntu-25.04-amd64`
- `boringcache-ubuntu-25.04-arm64`
- `boringcache-debian-bookworm-amd64`
- `boringcache-debian-bookworm-arm64`
- `boringcache-debian-bullseye-amd64`
- `boringcache-debian-bullseye-arm64`
- `boringcache-alpine-amd64`
- `boringcache-arch-amd64`
- `boringcache-arch-arm64`
- `boringcache-macos-14-arm64`
- `boringcache-macos-15-arm64`
- `boringcache-windows-2022-amd64.exe`

## Installation Locations

The script installs to the first writable location:
1. `/usr/local/bin` (with sudo if needed)
2. `$HOME/.local/bin`
3. `$HOME/bin`

## Security Considerations

- Downloads over HTTPS only
- Provides warning about piping curl to shell
- Shows installation path and PATH information
- Includes verification step after installation
- No checksum verification yet (consider adding release checksums)

## Maintenance

- Update `REPO` variable in `install.sh` if repository moves
- Update download links in `index.html` if repository moves
- Monitor GitHub API rate limits for release fetching
- Consider adding checksum validation for extra security

## Future Enhancements

- Add checksum validation using GitHub release checksums
- Support for installing specific versions
- Package manager installations (brew, apt, etc.)
- Windows MSI installer
- Auto-update mechanism in the CLI itself
