#!/bin/sh
# BoringCache CLI Installation Script
# Usage: curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" https://install.boringcache.com/install.sh | sh
# Strict: curl -sSL https://install.boringcache.com/install.sh | BORINGCACHE_VERIFY_SIGNATURE=1 sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub repository
REPO="boringcache/cli"
BINARY_NAME="boringcache"
CHECKSUM_CERTIFICATE_IDENTITY_REGEXP='^https://github\.com/boringcache/monorepo/\.github/workflows/(cli-release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+|cli-release-checksums\.yml@refs/heads/main)$'
CHECKSUM_CERTIFICATE_OIDC_ISSUER='https://token.actions.githubusercontent.com'
VERIFY_CHECKSUM_SIGNATURE=0

# Function to print colored output
print_status() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

print_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

print_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

# Function to detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "darwin";;
        CYGWIN*)    echo "windows";;
        MINGW*)     echo "windows";;
        MSYS*)      echo "windows";;
        *)          echo "unknown";;
    esac
}

# Function to detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64";;
        aarch64|arm64)  echo "arm64";;
        armv7l)         echo "unknown";;  # 32-bit ARM currently unsupported
        *)              echo "unknown";;  # Default fallback for unsupported architectures
    esac
}

# Function to get the latest release tag
get_latest_release() {
    local repo="$1"
    
    # Try to get latest release from GitHub API
    local response=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null || true)
    
    # Check if API call was successful
    if echo "$response" | grep -q '"tag_name":'; then
        echo "$response" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
        return 0
    fi
    
    # If API fails (e.g., private repo), fall back to known version
    # This should be updated when new versions are released
    local fallback_version="v1.13.100"
    
    print_warning "GitHub API unavailable, using fallback version: $fallback_version" >&2
    print_warning "This may not be the latest version. Check https://github.com/${repo}/releases manually." >&2

    echo "$fallback_version"
}

download_file() {
    local url="$1"
    local output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${url}" -o "${output}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${url}" -O "${output}"
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
}

verify_checksum() {
    local temp_dir="$1"
    local binary_name="$2"
    local checksum_file="${temp_dir}/SHA256SUMS"

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "${temp_dir}" && grep "  ${binary_name}$" SHA256SUMS | sha256sum -c -) >/dev/null
    elif command -v shasum >/dev/null 2>&1; then
        local expected
        local actual
        expected=$(grep "  ${binary_name}$" "${checksum_file}" | awk '{print $1}')
        actual=$(shasum -a 256 "${temp_dir}/${binary_name}" | awk '{print $1}')
        [ -n "${expected}" ] && [ "${expected}" = "${actual}" ]
    else
        print_error "Neither sha256sum nor shasum found. Cannot verify release checksum."
        exit 1
    fi
}

prepare_checksum_signature_verification() {
    VERIFY_CHECKSUM_SIGNATURE=0

    case "${BORINGCACHE_VERIFY_SIGNATURE:-auto}" in
        auto)
            if command -v cosign >/dev/null 2>&1; then
                VERIFY_CHECKSUM_SIGNATURE=1
                print_status "cosign found; release signature verification is enabled."
            else
                print_warning "cosign not found; continuing with SHA-256 checksum verification."
                print_warning "Install cosign and set BORINGCACHE_VERIFY_SIGNATURE=1 for fail-closed signature verification."
            fi
            ;;
        1|true|required)
            if ! command -v cosign >/dev/null 2>&1; then
                print_error "BORINGCACHE_VERIFY_SIGNATURE=1 requires cosign in PATH."
                return 1
            fi
            VERIFY_CHECKSUM_SIGNATURE=1
            ;;
        0|false|off)
            ;;
        *)
            print_error "BORINGCACHE_VERIFY_SIGNATURE must be auto, 1, or 0."
            return 1
            ;;
    esac
}

verify_checksum_signature() {
    local temp_dir="$1"

    if [ "${VERIFY_CHECKSUM_SIGNATURE}" != "1" ]; then
        return 0
    fi

    if [ ! -s "${temp_dir}/SHA256SUMS.bundle" ]; then
        print_error "Signed checksum bundle is missing or empty."
        return 1
    fi

    cosign verify-blob \
        --bundle "${temp_dir}/SHA256SUMS.bundle" \
        --certificate-identity-regexp "${CHECKSUM_CERTIFICATE_IDENTITY_REGEXP}" \
        --certificate-oidc-issuer "${CHECKSUM_CERTIFICATE_OIDC_ISSUER}" \
        "${temp_dir}/SHA256SUMS" >/dev/null
}

# Function to download and install binary
install_binary() {
    local os="$1"
    local arch="$2"
    local version="$3"
    
    # Map OS and architecture to actual binary names
    local binary_name=""
    
    case "${os}-${arch}" in
        "darwin-amd64"|"darwin-arm64")
            binary_name="boringcache-macos-universal"
            ;;
        "linux-amd64")
            if [ -f /etc/alpine-release ]; then
                binary_name="boringcache-linux-musl-amd64"
            else
                binary_name="boringcache-linux-amd64"
            fi
            ;;
        "linux-arm64")
            if [ -f /etc/alpine-release ]; then
                binary_name="boringcache-linux-musl-arm64"
            else
                binary_name="boringcache-linux-arm64"
            fi
            ;;
        "windows-amd64")
            binary_name="boringcache-windows-amd64.exe"
            ;;
        "windows-arm64")
            binary_name="boringcache-windows-arm64.exe"
            ;;
        *)
            print_error "Unsupported platform: ${os}-${arch}"
            print_error "Please download manually from: https://github.com/${REPO}/releases"
            exit 1
            ;;
    esac
    
    local release_url="https://github.com/${REPO}/releases/download/${version}"
    local download_url="${release_url}/${binary_name}"
    
    print_status "Downloading ${binary_name} from ${download_url}..."
    
    # Create temporary directory
    local temp_dir=$(mktemp -d)
    local temp_file="${temp_dir}/${binary_name}"

    if ! prepare_checksum_signature_verification; then
        rm -rf "${temp_dir}"
        exit 1
    fi
    
    download_file "${download_url}" "${temp_file}"
    download_file "${release_url}/SHA256SUMS" "${temp_dir}/SHA256SUMS"
    if [ "${VERIFY_CHECKSUM_SIGNATURE}" = "1" ]; then
        if ! download_file "${release_url}/SHA256SUMS.bundle" "${temp_dir}/SHA256SUMS.bundle"; then
            rm -f "${temp_dir}/SHA256SUMS.bundle"
            print_error "Signed checksum bundle is unavailable for ${version}."
            rm -rf "${temp_dir}"
            exit 1
        fi
    fi
    
    # Check if download was successful
    if [ ! -f "${temp_file}" ] || [ ! -s "${temp_file}" ]; then
        print_error "Failed to download ${binary_name}"
        print_error "Please check if the release exists at: ${download_url}"
        exit 1
    fi

    if ! verify_checksum_signature "${temp_dir}"; then
        print_error "Checksum signature verification failed"
        exit 1
    fi

    if ! verify_checksum "${temp_dir}" "${binary_name}"; then
        print_error "Checksum verification failed for ${binary_name}"
        exit 1
    fi
    
    # Make binary executable
    chmod +x "${temp_file}"
    
    # Determine install directory
    local install_dir
    if [ -w "/usr/local/bin" ]; then
        install_dir="/usr/local/bin"
    elif [ -d "$HOME/.local/bin" ]; then
        install_dir="$HOME/.local/bin"
        mkdir -p "$install_dir"
    elif [ -d "$HOME/bin" ]; then
        install_dir="$HOME/bin"
    else
        install_dir="$HOME/.local/bin"
        mkdir -p "$install_dir"
    fi
    
    local final_binary="${install_dir}/${BINARY_NAME}"
    
    # Install the binary
    print_status "Installing to ${final_binary}..."
    
    if [ "$install_dir" = "/usr/local/bin" ] && [ ! -w "/usr/local/bin" ]; then
        # Need sudo for /usr/local/bin
        sudo mv "${temp_file}" "${final_binary}"
    else
        mv "${temp_file}" "${final_binary}"
    fi
    
    # Cleanup
    rm -rf "${temp_dir}"
    
    print_success "BoringCache CLI installed successfully!"
    print_status "Binary location: ${final_binary}"
    
    # Check if install directory is in PATH
    case ":$PATH:" in
        *":${install_dir}:"*)
            print_success "✓ Install directory is in your PATH"
            ;;
        *)
            print_warning "⚠ Install directory '${install_dir}' is not in your PATH"
            print_warning "Add it to your PATH by adding this line to your shell profile:"
            print_warning "  export PATH=\"${install_dir}:\$PATH\""
            ;;
    esac
    
    # Test the installation
    if command -v "${BINARY_NAME}" >/dev/null 2>&1 && "${BINARY_NAME}" --version >/dev/null 2>&1; then
        print_success "✓ Installation verified - 'boringcache --version' succeeded"
        print_status "Run 'boringcache --help' to get started"
    else
        print_warning "⚠ 'boringcache' command not found in PATH"
        print_warning "You may need to restart your terminal or run:"
        print_warning "  export PATH=\"${install_dir}:\$PATH\""
    fi
}

# Main installation process
main() {
    print_status "🚀 Installing BoringCache CLI..."
    
    # Detect platform
    OS=$(detect_os)
    ARCH=$(detect_arch)
    
    print_status "Detected platform: ${OS}-${ARCH}"
    
    # Check if platform is supported
    case "$OS" in
        linux|darwin)
            ;;
        windows)
            print_warning "Windows installation via this script is experimental"
            print_warning "Consider downloading the binary manually from GitHub releases"
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            print_error "Supported platforms: linux, darwin (macOS)"
            exit 1
            ;;
    esac
    
    # Get latest release version
    print_status "Fetching latest release information..."
    VERSION=$(get_latest_release "$REPO")
    
    if [ -z "$VERSION" ]; then
        print_error "Failed to get latest release version"
        print_error "Please check your internet connection or try again later"
        exit 1
    fi
    
    print_status "Latest version: $VERSION"
    
    # Install the binary
    install_binary "$OS" "$ARCH" "$VERSION"
    
    # Show next steps
    echo
    print_success "🎉 Installation complete!"
    echo
    print_status "Next steps:"
    print_status "1. Move into an existing project repo."
    echo
    print_status "2. Connect the CLI:"
    print_status "   ${BINARY_NAME} onboard"
    echo
    print_status "3. Wrap one repeated step:"
    print_status "   ${BINARY_NAME} run -- bundle install"
    echo
    print_status "📖 Docs: https://boringcache.com/docs"
}

if [ "${BORINGCACHE_INSTALLER_SOURCE_ONLY:-0}" != "1" ]; then
    main "$@"
fi
