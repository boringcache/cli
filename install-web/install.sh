#!/bin/sh
# BoringCache CLI Installation Script
# Usage: curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" https://install.boringcache.com/install.sh | sh

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
        armv7l)         echo "arm64";;  # Fallback for some ARM systems
        *)              echo "amd64";;  # Default fallback
    esac
}

# Function to get the latest release tag
get_latest_release() {
    local repo="$1"
    
    # Try to get latest release from GitHub API
    local response=$(curl -s "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null)
    
    # Check if API call was successful
    if echo "$response" | grep -q '"tag_name":'; then
        echo "$response" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
        return 0
    fi
    
    # If API fails (e.g., private repo), fall back to known version
    # This should be updated when new versions are released
    local fallback_version="v1.5.0"
    
    print_warning "GitHub API unavailable, using fallback version: $fallback_version"
    print_warning "This may not be the latest version. Check https://github.com/${repo}/releases manually."
    
    echo "$fallback_version"
}

# Function to download and install binary
install_binary() {
    local os="$1"
    local arch="$2"
    local version="$3"
    
    # Map OS and architecture to actual binary names
    local binary_name=""
    
    case "${os}-${arch}" in
        "darwin-amd64")
            print_error "macOS Intel builds are no longer published. Please build from source or run under Rosetta."
            exit 1
            ;;
        "darwin-arm64")
            # Prefer binaries that match the host OS generation
            macos_major=$(sw_vers -productVersion 2>/dev/null | cut -d'.' -f1)
            if [ -n "$macos_major" ] && [ "$macos_major" -lt 15 ]; then
                binary_name="boringcache-macos-14-arm64"
            else
                binary_name="boringcache-macos-15-arm64"
            fi
            ;;
        "linux-amd64")
            # Detect specific Linux distribution for better binary selection
            if [ -f /etc/arch-release ]; then
                binary_name="boringcache-arch-amd64"
            elif [ -f /etc/alpine-release ]; then
                binary_name="boringcache-alpine-amd64"
            elif [ -f /etc/debian_version ]; then
                # Check if it's Debian or Ubuntu
                if grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
                    # Ubuntu detection - try to get specific version
                    if grep -q "22.04" /etc/os-release 2>/dev/null; then
                        binary_name="boringcache-ubuntu-22.04-amd64"
                    elif grep -q "24.04" /etc/os-release 2>/dev/null; then
                        binary_name="boringcache-ubuntu-24.04-amd64"
                    else
                        # Default to 22.04 for other Ubuntu versions
                        binary_name="boringcache-ubuntu-22.04-amd64"
                    fi
                else
                    # Debian detection - check specific version
                    if grep -q "bullseye" /etc/os-release 2>/dev/null || grep -q "11" /etc/debian_version 2>/dev/null; then
                        binary_name="boringcache-debian-bullseye-amd64"
                    elif grep -q "bookworm" /etc/os-release 2>/dev/null || grep -q "12" /etc/debian_version 2>/dev/null; then
                        binary_name="boringcache-debian-bookworm-amd64"
                    else
                        # Default to bookworm for newer Debian versions
                        binary_name="boringcache-debian-bookworm-amd64"
                    fi
                fi
            else
                # Default fallback to generic Linux (Ubuntu 22.04 base)
                binary_name="boringcache-linux-amd64"
            fi
            ;;
        "linux-arm64")
            # Detect specific Linux distribution for better binary selection
            if [ -f /etc/arch-release ]; then
                binary_name="boringcache-arch-arm64"
            elif [ -f /etc/debian_version ]; then
                # Check if it's Debian or Ubuntu
                if grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
                    # Ubuntu detection - try to get specific version
                    if grep -q "22.04" /etc/os-release 2>/dev/null; then
                        binary_name="boringcache-ubuntu-22.04-arm64"
                    elif grep -q "24.04" /etc/os-release 2>/dev/null; then
                        binary_name="boringcache-ubuntu-24.04-arm64"
                    else
                        # Default to 22.04 for other Ubuntu versions
                        binary_name="boringcache-ubuntu-22.04-arm64"
                    fi
                else
                    # Debian detection - check specific version
                    if grep -q "bullseye" /etc/os-release 2>/dev/null || grep -q "11" /etc/debian_version 2>/dev/null; then
                        binary_name="boringcache-debian-bullseye-arm64"
                    elif grep -q "bookworm" /etc/os-release 2>/dev/null || grep -q "12" /etc/debian_version 2>/dev/null; then
                        binary_name="boringcache-debian-bookworm-arm64"
                    else
                        # Default to bookworm for newer Debian versions
                        binary_name="boringcache-debian-bookworm-arm64"
                    fi
                fi
            else
                # Default fallback to generic Linux (Ubuntu 22.04 base)
                binary_name="boringcache-linux-arm64"
            fi
            ;;
        "windows-amd64")
            binary_name="boringcache-windows-2022-amd64.exe"
            ;;
        *)
            print_error "Unsupported platform: ${os}-${arch}"
            print_error "Please download manually from: https://github.com/${REPO}/releases"
            exit 1
            ;;
    esac
    
    local download_url="https://github.com/${REPO}/releases/download/${version}/${binary_name}"
    
    print_status "Downloading ${binary_name} from ${download_url}..."
    
    # Create temporary directory
    local temp_dir=$(mktemp -d)
    local temp_file="${temp_dir}/${binary_name}"
    
    # Download the binary
    if command -v curl >/dev/null 2>&1; then
        curl -sL "${download_url}" -o "${temp_file}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${download_url}" -O "${temp_file}"
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    
    # Check if download was successful
    if [ ! -f "${temp_file}" ] || [ ! -s "${temp_file}" ]; then
        print_error "Failed to download ${binary_name}"
        print_error "Please check if the release exists at: ${download_url}"
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
    if command -v "${BINARY_NAME}" >/dev/null 2>&1; then
        print_success "✓ Installation verified - 'boringcache' command is available"
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
    print_status "1. Authenticate with your API token:"
    print_status "   ${BINARY_NAME} auth --token YOUR_API_TOKEN"
    echo
    print_status "2. Save cache (tag:path format):"
    print_status "   ${BINARY_NAME} save my-workspace \"node-deps:node_modules,build-cache:target\""
    echo
    print_status "3. Restore cache (tag:path format):"
    print_status "   ${BINARY_NAME} restore my-workspace \"node-deps:node_modules,build-cache:target\""
    echo
    print_status "📖 For more information, visit: https://github.com/${REPO}"
}

# Run main function
main "$@"
