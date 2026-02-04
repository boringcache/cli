#!/usr/bin/env bash
#
# Release script for BoringCache CLI
#
# Usage:
#   ./scripts/release.sh patch    # 0.1.2 -> 0.1.3
#   ./scripts/release.sh minor    # 0.1.2 -> 0.2.0
#   ./scripts/release.sh major    # 0.1.2 -> 1.0.0
#   ./scripts/release.sh 0.2.0    # Explicit version
#
# This script:
#   1. Validates the working directory is clean
#   2. Runs cargo fmt --check
#   3. Runs cargo clippy
#   4. Runs cargo test
#   5. Bumps version in Cargo.toml
#   6. Updates Cargo.lock
#   7. Commits the version bump
#   8. Creates an annotated git tag
#   9. Pushes the commit and tag

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get current version from Cargo.toml
get_current_version() {
    grep '^version = ' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/version = "\(.*\)"/\1/'
}

# Parse semver components
parse_version() {
    local version="$1"
    echo "$version" | sed 's/\./ /g'
}

# Bump version based on type
bump_version() {
    local current="$1"
    local bump_type="$2"

    read -r major minor patch <<< "$(parse_version "$current")"

    case "$bump_type" in
        patch)
            patch=$((patch + 1))
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        *)
            # Assume it's an explicit version
            if [[ "$bump_type" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "$bump_type"
                return
            else
                log_error "Invalid version or bump type: $bump_type"
                log_error "Use: patch, minor, major, or explicit version (e.g., 1.2.3)"
                exit 1
            fi
            ;;
    esac

    echo "${major}.${minor}.${patch}"
}

# Update version in Cargo.toml
update_cargo_version() {
    local new_version="$1"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS sed requires empty string for -i
        sed -i '' "s/^version = \".*\"/version = \"$new_version\"/" "$PROJECT_ROOT/Cargo.toml"
    else
        sed -i "s/^version = \".*\"/version = \"$new_version\"/" "$PROJECT_ROOT/Cargo.toml"
    fi
}

# Main release function
main() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 <patch|minor|major|VERSION>"
        echo ""
        echo "Examples:"
        echo "  $0 patch    # Bump patch version (0.1.2 -> 0.1.3)"
        echo "  $0 minor    # Bump minor version (0.1.2 -> 0.2.0)"
        echo "  $0 major    # Bump major version (0.1.2 -> 1.0.0)"
        echo "  $0 0.2.0    # Set explicit version"
        exit 1
    fi

    local bump_type="$1"

    cd "$PROJECT_ROOT"

    # Step 1: Check git status
    log_info "Checking git status..."
    if [[ -n "$(git status --porcelain)" ]]; then
        log_error "Working directory is not clean. Please commit or stash changes first."
        git status --short
        exit 1
    fi

    # Ensure we're on main branch
    local current_branch
    current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "main" ]]; then
        log_warn "Not on main branch (currently on '$current_branch')"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Pull latest changes
    log_info "Pulling latest changes..."
    git pull --rebase origin "$current_branch" || true

    # Get versions
    local current_version
    current_version=$(get_current_version)
    local new_version
    new_version=$(bump_version "$current_version" "$bump_type")

    log_info "Current version: $current_version"
    log_info "New version: $new_version"

    # Check if tag already exists
    if git rev-parse "v$new_version" >/dev/null 2>&1; then
        log_error "Tag v$new_version already exists!"
        exit 1
    fi

    # Step 2: Run cargo fmt --check
    log_info "Running cargo fmt --check..."
    if ! cargo fmt -- --check; then
        log_error "Code is not formatted. Run 'cargo fmt' first."
        exit 1
    fi
    log_success "Format check passed"

    # Step 3: Run cargo clippy
    log_info "Running cargo clippy..."
    if ! cargo clippy --all-targets --all-features -- -D warnings; then
        log_error "Clippy found issues. Please fix them first."
        exit 1
    fi
    log_success "Clippy check passed"

    # Step 4: Run cargo test
    log_info "Running cargo test..."
    if ! cargo test; then
        log_error "Tests failed. Please fix them first."
        exit 1
    fi
    log_success "All tests passed"

    # Step 5-7: Update version and commit (skip if version unchanged)
    if [[ "$current_version" == "$new_version" ]]; then
        log_info "Version already set to $new_version, skipping version bump..."
    else
        log_info "Updating Cargo.toml version to $new_version..."
        update_cargo_version "$new_version"

        # Update Cargo.lock
        log_info "Updating Cargo.lock..."
        cargo update --package boring_cache_cli

        # Verify the change
        local verified_version
        verified_version=$(get_current_version)
        if [[ "$verified_version" != "$new_version" ]]; then
            log_error "Version update failed. Expected $new_version, got $verified_version"
            exit 1
        fi

        # Commit the version bump
        log_info "Committing version bump..."
        git add Cargo.toml Cargo.lock
        git commit -m "chore: bump version to $new_version"
    fi

    # Step 8: Create annotated tag
    log_info "Creating tag v$new_version..."
    git tag -a "v$new_version" -m "Release v$new_version"

    # Step 9: Push commit and tag
    log_info "Pushing to origin..."
    git push origin "$current_branch"
    git push origin "v$new_version"

    log_success "Released v$new_version!"
    echo ""
    echo "The release workflow will now build and publish binaries."
    echo "Monitor progress at: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
}

main "$@"
