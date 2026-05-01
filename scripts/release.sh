#!/usr/bin/env bash
#
# Release script for BoringCache CLI
#
# Preferred usage:
#   ./scripts/release.sh prepare patch    # create and push the signed version commit
#   ./scripts/release.sh tag 0.1.3        # tag the already-green HEAD commit
#   ./scripts/release.sh tag 0.1.3 SHA    # tag an explicit already-green commit
#
# Legacy one-shot usage:
#   ./scripts/release.sh patch            # bump, commit, tag, and push in one run
#   ./scripts/release.sh minor            # 0.1.2 -> 0.2.0
#   ./scripts/release.sh major            # 0.1.2 -> 1.0.0
#   ./scripts/release.sh 0.2.0            # explicit version
#
# This script:
#   1. Validates the working directory is clean
#   2. Runs cargo fmt --check
#   3. Runs cargo clippy
#   4. Runs the Rust 2024 compatibility check
#   5. Runs cargo test
#   6. Bumps version in Cargo.toml
#   7. Updates install fallback versions
#   8. Updates Cargo.lock
#   9. Commits the version bump (signed)
#   10. Creates a signed annotated git tag on the already-green commit
#   11. Pushes the commit and/or tag

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

usage() {
    cat <<'USAGE'
Usage:
  ./scripts/release.sh prepare <patch|minor|major|VERSION>
      Create and push the signed version commit. Wait for CLI CI/E2E on
      that commit, then run the tag command.

  ./scripts/release.sh tag <VERSION> [COMMIT]
      Create and push a signed tag for an already-green release commit.
      When COMMIT is omitted, HEAD is used. This does not create a new
      commit, run local tests, or dispatch CI.

  ./scripts/release.sh <patch|minor|major|VERSION>
      Legacy one-shot release. This bumps, commits, tags, and pushes in
      one run, so the pushed release commit will run branch CI before the
      tag release workflow publishes assets.

Examples:
  ./scripts/release.sh prepare patch
  ./scripts/release.sh tag 1.2.3
  ./scripts/release.sh tag 1.2.3 0123abcd
  ./scripts/release.sh 1.2.3
USAGE
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

update_install_fallback_version() {
    local file="$1"
    local new_version="$2"
    local release_tag="v${new_version}"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/local fallback_version=\"v[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\"/local fallback_version=\"${release_tag}\"/" "$file"
    else
        sed -i "s/local fallback_version=\"v[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\"/local fallback_version=\"${release_tag}\"/" "$file"
    fi
}

verify_install_fallback_version() {
    local file="$1"
    local expected="$2"
    local actual
    actual="$(sed -n -E 's/^[[:space:]]*local fallback_version=\"(v[0-9]+\.[0-9]+\.[0-9]+)\"/\1/p' "$file" | head -1)"
    if [[ "$actual" != "$expected" ]]; then
        log_error "Fallback version update failed for ${file}. Expected ${expected}, got ${actual:-<missing>}"
        exit 1
    fi
}

ensure_tag_absent() {
    local version="$1"
    local tag="v${version}"
    local remote_status=0

    if git rev-parse "${tag}" >/dev/null 2>&1; then
        log_error "Tag ${tag} already exists locally!"
        exit 1
    fi

    git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1 || remote_status=$?
    if [[ "${remote_status}" -eq 0 ]]; then
        log_error "Tag ${tag} already exists on origin!"
        exit 1
    fi
    if [[ "${remote_status}" -ne 2 ]]; then
        log_warn "Could not confirm whether ${tag} exists on origin; continuing with local check only."
    fi
}

run_local_gates() {
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

    # Step 4: Run Rust 2024 compatibility check
    log_info "Running Rust 2024 compatibility check..."
    if ! RUSTFLAGS='-Wrust-2024-compatibility' cargo check --all-targets; then
        log_error "Rust 2024 compatibility check found issues. Please fix them first."
        exit 1
    fi
    log_success "Rust 2024 compatibility check passed"

    # Step 5: Run cargo test
    log_info "Running cargo test..."
    if ! cargo test; then
        log_error "Tests failed. Please fix them first."
        exit 1
    fi
    log_success "All tests passed"
}

create_signed_tag() {
    local version="$1"
    local target_ref="${2:-HEAD}"

    log_info "Creating tag v${version} at ${target_ref}..."
    git tag -s -m "Release v${version}" "v${version}" "${target_ref}"
}

assert_head_matches_origin() {
    local branch="$1"
    local local_sha
    local remote_sha

    log_info "Verifying HEAD matches origin/${branch}..."
    git fetch origin "$branch"
    local_sha="$(git rev-parse HEAD)"
    remote_sha="$(git rev-parse "origin/${branch}")"
    if [[ "$local_sha" != "$remote_sha" ]]; then
        log_error "HEAD ${local_sha} does not match origin/${branch} ${remote_sha}."
        log_error "Tag mode must run on the pushed, already-green release commit."
        exit 1
    fi
}

assert_ref_is_on_origin_branch() {
    local branch="$1"
    local target_sha="$2"

    log_info "Verifying ${target_sha} is present on origin/${branch}..."
    git fetch origin "$branch"
    if ! git merge-base --is-ancestor "${target_sha}" "origin/${branch}"; then
        log_error "Commit ${target_sha} is not reachable from origin/${branch}."
        log_error "Release tags must point at a pushed, already-green mainline commit."
        exit 1
    fi
}

verify_release_version_at_ref() {
    local target_ref="$1"
    local expected_version="$2"
    local version_line
    local actual_version

    version_line="$(git show "${target_ref}:Cargo.toml" | grep '^version = ' | head -1 || true)"
    actual_version="$(printf '%s\n' "${version_line}" | sed 's/version = "\(.*\)"/\1/')"
    if [[ "${actual_version}" != "${expected_version}" ]]; then
        log_error "Cargo.toml at ${target_ref} is version ${actual_version:-<missing>}, expected ${expected_version}."
        log_error "Tag the release commit that already contains the version bump."
        exit 1
    fi
}

# Main release function
main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi

    local mode="one-shot"
    local bump_type="$1"

    case "$1" in
        prepare)
            if [[ $# -ne 2 ]]; then
                usage
                exit 1
            fi
            mode="prepare"
            bump_type="$2"
            ;;
        tag)
            if [[ $# -lt 2 || $# -gt 3 ]]; then
                usage
                exit 1
            fi
            mode="tag"
            bump_type="$2"
            if [[ ! "$bump_type" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                log_error "Tag mode requires an explicit version, for example: ./scripts/release.sh tag 1.2.3"
                exit 1
            fi
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ $# -ne 1 ]]; then
                usage
                exit 1
            fi
            ;;
    esac

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
    local tag_target_ref="HEAD"
    local tag_target_sha=""
    if [[ "$mode" == "tag" ]]; then
        new_version="$bump_type"
        if [[ $# -eq 3 ]]; then
            tag_target_ref="$3"
        fi
        tag_target_sha="$(git rev-parse "${tag_target_ref}^{commit}")"
    else
        new_version=$(bump_version "$current_version" "$bump_type")
    fi

    log_info "Current version: $current_version"
    log_info "New version: $new_version"
    if [[ "$mode" == "one-shot" ]]; then
        log_warn "One-shot release creates a release commit and branch CI will run on it. Prefer: prepare, wait for green CI, then tag."
    fi

    # Check if tag already exists
    ensure_tag_absent "$new_version"

    if [[ "$mode" == "tag" ]]; then
        if [[ "${tag_target_ref}" == "HEAD" && "$current_version" != "$new_version" ]]; then
            log_error "Cargo.toml version is ${current_version}, but tag mode requested ${new_version}."
            log_error "Run './scripts/release.sh prepare ${new_version}' first, wait for CI, then tag."
            exit 1
        fi
        if [[ "${tag_target_ref}" == "HEAD" ]]; then
            assert_head_matches_origin "$current_branch"
        else
            assert_ref_is_on_origin_branch "$current_branch" "$tag_target_sha"
        fi
        verify_release_version_at_ref "$tag_target_sha" "$new_version"

        log_info "Tagging already-prepared release commit $(git rev-parse --short "$tag_target_sha")."
        create_signed_tag "$new_version" "$tag_target_sha"
        log_info "Pushing tag v${new_version} to origin..."
        git push origin "v$new_version"

        log_success "Tagged v$new_version!"
        echo ""
        echo "The release workflow will verify existing CLI CI/E2E for this commit, then build and publish binaries."
        echo "Monitor progress at: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
        exit 0
    fi

    if [[ "$mode" == "prepare" && "$current_version" == "$new_version" ]]; then
        log_error "Version is already set to $new_version. Run './scripts/release.sh tag $new_version' after CI is green."
        exit 1
    fi

    run_local_gates

    # Step 6-9: Update version and commit (skip if version unchanged)
    if [[ "$current_version" == "$new_version" ]]; then
        log_info "Version already set to $new_version, skipping version bump..."
    else
        log_info "Updating Cargo.toml version to $new_version..."
        update_cargo_version "$new_version"

        # Update install script fallback versions
        log_info "Updating install fallback version to v${new_version}..."
        update_install_fallback_version "$PROJECT_ROOT/install.sh" "$new_version"
        update_install_fallback_version "$PROJECT_ROOT/install-web/install.sh" "$new_version"
        verify_install_fallback_version "$PROJECT_ROOT/install.sh" "v${new_version}"
        verify_install_fallback_version "$PROJECT_ROOT/install-web/install.sh" "v${new_version}"

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
        git add Cargo.toml Cargo.lock install.sh install-web/install.sh
        git commit -S -m "chore: bump version to $new_version"
    fi

    if [[ "$mode" == "prepare" ]]; then
        log_info "Pushing release commit to origin..."
        git push origin "$current_branch"

        log_success "Prepared v$new_version release commit!"
        echo ""
        echo "Wait for CLI CI and E2E Tests to pass on $(git rev-parse --short HEAD), then run:"
        echo "  ./scripts/release.sh tag $new_version"
        exit 0
    fi

    # Step 8: Create signed annotated tag
    create_signed_tag "$new_version"

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
