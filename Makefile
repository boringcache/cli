# BoringCache CLI Makefile
#
# Common development tasks

.PHONY: all build check test lint fmt clean release-patch release-minor release-major install

# Default target
all: check

# Build in release mode
build:
	cargo build --release

# Run all checks (fmt, clippy, test)
check: fmt-check lint test

# Run tests
test:
	cargo test

# Run clippy linter
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Check code formatting
fmt-check:
	cargo fmt -- --check

# Format code
fmt:
	cargo fmt

# Clean build artifacts
clean:
	cargo clean

# Install locally
install:
	cargo install --path .

# Release commands - bump version and push tag
# If VERSION is provided (e.g., make release-patch VERSION=1.0.0), use exact version
# Otherwise bump the version as usual
release-patch:
	@if [ -n "$(VERSION)" ]; then \
		./scripts/release.sh $(VERSION); \
	else \
		./scripts/release.sh patch; \
	fi

release-minor:
	@if [ -n "$(VERSION)" ]; then \
		./scripts/release.sh $(VERSION); \
	else \
		./scripts/release.sh minor; \
	fi

release-major:
	@if [ -n "$(VERSION)" ]; then \
		./scripts/release.sh $(VERSION); \
	else \
		./scripts/release.sh major; \
	fi

# Development build (faster compilation)
dev:
	cargo build

# Run with verbose logging
run-verbose:
	RUST_LOG=debug cargo run --

# Show current version
version:
	@grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/'

# Pre-commit hook: run before committing
pre-commit: fmt lint test
	@echo "Pre-commit checks passed!"

# Help
help:
	@echo "BoringCache CLI Development Commands"
	@echo ""
	@echo "Development:"
	@echo "  make dev          - Build debug binary"
	@echo "  make build        - Build release binary"
	@echo "  make check        - Run all checks (fmt, lint, test)"
	@echo "  make test         - Run tests"
	@echo "  make lint         - Run clippy"
	@echo "  make fmt          - Format code"
	@echo "  make fmt-check    - Check formatting"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make install      - Install to ~/.cargo/bin"
	@echo ""
	@echo "Release:"
	@echo "  make release-patch              - Release patch version (0.1.2 -> 0.1.3)"
	@echo "  make release-minor              - Release minor version (0.1.2 -> 0.2.0)"
	@echo "  make release-major              - Release major version (0.1.2 -> 1.0.0)"
	@echo "  make release-patch VERSION=X.Y.Z - Release exact version X.Y.Z"
	@echo "  make version                    - Show current version"
	@echo ""
	@echo "Git Hooks:"
	@echo "  make pre-commit   - Run pre-commit checks"
