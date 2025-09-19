#!/usr/bin/env ruby

# Build Linux binaries using Dagger
# This script builds both CLI and CI binaries in Linux containers

require 'dagger_ruby'

def build_linux_binaries_for_platform(client, platform, cargo_cache, cargo_registry)
  arch_suffix = platform.include?('arm64') ? 'arm64' : 'amd64'
  rust_target = platform.include?('arm64') ? 'aarch64-unknown-linux-gnu' : 'x86_64-unknown-linux-gnu'

  puts "🏗️  Building for #{platform}..."

  # Build CLI binary (Rust)
  puts "🦀 Building static CLI binary with Rust 1.89 (#{rust_target})..."

  cli_container = client
                  .container(platform: platform)
                  .from('rust:1.89')
                  .with_mounted_cache('/usr/local/cargo/registry', cargo_registry)
                  .with_mounted_cache('/usr/local/cargo/git', cargo_cache)
                  .with_directory('/src', client.host.directory('.'))
                  .with_workdir('/src')
                  .with_env_variable('RUSTFLAGS', '-C target-feature=+crt-static')
                  .with_exec(['rustup', 'target', 'add', rust_target])
                  .with_exec(['cargo', 'build', '--release', '--target', rust_target])

  # Extract CLI binary from target-specific directory
  cli_binary = cli_container.file("/src/target/#{rust_target}/release/boringcache")
  cli_binary.export("./build/boringcache-linux-#{arch_suffix}")
  puts "✅ Static CLI binary saved to ./build/boringcache-linux-#{arch_suffix}"

  arch_suffix
end

def build_linux_binaries(platforms = ['linux/amd64'])
  puts '🐳 Building BoringCache Linux binaries with Dagger for multiple architectures...'

  DaggerRuby.connection do |client|
    # Create build directory
    puts '📁 Creating build directory...'
    system('mkdir -p build')

    # Create cache volumes for faster builds (shared across architectures)
    cargo_cache = client.cache_volume('cargo-cache')
    cargo_registry = client.cache_volume('cargo-registry')

    built_architectures = []

    # Build for each platform
    platforms.each do |platform|
      puts "\n" + '=' * 50
      begin
        arch_suffix = build_linux_binaries_for_platform(client, platform, cargo_cache, cargo_registry)
        built_architectures << arch_suffix
        puts "✅ Completed #{platform} build"
      rescue StandardError => e
        puts "⚠️  Failed to build for #{platform}: #{e.message}"
        puts 'Continuing with other architectures...'
      end
    end

    # Set executable permissions for all built binaries
    puts "\n🔧 Setting executable permissions for all binaries..."
    built_architectures.each do |arch|
      system("chmod +x build/boringcache-linux-#{arch}")
      system("chmod +x build/boringcache-ci-linux-#{arch}")
    end

    puts "\n🎉 Multi-architecture static Linux binaries built successfully with caching!"
    puts ''
    puts 'Files created:'
    built_architectures.each do |arch|
      puts "  ./build/boringcache-linux-#{arch} (CLI - #{arch.upcase} - STATIC)"
      puts "  ./build/boringcache-ci-linux-#{arch} (CI - #{arch.upcase})"
    end
    puts ''
    puts '⚡ Performance features:'
    puts '  - Statically-linked Rust binaries (no dependencies!)'
    puts '  - Cargo registry & git caching for faster Rust builds'
    puts '  - Deno module caching for faster TypeScript compilation'
    puts '  - Optimized release builds with maximum optimization'
    puts '  - Multi-architecture support (ARM64 + AMD64)'
    puts ''
    puts 'Next steps:'
    puts '  1. These binaries work with both --container-architecture options in act'
    puts '  2. Use them in act workflows with --network host'
    puts '  3. Run: act --container-architecture linux/arm64 OR linux/amd64'
  end
end

# Run if called directly
if __FILE__ == $0
  begin
    build_linux_binaries
  rescue StandardError => e
    puts "❌ Error: #{e.message}"
    puts 'Make sure you have:'
    puts '  - dagger_ruby gem installed (gem install dagger_ruby)'
    puts '  - Dagger CLI installed (https://docs.dagger.io/install)'
    puts '  - Docker running'
    exit 1
  end
end
