# Security Policy

## Reporting a Vulnerability

Please do not open a public issue or pull request for a potential security
vulnerability. Use GitHub's private vulnerability reporting for the public CLI
distribution repository:

https://github.com/boringcache/cli/security/advisories/new

Include the CLI version, platform, relevant release or workflow link, expected
impact, and enough reproduction detail for us to verify the report. Do not
include live credentials, customer data, or secrets.

## Supported Versions

The latest published CLI release is supported. Security fixes are normally
shipped as a new release rather than backported to older binaries.

## Scope

This public repository is the CLI distribution channel. It owns the installer,
release binaries, checksums, signed checksum bundles, release notes, and public
documentation. Product source is maintained separately in the private
BoringCache monorepo.

Reports about the CLI, installer, release pipeline, artifact integrity, or the
authorization boundary between the CLI and BoringCache service are all welcome
through the private reporting link above.
