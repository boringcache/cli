#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLI_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
TEST_ROOT=$(mktemp -d)
ORIGINAL_PATH=${PATH}
EXPECTED_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKaCEtUJN1OYbcoBzD9k8nma39YQG
RXyLl5H1XoimZCWB+7Su1mFFFMPWS7nWPGcbxeB8F7nN5I3GUgRPWQ1FAw==
-----END PUBLIC KEY-----'
EXPECTED_MINIMUM_COSIGN_VERSION='3.1.3'
EXPECTED_KEYED_RELEASE_MINIMUM_VERSION='v1.31.0'
EXPECTED_CERTIFICATE_IDENTITY_REGEXP='^https://github\.com/boringcache/monorepo/\.github/workflows/(cli-release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+|cli-release-checksums\.yml@refs/heads/main)$'
EXPECTED_CERTIFICATE_OIDC_ISSUER='https://token.actions.githubusercontent.com'

cleanup() {
    rm -rf "${TEST_ROOT}"
}

fail() {
    printf 'installer trust test failed: %s\n' "$1" >&2
    exit 1
}

write_checksum() {
    directory="$1"
    binary_name="$2"

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "${directory}" && sha256sum "${binary_name}" > SHA256SUMS)
    else
        checksum=$(shasum -a 256 "${directory}/${binary_name}" | awk '{print $1}')
        printf '%s  %s\n' "${checksum}" "${binary_name}" > "${directory}/SHA256SUMS"
    fi
}

test_installer() {
    installer="$1"
    fixture_name="$2"
    fixture_dir="${TEST_ROOT}/${fixture_name}"
    fake_bin="${fixture_dir}/bin"
    cosign_args="${fixture_dir}/cosign-args"
    binary_name="boringcache-linux-amd64"

    mkdir -p "${fake_bin}"
    BORINGCACHE_INSTALLER_SOURCE_ONLY=1
    export BORINGCACHE_INSTALLER_SOURCE_ONLY
    # shellcheck source=/dev/null
    . "${installer}"

    download_log="${fixture_dir}/release-downloads"
    downloaded_release="${fixture_dir}/downloaded-release"
    download_file() {
        printf '%s\n' "$1" >> "${download_log}"
        case "$1" in
            "${ARTIFACT_ORIGIN}"/*)
                printf 'partial canonical download\n' > "$2"
                return 22
                ;;
            *)
                printf 'GitHub mirror bytes\n' > "$2"
                ;;
        esac
    }
    download_release_file v1.20.0 boringcache-linux-amd64 "${downloaded_release}" 2>/dev/null ||
        fail "${fixture_name} did not use the historical GitHub release origin"
    sed -n '1p' "${download_log}" | grep -Fx \
        "https://github.com/boringcache/cli/releases/download/v1.20.0/boringcache-linux-amd64" >/dev/null ||
        fail "${fixture_name} did not use the exact historical GitHub release"
    [ "$(wc -l < "${download_log}" | tr -d ' ')" = "1" ] ||
        fail "${fixture_name} tried the canonical origin for a historical release"
    [ "$(cat "${downloaded_release}")" = "GitHub mirror bytes" ] ||
        fail "${fixture_name} did not publish the completed historical download atomically"

    : > "${download_log}"
    download_release_file v1.31.0 boringcache-linux-amd64 "${downloaded_release}" 2>/dev/null ||
        fail "${fixture_name} did not use the same-version GitHub mirror"
    sed -n '1p' "${download_log}" | grep -Fx \
        "${ARTIFACT_ORIGIN}/releases/cli/v1.31.0/boringcache-linux-amd64" >/dev/null ||
        fail "${fixture_name} did not try the canonical release origin first"
    sed -n '2p' "${download_log}" | grep -Fx \
        "https://github.com/boringcache/cli/releases/download/v1.31.0/boringcache-linux-amd64" >/dev/null ||
        fail "${fixture_name} did not use the exact-version GitHub mirror"
    [ "$(cat "${downloaded_release}")" = "GitHub mirror bytes" ] ||
        fail "${fixture_name} retained partial canonical bytes after mirror recovery"
    [ ! -e "${downloaded_release}.part" ] ||
        fail "${fixture_name} retained a partial download after success"
    if download_release_file latest boringcache-linux-amd64 "${downloaded_release}" >/dev/null 2>&1; then
        fail "${fixture_name} accepted a release version without an exact trust policy"
    fi

    [ "${CHECKSUM_PUBLIC_KEY}" = "${EXPECTED_PUBLIC_KEY}" ] ||
        fail "${fixture_name} trusts an unexpected release key"
    [ "${COSIGN_MINIMUM_VERSION}" = "${EXPECTED_MINIMUM_COSIGN_VERSION}" ] ||
        fail "${fixture_name} declares an unexpected minimum cosign version"
    [ "${KEYED_RELEASE_MINIMUM_VERSION}" = "${EXPECTED_KEYED_RELEASE_MINIMUM_VERSION}" ] ||
        fail "${fixture_name} declares an unexpected keyed-release boundary"
    [ "${CHECKSUM_CERTIFICATE_IDENTITY_REGEXP}" = "${EXPECTED_CERTIFICATE_IDENTITY_REGEXP}" ] ||
        fail "${fixture_name} trusts an unexpected historical signing identity"
    [ "${CHECKSUM_CERTIFICATE_OIDC_ISSUER}" = "${EXPECTED_CERTIFICATE_OIDC_ISSUER}" ] ||
        fail "${fixture_name} trusts an unexpected historical OIDC issuer"
    [ "$(release_signature_policy v1.30.9)" = "keyless" ] ||
        fail "${fixture_name} does not preserve the historical keyless policy"
    [ "$(release_signature_policy v1.31.0)" = "keyed" ] ||
        fail "${fixture_name} does not activate the keyed policy at v1.31.0"
    [ "$(release_signature_policy v2.0.0)" = "keyed" ] ||
        fail "${fixture_name} allows a later release to downgrade to keyless verification"
    cosign_version_is_supported "${EXPECTED_MINIMUM_COSIGN_VERSION}" ||
        fail "${fixture_name} rejects its minimum cosign version"
    cosign_version_is_supported "4.0.0" ||
        fail "${fixture_name} rejects a newer cosign major version"
    cosign_version_is_supported "3.10.0" ||
        fail "${fixture_name} compares cosign versions lexically"
    if cosign_version_is_supported "3.1.2"; then
        fail "${fixture_name} accepts a cosign version below its security floor"
    fi

    printf 'release binary\n' > "${fixture_dir}/${binary_name}"
    write_checksum "${fixture_dir}" "${binary_name}"
    verify_checksum "${fixture_dir}" "${binary_name}" ||
        fail "${fixture_name} rejected a matching checksum"

    printf 'tampered release binary\n' > "${fixture_dir}/${binary_name}"
    if verify_checksum "${fixture_dir}" "${binary_name}" >/dev/null 2>&1; then
        fail "${fixture_name} accepted a checksum mismatch"
    fi

    printf '404: Not Found\n' > "${fixture_dir}/${binary_name}"
    if verify_checksum "${fixture_dir}" "${binary_name}" >/dev/null 2>&1; then
        fail "${fixture_name} accepted an HTTP error body as a release binary"
    fi

    VERIFY_CHECKSUM_SIGNATURE=1
    rm -f "${fixture_dir}/SHA256SUMS.bundle"
    if verify_checksum_signature "${fixture_dir}" v1.31.0 >/dev/null 2>&1; then
        fail "${fixture_name} accepted a missing signature bundle"
    fi

    if (
        PATH=/usr/bin:/bin
        BORINGCACHE_VERIFY_SIGNATURE=1
        VERIFY_CHECKSUM_SIGNATURE=0
        prepare_checksum_signature_verification >/dev/null 2>&1
    ); then
        fail "${fixture_name} allowed strict verification without cosign"
    fi

    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' 'if [ "${1:-}" = "version" ]; then'
        printf '%s\n' '    printf "GitVersion:    %s\n" "${COSIGN_FAKE_VERSION}"'
        printf '%s\n' '    exit 0'
        printf '%s\n' 'fi'
        printf '%s\n' 'printf "%s\n" "$@" > "${COSIGN_ARGS_FILE}"'
    } > "${fake_bin}/cosign"
    chmod +x "${fake_bin}/cosign"
    PATH="${fake_bin}:${ORIGINAL_PATH}"
    COSIGN_ARGS_FILE="${cosign_args}"
    COSIGN_FAKE_VERSION=v2.4.1
    VERIFY_CHECKSUM_SIGNATURE=0
    export PATH COSIGN_ARGS_FILE COSIGN_FAKE_VERSION VERIFY_CHECKSUM_SIGNATURE

    if incompatible_output=$(
        BORINGCACHE_VERIFY_SIGNATURE=auto
        export BORINGCACHE_VERIFY_SIGNATURE
        prepare_checksum_signature_verification 2>&1
    ); then
        fail "${fixture_name} allowed auto verification with an incompatible cosign"
    fi
    printf '%s\n' "${incompatible_output}" | grep -F \
        "cosign 2.4.1 is unsupported for BoringCache release signatures; cosign ${EXPECTED_MINIMUM_COSIGN_VERSION} or newer is required." >/dev/null ||
        fail "${fixture_name} did not explain the incompatible cosign version"
    printf '%s\n' "${incompatible_output}" | grep -F \
        'set BORINGCACHE_VERIFY_SIGNATURE=0 to explicitly use SHA-256 checksum verification only.' >/dev/null ||
        fail "${fixture_name} did not make the auto-mode checksum opt-out explicit"

    if (
        BORINGCACHE_VERIFY_SIGNATURE=1
        export BORINGCACHE_VERIFY_SIGNATURE
        prepare_checksum_signature_verification >/dev/null 2>&1
    ); then
        fail "${fixture_name} allowed strict verification with an incompatible cosign"
    fi

    BORINGCACHE_VERIFY_SIGNATURE=0
    VERIFY_CHECKSUM_SIGNATURE=1
    export BORINGCACHE_VERIFY_SIGNATURE VERIFY_CHECKSUM_SIGNATURE
    prepare_checksum_signature_verification ||
        fail "${fixture_name} rejected an explicit checksum-only request"
    [ "${VERIFY_CHECKSUM_SIGNATURE}" = "0" ] ||
        fail "${fixture_name} enabled signatures for an explicit checksum-only request"

    COSIGN_FAKE_VERSION="v${EXPECTED_MINIMUM_COSIGN_VERSION}"
    BORINGCACHE_VERIFY_SIGNATURE=1
    VERIFY_CHECKSUM_SIGNATURE=0
    export COSIGN_FAKE_VERSION BORINGCACHE_VERIFY_SIGNATURE VERIFY_CHECKSUM_SIGNATURE

    prepare_checksum_signature_verification ||
        fail "${fixture_name} did not enable strict verification with supported cosign present"
    [ "${VERIFY_CHECKSUM_SIGNATURE}" = "1" ] ||
        fail "${fixture_name} did not record strict verification state"

    printf 'signed bundle fixture\n' > "${fixture_dir}/SHA256SUMS.bundle"
    verify_checksum_signature "${fixture_dir}" v1.31.0 ||
        fail "${fixture_name} rejected the strict signature fixture"
    grep -Fx -- "--key" "${cosign_args}" >/dev/null ||
        fail "${fixture_name} did not select the checked release key"
    grep -Fx -- "${fixture_dir}/release-cosign-v1.pub" "${cosign_args}" >/dev/null ||
        fail "${fixture_name} did not pass the checked release key to cosign"
    [ "$(cat "${fixture_dir}/release-cosign-v1.pub")" = "${EXPECTED_PUBLIC_KEY}" ] ||
        fail "${fixture_name} wrote an unexpected release key"
    if grep -Fx -- "--certificate-identity-regexp" "${cosign_args}" >/dev/null; then
        fail "${fixture_name} allowed keyed verification to fall back to a certificate identity"
    fi

    : > "${cosign_args}"
    verify_checksum_signature "${fixture_dir}" v1.20.0 ||
        fail "${fixture_name} rejected the historical keyless signature fixture"
    grep -Fx -- "--certificate-identity-regexp" "${cosign_args}" >/dev/null ||
        fail "${fixture_name} did not select the historical signing identity"
    grep -Fx -- "${EXPECTED_CERTIFICATE_IDENTITY_REGEXP}" "${cosign_args}" >/dev/null ||
        fail "${fixture_name} passed an unexpected historical signing identity"
    grep -Fx -- "--certificate-oidc-issuer" "${cosign_args}" >/dev/null ||
        fail "${fixture_name} did not select the historical OIDC issuer"
    grep -Fx -- "${EXPECTED_CERTIFICATE_OIDC_ISSUER}" "${cosign_args}" >/dev/null ||
        fail "${fixture_name} passed an unexpected historical OIDC issuer"
    if grep -Fx -- "--key" "${cosign_args}" >/dev/null; then
        fail "${fixture_name} applied the new release key to a historical release"
    fi
    if verify_checksum_signature "${fixture_dir}" latest >/dev/null 2>&1; then
        fail "${fixture_name} verified a release version without an exact trust policy"
    fi

    PATH=${ORIGINAL_PATH}
    unset COSIGN_ARGS_FILE COSIGN_FAKE_VERSION BORINGCACHE_VERIFY_SIGNATURE
    export PATH
}

trap cleanup EXIT HUP INT TERM

test_installer "${CLI_ROOT}/install.sh" "root-installer"
test_installer "${CLI_ROOT}/install-web/install.sh" "web-installer"

for installer in "${CLI_ROOT}/install.sh" "${CLI_ROOT}/install-web/install.sh"; do
    grep -F 'libboringcache_xcode_cas-macos-universal.dylib' "${installer}" >/dev/null ||
        fail "$(basename "${installer}") does not download the universal Xcode adapter"
    grep -F 'libboringcache_xcode_cas.dylib' "${installer}" >/dev/null ||
        fail "$(basename "${installer}") does not install the Xcode adapter beside the CLI"
done

printf 'installer trust tests passed\n'
