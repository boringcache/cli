#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLI_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
TEST_ROOT=$(mktemp -d)
ORIGINAL_PATH=${PATH}
EXPECTED_IDENTITY_REGEXP='^https://github\.com/boringcache/monorepo/\.github/workflows/(cli-release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+|cli-release-checksums\.yml@refs/heads/main)$'

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

    [ "${CHECKSUM_CERTIFICATE_IDENTITY_REGEXP}" = "${EXPECTED_IDENTITY_REGEXP}" ] ||
        fail "${fixture_name} trusts an unexpected workflow identity"

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
    if verify_checksum_signature "${fixture_dir}" >/dev/null 2>&1; then
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

    printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$@" > "${COSIGN_ARGS_FILE}"' > "${fake_bin}/cosign"
    chmod +x "${fake_bin}/cosign"
    PATH="${fake_bin}:${ORIGINAL_PATH}"
    COSIGN_ARGS_FILE="${cosign_args}"
    BORINGCACHE_VERIFY_SIGNATURE=1
    VERIFY_CHECKSUM_SIGNATURE=0
    export PATH COSIGN_ARGS_FILE BORINGCACHE_VERIFY_SIGNATURE VERIFY_CHECKSUM_SIGNATURE

    prepare_checksum_signature_verification ||
        fail "${fixture_name} did not enable strict verification with cosign present"
    [ "${VERIFY_CHECKSUM_SIGNATURE}" = "1" ] ||
        fail "${fixture_name} did not record strict verification state"

    printf 'signed bundle fixture\n' > "${fixture_dir}/SHA256SUMS.bundle"
    verify_checksum_signature "${fixture_dir}" ||
        fail "${fixture_name} rejected the strict signature fixture"
    grep -Fx -- "${EXPECTED_IDENTITY_REGEXP}" "${cosign_args}" >/dev/null ||
        fail "${fixture_name} did not pass the exact signer allowlist to cosign"
    grep -Fx -- "${CHECKSUM_CERTIFICATE_OIDC_ISSUER}" "${cosign_args}" >/dev/null ||
        fail "${fixture_name} did not pin the GitHub Actions OIDC issuer"

    PATH=${ORIGINAL_PATH}
    unset COSIGN_ARGS_FILE BORINGCACHE_VERIFY_SIGNATURE
    export PATH
}

trap cleanup EXIT HUP INT TERM

test_installer "${CLI_ROOT}/install.sh" "root-installer"
test_installer "${CLI_ROOT}/install-web/install.sh" "web-installer"

printf 'installer trust tests passed\n'
