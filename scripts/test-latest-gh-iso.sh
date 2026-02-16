#!/usr/bin/env bash
set -euo pipefail

WORKFLOW="build-images.yml"
RUN_ID=""
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo mvpv2)"
DOWNLOAD_DIR=""
KEEP_DOWNLOADS=0
REPO_OVERRIDE=""
DOWNLOAD_TIMEOUT_SECONDS=360

usage() {
    cat <<'EOF'
Usage:
  ./scripts/test-latest-gh-iso.sh [options] [-- test-iso-options]

Options:
  --branch NAME         Branch to select latest successful run from (default: current git branch)
  --run-id ID           Use a specific run ID instead of auto-selecting latest success
  --workflow FILE       Workflow file/name (default: build-images.yml)
  --repo OWNER/REPO     Override GitHub repo (default: inferred from current git remote)
  --download-dir DIR    Directory to download artifact into (default: temp dir)
  --keep-downloads      Keep downloaded artifacts
  -h, --help            Show help

Examples:
  ./scripts/test-latest-gh-iso.sh
  ./scripts/test-latest-gh-iso.sh --branch mvpv2 -- --timeout 420 --verbose
  ./scripts/test-latest-gh-iso.sh --run-id 22074155056 -- --interactive
EOF
}

log() {
    printf '[test-latest-gh-iso] %s\n' "$*"
}

fail() {
    printf '[test-latest-gh-iso] ERROR: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

TEST_ISO_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch)
            BRANCH="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            shift 2
            ;;
        --workflow)
            WORKFLOW="${2:-}"
            shift 2
            ;;
        --repo)
            REPO_OVERRIDE="${2:-}"
            shift 2
            ;;
        --download-dir)
            DOWNLOAD_DIR="${2:-}"
            shift 2
            ;;
        --keep-downloads)
            KEEP_DOWNLOADS=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            TEST_ISO_ARGS=("$@")
            break
            ;;
        *)
            fail "Unknown option: $1"
            ;;
    esac
done

need_cmd gh
need_cmd find
need_cmd sha256sum
need_cmd timeout

if [[ -n "${REPO_OVERRIDE}" ]]; then
    GH_REPO_ARGS=(-R "${REPO_OVERRIDE}")
else
    GH_REPO_ARGS=()
fi

if [[ -z "${RUN_ID}" ]]; then
    log "Resolving latest successful workflow run"
    RUN_ID="$(gh run list "${GH_REPO_ARGS[@]}" \
        --workflow "${WORKFLOW}" \
        --limit 30 \
        --json databaseId,headBranch,conclusion,event \
        --jq "map(select(.headBranch==\"${BRANCH}\" and .conclusion==\"success\" and .event==\"workflow_dispatch\")) | .[0].databaseId")"
fi

if [[ -z "${RUN_ID}" || "${RUN_ID}" == "null" ]]; then
    fail "No successful ${WORKFLOW} workflow_dispatch run found for branch '${BRANCH}'"
fi

if [[ -z "${DOWNLOAD_DIR}" ]]; then
    DOWNLOAD_DIR="$(mktemp -d /tmp/clawgress-gh-artifact.XXXXXX)"
else
    mkdir -p "${DOWNLOAD_DIR}"
fi

cleanup() {
    if [[ ${KEEP_DOWNLOADS} -eq 1 ]]; then
        log "Keeping downloaded artifacts in ${DOWNLOAD_DIR}"
    else
        rm -rf "${DOWNLOAD_DIR}"
    fi
}
trap cleanup EXIT

log "Downloading artifacts for run ${RUN_ID} to ${DOWNLOAD_DIR}"
timeout "${DOWNLOAD_TIMEOUT_SECONDS}" gh run download "${GH_REPO_ARGS[@]}" "${RUN_ID}" -D "${DOWNLOAD_DIR}" >/dev/null

ISO_PATH="$(find "${DOWNLOAD_DIR}" -type f -name "*.iso" | head -1)"
[[ -n "${ISO_PATH}" ]] || fail "No ISO found in downloaded artifacts for run ${RUN_ID}"

SHA_PATH="$(find "${DOWNLOAD_DIR}" -type f -name "SHA256SUMS" | head -1 || true)"
if [[ -n "${SHA_PATH}" ]]; then
    log "Verifying checksum using ${SHA_PATH}"
    (
        cd "$(dirname "${SHA_PATH}")"
        sha256sum -c "$(basename "${SHA_PATH}")" >/dev/null
    )
    log "Checksum verification passed"
else
    log "SHA256SUMS not found; skipping checksum verification"
fi

log "Launching local QEMU test with ISO: ${ISO_PATH}"
"$(dirname "$0")/test-iso.sh" --iso "${ISO_PATH}" "${TEST_ISO_ARGS[@]}"
