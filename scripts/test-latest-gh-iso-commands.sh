#!/usr/bin/env bash
set -euo pipefail

WORKFLOW="build-images.yml"
RUN_ID=""
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo mvpv2)"
DOWNLOAD_DIR=""
KEEP_DOWNLOADS=0
REPO_OVERRIDE=""
RUNNER_ARGS=()
DOWNLOAD_TIMEOUT_SECONDS=360

usage() {
    cat <<'EOF'
Usage:
  ./scripts/test-latest-gh-iso-commands.sh [options] [-- runner-options]

Options:
  --branch NAME         Branch to select latest successful run from (default: current git branch)
  --run-id ID           Use a specific run ID instead of auto-selecting latest success
  --workflow FILE       Workflow file/name (default: build-images.yml)
  --repo OWNER/REPO     Override GitHub repo
  --download-dir DIR    Directory to download artifact into (default: temp dir)
  --keep-downloads      Keep downloaded artifacts
  -h, --help            Show help

Runner options (after --) are passed to:
  ./scripts/test-iso-commands.py

Examples:
  ./scripts/test-latest-gh-iso-commands.sh
  ./scripts/test-latest-gh-iso-commands.sh -- --commands-file ./scripts/cmd-suite.txt --log-dir /tmp/clawgress-cmdsuite
  ./scripts/test-latest-gh-iso-commands.sh --run-id 22074155056 -- --no-kvm --boot-timeout 420
EOF
}

log() {
    printf '[test-latest-gh-iso-commands] %s\n' "$*"
}

fail() {
    printf '[test-latest-gh-iso-commands] ERROR: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

resolve_repo() {
    if [[ -n "${REPO_OVERRIDE}" ]]; then
        echo "${REPO_OVERRIDE}"
        return 0
    fi

    local remote
    remote="$(git config --get remote.origin.url || true)"
    if [[ -z "${remote}" ]]; then
        fail "Unable to determine repository (set --repo OWNER/REPO)"
    fi

    remote="${remote%.git}"
    if [[ "${remote}" =~ ^git@github\.com:([^/]+/[^/]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi
    if [[ "${remote}" =~ ^https://github\.com/([^/]+/[^/]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    fail "Unsupported remote URL format: ${remote}"
}

download_artifacts() {
    local repo="$1"
    local run_id="$2"
    local outdir="$3"

    # Try normal gh download first; fallback to raw API zip if it hangs/fails.
    if timeout "${DOWNLOAD_TIMEOUT_SECONDS}" gh run download "${GH_REPO_ARGS[@]}" "${run_id}" -D "${outdir}" >/dev/null 2>&1; then
        return 0
    fi

    log "gh run download failed or timed out after ${DOWNLOAD_TIMEOUT_SECONDS}s; falling back to artifact API download"
    local artifact_id artifact_name zip_path target_dir
    artifact_id="$(gh api "repos/${repo}/actions/runs/${run_id}/artifacts" --jq '.artifacts[] | select(.expired==false) | .id' | head -n 1)"
    artifact_name="$(gh api "repos/${repo}/actions/runs/${run_id}/artifacts" --jq '.artifacts[] | select(.expired==false) | .name' | head -n 1)"
    [[ -n "${artifact_id}" ]] || fail "No non-expired artifacts found for run ${run_id}"
    [[ -n "${artifact_name}" ]] || fail "Could not resolve artifact name for run ${run_id}"

    zip_path="${outdir}/${artifact_name}.zip"
    target_dir="${outdir}/${artifact_name}"
    mkdir -p "${target_dir}"
    gh api "repos/${repo}/actions/artifacts/${artifact_id}/zip" > "${zip_path}"
    unzip -q "${zip_path}" -d "${target_dir}"
}

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
            RUNNER_ARGS=("$@")
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
need_cmd python3
need_cmd unzip

REPO_NAME="$(resolve_repo)"

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
download_artifacts "${REPO_NAME}" "${RUN_ID}" "${DOWNLOAD_DIR}"

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

log "Running automated login+command suite against ISO: ${ISO_PATH}"
python3 "$(dirname "$0")/test-iso-commands.py" --iso "${ISO_PATH}" "${RUNNER_ARGS[@]}"
