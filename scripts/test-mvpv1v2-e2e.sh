#!/usr/bin/env bash
set -euo pipefail

WORKFLOW="build-images.yml"
RUN_ID=""
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo mvpv2)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_OVERRIDE=""
ISO_PATH=""
DOWNLOAD_DIR=""
KEEP_DOWNLOADS=0
FORCE_KVM=1

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/test-mvpv1v2-e2e.sh [options]

Options:
  --iso PATH           Use a local ISO directly
  --run-id ID          Download artifact from specific workflow run ID
  --branch NAME        Pick latest successful workflow_dispatch run for branch (default: current branch)
  --workflow FILE      Workflow to query (default: build-images.yml)
  --repo OWNER/REPO    Override GitHub repo
  --download-dir DIR   Artifact download directory
  --keep-downloads     Keep downloaded artifact directory
  --no-force-kvm       Do not force KVM
  -h, --help           Show this help
USAGE
}

log() {
  printf '[test-mvpv1v2-e2e] %s\n' "$*"
}

fail() {
  printf '[test-mvpv1v2-e2e] ERROR: %s\n' "$*" >&2
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
  [[ -n "${remote}" ]] || fail "Unable to determine repository (set --repo OWNER/REPO)"

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iso)
      ISO_PATH="${2:-}"
      shift 2
      ;;
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:-}"
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
    --no-force-kvm)
      FORCE_KVM=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

need_cmd gh
need_cmd sha256sum
need_cmd python3

REPO_NAME="$(resolve_repo)"
if [[ -n "${REPO_OVERRIDE}" ]]; then
  GH_REPO_ARGS=(-R "${REPO_OVERRIDE}")
else
  GH_REPO_ARGS=()
fi

if [[ -z "${ISO_PATH}" ]]; then
  if [[ -z "${RUN_ID}" ]]; then
    log "Resolving latest successful workflow run"
    RUN_ID="$(gh run list "${GH_REPO_ARGS[@]}" \
      --workflow "${WORKFLOW}" \
      --limit 30 \
      --json databaseId,headBranch,conclusion,event \
      --jq "map(select(.headBranch==\"${BRANCH}\" and .conclusion==\"success\" and .event==\"workflow_dispatch\")) | .[0].databaseId")"
  fi

  [[ -n "${RUN_ID}" && "${RUN_ID}" != "null" ]] || fail "No successful run found"

  if [[ -z "${DOWNLOAD_DIR}" ]]; then
    DOWNLOAD_DIR="$(mktemp -d /tmp/clawgress-mvpv1v2-artifact.XXXXXX)"
  else
    mkdir -p "${DOWNLOAD_DIR}"
  fi

  ART_NAME="$(gh api "repos/${REPO_NAME}/actions/runs/${RUN_ID}/artifacts" --jq '.artifacts[] | select(.expired==false) | .name' | head -n1)"
  [[ -n "${ART_NAME}" ]] || fail "No non-expired artifacts for run ${RUN_ID}"

  log "Downloading artifact ${ART_NAME} from run ${RUN_ID}"
  timeout 2400 gh run download "${RUN_ID}" "${GH_REPO_ARGS[@]}" --name "${ART_NAME}" -D "${DOWNLOAD_DIR}"

  ISO_PATH="$(find "${DOWNLOAD_DIR}" -type f -name '*.iso' | head -1)"
  [[ -n "${ISO_PATH}" ]] || fail "No ISO found in downloaded artifact"

  SHA_PATH="$(find "${DOWNLOAD_DIR}" -type f -name 'SHA256SUMS' | head -1 || true)"
  if [[ -n "${SHA_PATH}" ]]; then
    log "Verifying checksum"
    (
      cd "$(dirname "${SHA_PATH}")"
      sha256sum -c "$(basename "${SHA_PATH}")" >/dev/null
    )
  else
    log "WARN: SHA256SUMS missing; skipping checksum verification"
  fi
else
  [[ -f "${ISO_PATH}" ]] || fail "ISO file not found: ${ISO_PATH}"
fi

RUN_TAG="${RUN_ID:-local}-$(date +%Y%m%d-%H%M%S)"
OUT_DIR="/tmp/clawgress-mvpv1v2-e2e-${RUN_TAG}"
CMD_LOG_DIR="${OUT_DIR}/cmdsuite"
NET_LOG="${OUT_DIR}/netlab.log"
REPORT_JSON="${OUT_DIR}/mvpv1v2-report.json"
REPORT_MD="${OUT_DIR}/mvpv1v2-report.md"
mkdir -p "${CMD_LOG_DIR}"

log "ISO: ${ISO_PATH}"
log "Output dir: ${OUT_DIR}"

CMD_ARGS=(--iso "${ISO_PATH}" --suite mvp-full --log-dir "${CMD_LOG_DIR}" --diag-on-failure --boot-timeout 420)
if [[ ${FORCE_KVM} -eq 1 ]]; then
  CMD_ARGS+=(--force-kvm)
fi

set +e
if [[ ${FORCE_KVM} -eq 1 && -e /dev/kvm && ! -w /dev/kvm && -x "$(command -v sg)" ]]; then
  log "Running command suite via 'sg kvm' for /dev/kvm access"
  CMD_STR="$(printf '%q ' python3 "${SCRIPT_DIR}/test-iso-commands.py" "${CMD_ARGS[@]}")"
  sg kvm -c "cd $(printf '%q' "${REPO_ROOT}") && ${CMD_STR}" | tee "${OUT_DIR}/cmdsuite.stdout.log"
  CMD_RC=$?
else
  python3 "${SCRIPT_DIR}/test-iso-commands.py" "${CMD_ARGS[@]}" | tee "${OUT_DIR}/cmdsuite.stdout.log"
  CMD_RC=$?
fi
set -e

NET_ARGS=(--iso "${ISO_PATH}" --clawgress-e2e --keep-artifacts)
if [[ ${FORCE_KVM} -eq 1 ]]; then
  NET_ARGS+=(--force-kvm)
fi

set +e
sudo "${SCRIPT_DIR}/test-iso-network-lab.sh" "${NET_ARGS[@]}" 2>&1 | tee "${NET_LOG}"
NET_RC=$?
set -e

python3 - <<'PY' "${CMD_LOG_DIR}/summary.json" "${NET_LOG}" "${REPORT_JSON}" "${REPORT_MD}" "${CMD_RC}" "${NET_RC}" "${ISO_PATH}" "${REPO_ROOT}/README.md"
import json
import re
import sys
from pathlib import Path

cmd_summary_path = Path(sys.argv[1])
net_log_path = Path(sys.argv[2])
report_json_path = Path(sys.argv[3])
report_md_path = Path(sys.argv[4])
cmd_rc = int(sys.argv[5])
net_rc = int(sys.argv[6])
iso_path = sys.argv[7]
readme_path = Path(sys.argv[8])

summary = json.loads(cmd_summary_path.read_text(encoding="utf-8")) if cmd_summary_path.exists() else {}
net_log = net_log_path.read_text(encoding="utf-8", errors="ignore") if net_log_path.exists() else ""
readme = readme_path.read_text(encoding="utf-8", errors="ignore") if readme_path.exists() else ""

commands = summary.get("commands", [])

def cmd_pass(fragment: str) -> bool:
    for item in commands:
        if fragment in item.get("command", "") and item.get("status") == "pass":
            return True
    return False

def log_has(fragment: str) -> bool:
    return fragment in net_log

checks = [
    ("MVPv1-1", "VyOS base + build tooling stabilized", summary.get("login", {}).get("success") is True and cmd_rc == 0 and net_rc == 0),
    ("MVPv1-2", "bind9 integration + RPZ generation", cmd_pass("show clawgress rpz") and log_has("PASS: github.com blocked via 192.168.50.1")),
    ("MVPv1-3", "Policy engine + CLI/API", cmd_pass("RAW: set service clawgress enable") and cmd_pass("RAW: commit") and log_has("PASS: API clawgress/health returned success=true") and log_has("PASS: API clawgress/policy returned success=true")),
    ("MVPv1-4", "Forced DNS + egress firewall (53/80/443)", log_has("PASS: github.com blocked via 192.168.50.1") and log_has("PASS: google.com blocked via 192.168.50.1") and log_has("PASS: trello.com blocked via 192.168.50.1") and log_has("PASS: github.com resolved via 192.168.50.1")),
    ("MVPv1-5", "Logging + deny-reason mapping", cmd_pass("show clawgress telemetry") and re.search(r"status=(SERVFAIL|NXDOMAIN)", net_log) is not None),
    ("MVPv1-6", "Docs (quickstart + policy.json + CLI/API)", all(x in readme for x in ["## MVP Scope", "### MVPv1", "### MVPv2", "## REST API Examples"])),
    ("MVPv1-7", "Release artifacts (ISO/OVA/QCOW2)", Path(iso_path).is_file()),
    ("MVPv2-1", "Proxy/SNI allowlist mode", cmd_pass("policy proxy mode sni-allowlist") and cmd_pass("policy proxy backend none") and cmd_pass("policy proxy domain api.openai.com")),
    ("MVPv2-2", "Per-host policies", cmd_pass("policy host agent1 source") and cmd_pass("policy host agent1 exfil") and cmd_pass("host agent1 source")),
    ("MVPv2-3", "Agent telemetry (usage/denies/cache)", cmd_pass("show clawgress telemetry") and cmd_pass("show clawgress telemetry agents") and cmd_pass("show clawgress telemetry domains") and log_has("PASS: API clawgress/telemetry returned success=true")),
    ("MVPv2-4", "Rate limiting / shaping", cmd_pass("policy rate-limit-kbps 8000") and cmd_pass("match \"service clawgress policy rate-limit-kbps\"")),
    ("MVPv2-5", "Time-based policy windows", log_has("Applying restrictive time-window test") and log_has("PASS: api.slack.com blocked via 192.168.50.1")),
    ("MVPv2-6", "Data exfiltration caps", cmd_pass("exfil domain api.openai.com bytes 1048576") and cmd_pass("exfil domain api.openai.com period hour") and cmd_pass("match \"service clawgress policy host agent1 exfil domain api.openai.com bytes\"")),
    ("MVPv2.1-1", "Proxy backend enforcement (haproxy only)", cmd_pass("backend\":\"nginx\"") and cmd_pass("\"success\": false") and cmd_pass("policy.proxy.backend must be \\\"none\\\" or \\\"haproxy\\\"") and cmd_pass("set service clawgress policy proxy backend haproxy")),
    ("MVPv2.1-2", "Telemetry export redaction/no-redaction (CLI+API)", cmd_pass("telemetry export --window 1h | no-more | grep -q '<redacted>'") and cmd_pass("telemetry export --window 1h --no-redact | no-more | grep -q '\"source_ips\": {'") and cmd_pass("redact\":true") and cmd_pass("redact\":false")),
    ("MVPv2.1-3", "Effective-state backend activity", cmd_pass("show clawgress status | no-more | grep -q '\"haproxy_active\": true'")),
    ("MVPv2.1-4", "Commit diagnostics in /var/log/messages", cmd_pass("RAW: commit") and cmd_pass("sudo tail -n 400 /var/log/messages")),
]

result = {
    "cmd_suite_rc": cmd_rc,
    "net_suite_rc": net_rc,
    "iso": iso_path,
    "checks": [
        {"id": cid, "item": item, "status": "PASS" if ok else "FAIL"}
        for cid, item, ok in checks
    ],
}

report_json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

lines = [
    "# MVPv1 + MVPv2 E2E Report",
    "",
    f"- ISO: `{iso_path}`",
    f"- Command suite rc: `{cmd_rc}`",
    f"- Network suite rc: `{net_rc}`",
    "",
    "| ID | Item | Status |",
    "|---|---|---|",
]
for row in result["checks"]:
    lines.append(f"| {row['id']} | {row['item']} | {row['status']} |")

report_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

failed = [row for row in result["checks"] if row["status"] != "PASS"]
if failed:
    print("FAIL")
    for row in failed:
        print(f"{row['id']}: {row['item']}")
    sys.exit(1)

print("PASS")
sys.exit(0)
PY

REPORT_RC=$?

log "Report JSON: ${REPORT_JSON}"
log "Report Markdown: ${REPORT_MD}"

if [[ ${KEEP_DOWNLOADS} -eq 0 && -n "${DOWNLOAD_DIR}" ]]; then
  rm -rf "${DOWNLOAD_DIR}"
fi

if [[ ${REPORT_RC} -ne 0 ]]; then
  fail "MVPv1/MVPv2 validation report has failures"
fi

log "MVPv1/MVPv2 enhanced validation passed"
