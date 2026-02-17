#!/usr/bin/env bash
set -euo pipefail

ISO_FILE=""
RAM_MB=2048
CPUS=2
DISK_SIZE="10G"
BOOT_TIMEOUT=420
COMMIT_TIMEOUT=480
USE_KVM=1
FORCE_KVM=0
KEEP_LAB=0
KEEP_ARTIFACTS=0
CLAWGRESS_E2E=0

QEMU_LOCK_FILE="/run/lock/clawgress-qemu-netlab.lock"
QEMU_PROCESS_PATTERN='qemu-system-.*clawgress-(local-test|cmd-suite|smoke-test|net-lab)'
QEMU_NAME="clawgress-net-lab"

NETNS="clawlan"
BRIDGE_IF="clawbr0"
TAP_IF="clawtap0"
VETH_HOST_IF="clawveth0"
VETH_NS_IF="clawveth1"
LAN_CIDR="192.168.50.0/24"
LAN_GW_IP="192.168.50.1"
LAN_CLIENT_IP="192.168.50.10"
LAN_PREFIX="24"

WORKDIR=""
DISK_FILE=""
QEMU_LOG=""
SERIAL_SESSION_LOG=""
SERIAL_PTY_PATH=""
QEMU_PID=""
LAB_NS_RESOLV_DIR=""

usage() {
    cat <<'USAGE'
Usage:
  sudo ./scripts/test-iso-network-lab.sh --iso /path/to/vyos.iso [options]

Purpose:
  Boot VyOS ISO as a dual-NIC firewall lab:
  - eth0 (WAN): QEMU user-mode NAT (host internet)
  - eth1 (LAN): host-only bridge + netns client for end-to-end testing

Options:
  --iso PATH           ISO path (required)
  --timeout SEC        Boot/login timeout seconds (default: 420)
  --commit-timeout SEC Commit timeout seconds (default: 480)
  --ram MB             VM memory in MB (default: 2048)
  --cpus N             VM CPUs (default: 2)
  --disk-size SIZE     Disk image size (default: 10G)
  --no-kvm             Disable KVM acceleration
  --force-kvm          Require KVM and fail if unavailable
  --keep-lab           Keep VM + netns/bridge alive after script finishes
  --keep-artifacts     Keep temp workdir/logs under /tmp
  --clawgress-e2e      Enable Clawgress policy, validate allow/deny, then disable and re-validate
  -h, --help           Show help

Examples:
  sudo ./scripts/test-iso-network-lab.sh --iso /tmp/vyos.iso
  sudo ./scripts/test-iso-network-lab.sh --iso /tmp/vyos.iso --force-kvm --keep-lab
USAGE
}

log() {
    printf '[test-iso-network-lab] %s\n' "$*"
}

fail() {
    printf '[test-iso-network-lab] ERROR: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

acquire_run_lock() {
    if command -v flock >/dev/null 2>&1; then
        mkdir -p "$(dirname "${QEMU_LOCK_FILE}")"
        exec 9>"${QEMU_LOCK_FILE}"
        flock -x 9
    else
        log "flock not found; continuing without lock file protection"
    fi
}

kill_stale_qemu() {
    local pids
    pids="$(pgrep -f "${QEMU_PROCESS_PATTERN}" || true)"
    if [[ -z "${pids}" ]]; then
        return 0
    fi

    log "Found stale Clawgress QEMU process(es): ${pids}"
    log "Stopping stale process(es) before starting a new run"
    kill ${pids} 2>/dev/null || true
    sleep 2

    pids="$(pgrep -f "${QEMU_PROCESS_PATTERN}" || true)"
    if [[ -n "${pids}" ]]; then
        log "Force-killing remaining stale process(es): ${pids}"
        kill -9 ${pids} 2>/dev/null || true
        sleep 1
    fi
}

cleanup_network() {
    ip -n "${NETNS}" link del "${VETH_NS_IF}" >/dev/null 2>&1 || true
    ip netns del "${NETNS}" >/dev/null 2>&1 || true

    ip link del "${VETH_HOST_IF}" >/dev/null 2>&1 || true
    ip link set "${TAP_IF}" down >/dev/null 2>&1 || true
    ip tuntap del dev "${TAP_IF}" mode tap >/dev/null 2>&1 || true

    ip link set "${BRIDGE_IF}" down >/dev/null 2>&1 || true
    ip link del "${BRIDGE_IF}" type bridge >/dev/null 2>&1 || true

    if [[ -n "${LAB_NS_RESOLV_DIR}" && -d "${LAB_NS_RESOLV_DIR}" ]]; then
        rm -rf "${LAB_NS_RESOLV_DIR}"
    fi
}

cleanup() {
    if [[ ${KEEP_LAB} -eq 0 ]]; then
        if [[ -n "${QEMU_PID}" ]] && kill -0 "${QEMU_PID}" 2>/dev/null; then
            log "Stopping VM"
            kill "${QEMU_PID}" 2>/dev/null || true
            sleep 1
            kill -9 "${QEMU_PID}" 2>/dev/null || true
        fi
        cleanup_network
    else
        if [[ -n "${QEMU_PID}" ]] && kill -0 "${QEMU_PID}" 2>/dev/null; then
            log "Leaving VM running (PID: ${QEMU_PID})"
        fi
        log "Keeping network lab state (netns=${NETNS}, bridge=${BRIDGE_IF})"
    fi

    if [[ ${KEEP_ARTIFACTS} -eq 1 || ${KEEP_LAB} -eq 1 ]]; then
        if [[ -n "${WORKDIR}" ]]; then
            log "Keeping artifacts in ${WORKDIR}"
        fi
    else
        if [[ -n "${WORKDIR}" ]]; then
            rm -rf "${WORKDIR}"
        fi
    fi
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iso)
            ISO_FILE="${2:-}"
            shift 2
            ;;
        --timeout)
            BOOT_TIMEOUT="${2:-}"
            shift 2
            ;;
        --commit-timeout)
            COMMIT_TIMEOUT="${2:-}"
            shift 2
            ;;
        --ram)
            RAM_MB="${2:-}"
            shift 2
            ;;
        --cpus)
            CPUS="${2:-}"
            shift 2
            ;;
        --disk-size)
            DISK_SIZE="${2:-}"
            shift 2
            ;;
        --no-kvm)
            USE_KVM=0
            shift
            ;;
        --force-kvm)
            FORCE_KVM=1
            shift
            ;;
        --keep-lab)
            KEEP_LAB=1
            KEEP_ARTIFACTS=1
            shift
            ;;
        --keep-artifacts)
            KEEP_ARTIFACTS=1
            shift
            ;;
        --clawgress-e2e)
            CLAWGRESS_E2E=1
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

[[ -n "${ISO_FILE}" ]] || fail "--iso is required"
[[ -f "${ISO_FILE}" ]] || fail "ISO not found: ${ISO_FILE}"
[[ ${EUID} -eq 0 ]] || fail "Run as root (sudo) so the script can create netns/bridge/tap"

run_vyos_serial_commands() {
    local label="$1"
    local commands="$2"
    log "${label}"

    SERIAL_PTY_PATH="${SERIAL_PTY_PATH}" \
    SERIAL_SESSION_LOG="${SERIAL_SESSION_LOG}" \
    BOOT_TIMEOUT="${BOOT_TIMEOUT}" \
    COMMIT_TIMEOUT="${COMMIT_TIMEOUT}" \
    COMMANDS_PAYLOAD="${commands}" \
    python3 - <<'PY'
import os
import re
import pexpect
import pexpect.fdpexpect

serial_pty = os.environ["SERIAL_PTY_PATH"]
serial_log_path = os.environ["SERIAL_SESSION_LOG"]
boot_timeout = int(os.environ["BOOT_TIMEOUT"])
commit_timeout = int(os.environ["COMMIT_TIMEOUT"])
commands = [line.strip() for line in os.environ["COMMANDS_PAYLOAD"].splitlines() if line.strip()]

PROMPT_RE = r"(?m)^[^\r\n]*@[^\r\n]*(?::[^\r\n]*)?[$#] ?$"
LOGIN_RE = r"(?i)login:"
PASSWORD_RE = r"(?i)password:"

fd = os.open(serial_pty, os.O_RDWR | os.O_NOCTTY)
child = pexpect.fdpexpect.fdspawn(fd, encoding="utf-8", timeout=boot_timeout)

with open(serial_log_path, "a", encoding="utf-8") as serial_log:
    child.logfile = serial_log
    child.sendline("")
    idx = child.expect([PROMPT_RE, LOGIN_RE], timeout=boot_timeout)
    if idx == 1:
        child.sendline("vyos")
        child.expect(PASSWORD_RE, timeout=60)
        child.sendline("vyos")
        child.expect(PROMPT_RE, timeout=90)

    for cmd in commands:
        child.sendline(cmd)
        timeout = commit_timeout if cmd == "commit" else 120
        child.expect(PROMPT_RE, timeout=timeout)

os.close(fd)
PY
}

dns_status() {
    local server="$1"
    local domain="$2"
    local output status
    output="$(ip netns exec "${NETNS}" dig +time=3 +tries=1 @"${server}" "${domain}" A 2>&1 || true)"
    status="$(printf '%s\n' "${output}" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -n 1)"
    printf '%s\n' "${status}"
}

assert_dns_allowed() {
    local server="$1"
    local domain="$2"
    local status=""
    for _ in $(seq 1 12); do
        status="$(dns_status "${server}" "${domain}")"
        if [[ "${status}" == "NOERROR" ]]; then
            log "PASS: ${domain} resolved via ${server}"
            return 0
        fi
        sleep 2
    done
    fail "Expected ${domain} to resolve via ${server}, last status='${status:-none}'"
}

wait_dns_settle() {
    local server="$1"
    local domain="${2:-example.com}"
    local status=""
    for _ in $(seq 1 20); do
        status="$(dns_status "${server}" "${domain}")"
        if [[ "${status}" == "NOERROR" ]]; then
            return 0
        fi
        sleep 2
    done
    log "WARN: DNS settle check for ${domain} via ${server} did not reach NOERROR (last=${status:-none})"
    return 0
}

assert_dns_blocked() {
    local server="$1"
    local domain="$2"
    local status=""
    for _ in $(seq 1 12); do
        status="$(dns_status "${server}" "${domain}")"
        if [[ -n "${status}" && "${status}" != "NOERROR" ]]; then
            log "PASS: ${domain} blocked via ${server} (status=${status})"
            return 0
        fi
        sleep 2
    done
    fail "Expected ${domain} to be blocked via ${server}, last status='${status:-none}'"
}

wan_tcp_probe() {
    local host="$1"
    local port="$2"
    ip netns exec "${NETNS}" bash -lc "exec 3<>/dev/tcp/${host}/${port}" >/dev/null 2>&1
}

next_day_token() {
    local today idx
    today="$(date +%u)"
    idx=$((today % 7))
    case "${idx}" in
        0) echo "mon" ;;
        1) echo "tue" ;;
        2) echo "wed" ;;
        3) echo "thu" ;;
        4) echo "fri" ;;
        5) echo "sat" ;;
        6) echo "sun" ;;
        *) echo "sun" ;;
    esac
}

assert_api_success() {
    local endpoint="$1"
    local payload="$2"
    local response=""
    local path
    local last_response=""

    for path in "/api/${endpoint}" "/${endpoint}"; do
        response="$(ip netns exec "${NETNS}" curl -ksS --max-time 15 \
            -X POST "https://${LAN_GW_IP}${path}" \
            -H "Content-Type: application/json" \
            -d "${payload}" || true)"
        last_response="${response}"
        if printf '%s\n' "${response}" | grep -Eq '"success"[[:space:]]*:[[:space:]]*true'; then
            log "PASS: API ${endpoint} returned success=true via ${path}"
            return 0
        fi
    done

    fail "API endpoint ${endpoint} failed on all known paths. Last response: ${last_response}"
}

wait_api_ready() {
    local body=""
    for _ in $(seq 1 30); do
        body="$(ip netns exec "${NETNS}" curl -ksS --max-time 8 "https://${LAN_GW_IP}/openapi.json" || true)"
        if printf '%s\n' "${body}" | grep -q '"openapi"'; then
            log "PASS: HTTPS API listener is ready at /openapi.json"
            return 0
        fi

        body="$(ip netns exec "${NETNS}" curl -ksS --max-time 8 "https://${LAN_GW_IP}/api/openapi.json" || true)"
        if printf '%s\n' "${body}" | grep -q '"openapi"'; then
            log "PASS: HTTPS API listener is ready at /api/openapi.json"
            return 0
        fi
        sleep 2
    done
    fail "HTTPS API listener did not report OpenAPI schema on known paths"
}

need_cmd qemu-system-x86_64
need_cmd qemu-img
need_cmd ip
need_cmd python3
need_cmd timeout

acquire_run_lock
kill_stale_qemu
cleanup_network

WORKDIR="$(mktemp -d /tmp/clawgress-netlab.XXXXXX)"
DISK_FILE="${WORKDIR}/test-disk.qcow2"
QEMU_LOG="${WORKDIR}/qemu.log"
SERIAL_SESSION_LOG="${WORKDIR}/serial-session.log"

log "ISO: ${ISO_FILE}"
log "Workdir: ${WORKDIR}"
log "Creating disk image (${DISK_SIZE})"
qemu-img create -f qcow2 "${DISK_FILE}" "${DISK_SIZE}" >/dev/null

log "Setting up LAN bridge/netns"
ip link add "${BRIDGE_IF}" type bridge
ip link set "${BRIDGE_IF}" up

ip tuntap add dev "${TAP_IF}" mode tap
ip link set "${TAP_IF}" master "${BRIDGE_IF}"
ip link set "${TAP_IF}" up

ip link add "${VETH_HOST_IF}" type veth peer name "${VETH_NS_IF}"
ip link set "${VETH_HOST_IF}" master "${BRIDGE_IF}"
ip link set "${VETH_HOST_IF}" up

ip netns add "${NETNS}"
ip link set "${VETH_NS_IF}" netns "${NETNS}"
ip -n "${NETNS}" addr add "${LAN_CLIENT_IP}/${LAN_PREFIX}" dev "${VETH_NS_IF}"
ip -n "${NETNS}" link set lo up
ip -n "${NETNS}" link set "${VETH_NS_IF}" up
ip -n "${NETNS}" route add default via "${LAN_GW_IP}"

LAB_NS_RESOLV_DIR="/etc/netns/${NETNS}"
mkdir -p "${LAB_NS_RESOLV_DIR}"
printf 'nameserver %s\n' "${LAN_GW_IP}" > "${LAB_NS_RESOLV_DIR}/resolv.conf"

QEMU_ACCEL_ARGS=()
if [[ ${FORCE_KVM} -eq 1 ]]; then
    [[ -e /dev/kvm ]] || fail "--force-kvm requested but /dev/kvm does not exist"
    QEMU_ACCEL_ARGS=(-enable-kvm -cpu host)
    log "Using forced KVM acceleration"
elif [[ ${USE_KVM} -eq 1 ]]; then
    if [[ -e /dev/kvm ]]; then
        QEMU_ACCEL_ARGS=(-enable-kvm -cpu host)
        log "Using KVM acceleration"
    else
        log "KVM unavailable; using software emulation"
    fi
fi

log "Starting QEMU dual-NIC lab VM"
: > "${QEMU_LOG}"
qemu-system-x86_64 \
    -name "${QEMU_NAME}" \
    -m "${RAM_MB}" \
    -smp "${CPUS}" \
    "${QEMU_ACCEL_ARGS[@]}" \
    -cdrom "${ISO_FILE}" \
    -drive "file=${DISK_FILE},format=qcow2,if=virtio" \
    -boot d \
    -nographic \
    -serial pty \
    -monitor none \
    -display none \
    -netdev user,id=wan,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=wan \
    -netdev tap,id=lan,ifname="${TAP_IF}",script=no,downscript=no \
    -device virtio-net-pci,netdev=lan \
    >"${QEMU_LOG}" 2>&1 &
QEMU_PID=$!

for _ in $(seq 1 100); do
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        fail "QEMU exited early; check ${QEMU_LOG}"
    fi
    SERIAL_PTY_PATH="$(grep -oE '/dev/pts/[0-9]+' "${QEMU_LOG}" | tail -n 1 || true)"
    [[ -n "${SERIAL_PTY_PATH}" ]] && break
    sleep 0.2
done

[[ -n "${SERIAL_PTY_PATH}" ]] || fail "Could not determine QEMU serial PTY path from ${QEMU_LOG}"

log "Serial PTY: ${SERIAL_PTY_PATH}"
log "Provisioning VyOS interfaces/NAT/DNS-forwarding via serial console"

SERIAL_PTY_PATH="${SERIAL_PTY_PATH}" \
SERIAL_SESSION_LOG="${SERIAL_SESSION_LOG}" \
BOOT_TIMEOUT="${BOOT_TIMEOUT}" \
COMMIT_TIMEOUT="${COMMIT_TIMEOUT}" \
LAN_GW_IP="${LAN_GW_IP}" \
LAN_CIDR="${LAN_CIDR}" \
timeout "$((BOOT_TIMEOUT + COMMIT_TIMEOUT + 120))" python3 - <<'PY'
import os
import re
import sys

import pexpect
import pexpect.fdpexpect

serial_pty = os.environ["SERIAL_PTY_PATH"]
serial_log_path = os.environ["SERIAL_SESSION_LOG"]
boot_timeout = int(os.environ["BOOT_TIMEOUT"])
commit_timeout = int(os.environ["COMMIT_TIMEOUT"])
lan_gw_ip = os.environ["LAN_GW_IP"]
lan_cidr = os.environ["LAN_CIDR"]

PROMPT_RE = r"(?m)^[^\r\n]*@[^\r\n]*(?::[^\r\n]*)?[$#] ?$"
LOGIN_RE = r"(?i)login:"
PASSWORD_RE = r"(?i)password:"

fd = os.open(serial_pty, os.O_RDWR | os.O_NOCTTY)
child = pexpect.fdpexpect.fdspawn(fd, encoding="utf-8", timeout=boot_timeout)

with open(serial_log_path, "w", encoding="utf-8") as serial_log:
    child.logfile = serial_log

    child.expect(LOGIN_RE)
    child.sendline("vyos")
    child.expect(PASSWORD_RE, timeout=60)
    child.sendline("vyos")
    child.expect(PROMPT_RE, timeout=90)

    commands = [
        "configure",
        "delete interfaces ethernet eth0 address",
        "set interfaces ethernet eth0 address 10.0.2.15/24",
        "set protocols static route 0.0.0.0/0 next-hop 10.0.2.2",
        f"set interfaces ethernet eth1 address {lan_gw_ip}/24",
        "set system name-server 1.1.1.1",
        "set system name-server 8.8.8.8",
        "set nat source rule 100 outbound-interface name eth0",
        f"set nat source rule 100 source address {lan_cidr}",
        "set nat source rule 100 translation address masquerade",
        f"set service dns forwarding listen-address {lan_gw_ip}",
        f"set service dns forwarding allow-from {lan_cidr}",
        "commit",
        "save",
        "exit",
    ]

    for cmd in commands:
        child.sendline(cmd)
        timeout = commit_timeout if cmd == "commit" else 120
        child.expect(PROMPT_RE, timeout=timeout)

os.close(fd)
PY

log "Running LAN-side validation from namespace ${NETNS}"

ping -c 1 -W 2 "${LAN_GW_IP}" >/dev/null || true
ip netns exec "${NETNS}" ping -c 2 -W 2 "${LAN_GW_IP}"

log "Waiting for WAN readiness (TCP probe, up to 90s)"
WAN_READY=0
for _ in $(seq 1 30); do
    if wan_tcp_probe 1.1.1.1 443; then
        WAN_READY=1
        break
    fi
    sleep 3
done
[[ ${WAN_READY} -eq 1 ]] || fail "WAN did not become reachable from LAN namespace in time (TCP to 1.1.1.1:443)"

if ! ip netns exec "${NETNS}" ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1; then
    log "WARN: ICMP ping to 1.1.1.1 failed; continuing because TCP WAN probe passed"
fi

if command -v dig >/dev/null 2>&1; then
    log "Validating external DNS directly (authoritative WAN check)"
    ip netns exec "${NETNS}" dig +time=3 +tries=1 @1.1.1.1 example.com A

    log "Validating DNS via VyOS resolver (diagnostic)"
    RESOLVER_OK=0
    for _ in $(seq 1 10); do
        if ip netns exec "${NETNS}" dig +time=3 +tries=1 @"${LAN_GW_IP}" example.com A; then
            RESOLVER_OK=1
            break
        fi
        sleep 2
    done
    if [[ ${RESOLVER_OK} -eq 0 ]]; then
        log "WARN: DNS via VyOS resolver failed after retries (kept as diagnostic, not hard failure)"
    fi
else
    log "dig not installed; skipping DNS checks"
fi

if command -v curl >/dev/null 2>&1; then
    log "Validating HTTPS egress without DNS dependency (diagnostic)"
    if ! ip netns exec "${NETNS}" curl -I --max-time 15 --resolve example.com:443:104.18.26.120 https://example.com; then
        log "WARN: HTTPS diagnostic check failed (kept as diagnostic, not hard failure)"
    fi
else
    log "curl not installed; skipping HTTP connectivity check"
fi

if [[ ${CLAWGRESS_E2E} -eq 1 ]]; then
    BLOCK_DAY="$(next_day_token)"

    run_vyos_serial_commands "Enabling Clawgress policy for E2E validation" "$(cat <<'CMDS'
configure
set service clawgress enable
set service clawgress listen-address 127.0.0.1
set service clawgress policy domain api.openai.com label llm_provider
set service clawgress policy domain api.anthropic.com label llm_provider
set service clawgress policy domain api.slack.com label llm_provider
set service clawgress policy proxy mode sni-allowlist
set service clawgress policy proxy domain api.openai.com
set service clawgress policy proxy domain api.anthropic.com
set service https api
set service https api rest
set service https listen-address 0.0.0.0
set service https api keys id id_key key id_key
commit
save
exit
CMDS
)"

    run_vyos_serial_commands "Applying restrictive time-window test (${BLOCK_DAY})" "$(cat <<CMDS
configure
set service clawgress policy time-window day ${BLOCK_DAY}
set service clawgress policy time-window start 00:00
set service clawgress policy time-window end 00:01
commit
save
exit
CMDS
)"

    log "Clawgress ON + out-of-window: validating allow domain is blocked by time-window"
    assert_dns_blocked "${LAN_GW_IP}" "api.slack.com"

    run_vyos_serial_commands "Removing restrictive time-window test" "$(cat <<'CMDS'
configure
delete service clawgress policy time-window
commit
save
exit
CMDS
)"

    wait_dns_settle "${LAN_GW_IP}" "example.com"

    log "Clawgress ON: validating allowlist/deny behavior via LAN resolver"
    assert_dns_allowed "${LAN_GW_IP}" "api.openai.com"
    assert_dns_allowed "${LAN_GW_IP}" "api.anthropic.com"
    assert_dns_blocked "${LAN_GW_IP}" "github.com"
    assert_dns_blocked "${LAN_GW_IP}" "google.com"
    assert_dns_blocked "${LAN_GW_IP}" "trello.com"

    run_vyos_serial_commands "Capturing HTTPS API config state" "$(cat <<'CMDS'
show configuration commands | match "service https"
CMDS
)"
    wait_api_ready

    log "Clawgress ON: validating REST API paths"
    assert_api_success "clawgress/health" '{"key":"id_key"}'
    assert_api_success "clawgress/telemetry" '{"key":"id_key"}'
    assert_api_success "clawgress/policy" '{"key":"id_key","apply":false,"policy":{"version":1,"allow":{"domains":["api.openai.com","api.anthropic.com"],"ports":[443]},"labels":{"api.openai.com":"llm_provider","api.anthropic.com":"llm_provider"}}}'

    run_vyos_serial_commands "Disabling Clawgress policy for E2E validation" "$(cat <<'CMDS'
configure
delete service clawgress
commit
save
exit
CMDS
)"

    log "Clawgress OFF: validating normal DNS behavior restored"
    assert_dns_allowed "${LAN_GW_IP}" "api.openai.com"
    assert_dns_allowed "${LAN_GW_IP}" "github.com"
    assert_dns_allowed "${LAN_GW_IP}" "google.com"
    assert_dns_allowed "${LAN_GW_IP}" "trello.com"
fi

run_vyos_serial_commands "Collecting final system diagnostics" "$(cat <<'CMDS'
show clawgress status | no-more
show clawgress telemetry | no-more
show configuration commands | match "service clawgress"
sudo tail -n 800 /var/log/messages
sudo journalctl -u named.service --no-pager -n 200
CMDS
)"

log "Lab validation complete"
log "Artifacts: ${WORKDIR}"
log "Serial transcript: ${SERIAL_SESSION_LOG}"
log "QEMU log: ${QEMU_LOG}"

if [[ ${KEEP_LAB} -eq 1 ]]; then
    log "Live serial console: screen ${SERIAL_PTY_PATH} 115200"
    log "LAN test namespace: ip netns exec ${NETNS} <command>"
fi
