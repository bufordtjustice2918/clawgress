# Clawgress Local CLI Mapping Validation (QEMU, No SSH)

Use this workflow to validate command mappings and runtime file/state wiring directly from the device CLI in QEMU.

## Purpose

- Validate op-mode command availability (for example `show clawgress ...`).
- Validate config command visibility (for example `show configuration commands | match clawgress`).
- Validate installed files/templates/caches/binaries in the live image.
- Keep all evidence in a unique `/tmp` run directory per execution.

## 1. Build a unique command set file

```bash
RUNSTAMP=$(date +%Y%m%d-%H%M%S)
LOGDIR="/tmp/clawgress-cmdsuite-${RUNSTAMP}"
CMDFILE="${LOGDIR}/commands.txt"
mkdir -p "${LOGDIR}"

cat > "${CMDFILE}" <<'EOF'
show clawgress status
show clawgress telemetry
show clawgress firewall
show clawgress rpz
show configuration commands | match clawgress
ls -la /opt/vyatta/share/vyatta-op/templates/show/clawgress || true
find /opt/vyatta/share/vyatta-op/templates -maxdepth 5 -type d | grep -i clawgress || true
ls -la /usr/share/vyos/op-mode-definitions | grep -i clawgress || true
ls -la /usr/share/vyos/interface-definitions | grep -i clawgress || true
grep -n 'clawgress' /usr/share/vyos/op_cache.json | head -n 40 || true
ls -la /usr/libexec/vyos/op_mode/clawgress.py /usr/libexec/vyos/conf_mode/clawgress.py || true
ls -la /usr/bin/clawgress /usr/bin/clawgress-policy-apply /usr/bin/clawgress-firewall-apply || true
systemctl is-active bind9 || true
nft list table inet clawgress 2>/dev/null | head -n 40 || true
ls -la /config/clawgress /var/lib/clawgress 2>/dev/null || true
EOF
```

## 2. Run directly against a local ISO artifact

```bash
cd /home/kavan/Documents/dev/clawgress
sg kvm -c "python3 ./scripts/test-iso-commands.py \
  --iso /tmp/clawgress-gh-iso-cache/clawgress-images-clawgress-mvpv2-207/vyos-clawgress-mvpv2-generic-amd64.iso \
  --force-kvm \
  --log-dir ${LOGDIR} \
  --commands-file ${CMDFILE}"
```

Notes:
- This uses direct CLI command execution inside the VM session (human-style command text).
- No SSH path is used.

## 3. Review outputs

Primary outputs:
- `${LOGDIR}/summary.json`
- `${LOGDIR}/serial-session.log`

Quick checks:

```bash
cat "${LOGDIR}/summary.json"
```

```bash
rg -n "Invalid command|clawgress|op_cache|templates/show/clawgress|No such file" "${LOGDIR}/serial-session.log"
```

## 4. Interpretation examples

- `Invalid command: show [clawgress]`:
  - op-mode mapping not registered in runtime command tree.
- `show-clawgress.xml.in` present but no `templates/show/clawgress`:
  - XML present, generated op template not present in image.
- No `clawgress` entries in `op_cache.json`:
  - op cache generation/overlay missing the command tree.
- Missing `/usr/libexec/vyos/op_mode/clawgress.py` or conf script:
  - script overlay/package install path issue.

## 5. Hygiene

- Always use a unique `${LOGDIR}` to avoid mixing runs.
- Keep older run dirs for side-by-side diffing:

```bash
ls -1d /tmp/clawgress-cmdsuite-* | tail -n 20
```

