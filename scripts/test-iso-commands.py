#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pexpect


DEFAULT_COMMANDS = [
    "vbash -ic 'show clawgress status'",
    "vbash -ic 'show clawgress telemetry'",
    "vbash -ic 'show clawgress firewall'",
    "vbash -ic 'show clawgress rpz'",
]
QEMU_LOCK_FILE = "/tmp/clawgress-qemu.lock"
QEMU_PROCESS_PATTERN = r"qemu-system-.*clawgress-(local-test|cmd-suite|smoke-test)"

PROMPT_RE = r"(?m)^[^\r\n]*@[^\r\n]*:[^\r\n]*[$#] ?$"
LOGIN_RE = r"(?i)login:"
PASSWORD_RE = r"(?i)password:"
KVM_FAIL_RE = r"failed to initialize kvm|Could not access KVM kernel module"
INVALID_CMD_RE = r"(?im)^\s*Invalid command:"


def log(msg: str) -> None:
    print(f"[test-iso-commands] {msg}")


def fail(msg: str, code: int = 1) -> None:
    print(f"[test-iso-commands] ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def qemu_cmd(iso: str, disk: str, ram_mb: int, cpus: int, use_kvm: bool) -> list[str]:
    cmd = [
        "qemu-system-x86_64",
        "-name",
        "clawgress-cmd-suite",
        "-m",
        str(ram_mb),
        "-smp",
        str(cpus),
        "-cdrom",
        iso,
        "-drive",
        f"file={disk},format=qcow2,if=virtio",
        "-boot",
        "d",
        "-nographic",
        "-serial",
        "mon:stdio",
        "-monitor",
        "none",
        "-display",
        "none",
        "-netdev",
        "user,id=net0",
        "-device",
        "virtio-net-pci,netdev=net0",
    ]
    if use_kvm:
        cmd.extend(["-enable-kvm", "-cpu", "host"])
    return cmd


def load_commands(commands_file: str | None) -> list[str]:
    if not commands_file:
        return list(DEFAULT_COMMANDS)
    lines = []
    with open(commands_file, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
    if not lines:
        fail(f"commands file has no runnable commands: {commands_file}")
    return lines


def run_suite(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.iso):
        fail(f"ISO not found: {args.iso}")

    if shutil.which("qemu-system-x86_64") is None:
        fail("Missing required command: qemu-system-x86_64")
    if shutil.which("qemu-img") is None:
        fail("Missing required command: qemu-img")

    commands = load_commands(args.commands_file)

    lock_handle = open(QEMU_LOCK_FILE, "w", encoding="utf-8")
    try:
        import fcntl
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
    except Exception:
        log("Could not acquire file lock; continuing without lock protection")

    stale = subprocess.run(
        ["pgrep", "-f", QEMU_PROCESS_PATTERN],
        capture_output=True,
        text=True,
        check=False,
    )
    stale_pids = [pid for pid in stale.stdout.split() if pid.strip()]
    if stale_pids:
        log(f"Found stale Clawgress QEMU process(es): {' '.join(stale_pids)}")
        log("Stopping stale process(es) before starting a new run")
        subprocess.run(["kill", *stale_pids], check=False)
        time.sleep(2)
        stale_retry = subprocess.run(
            ["pgrep", "-f", QEMU_PROCESS_PATTERN],
            capture_output=True,
            text=True,
            check=False,
        )
        stale_retry_pids = [pid for pid in stale_retry.stdout.split() if pid.strip()]
        if stale_retry_pids:
            log(f"Force-killing remaining stale process(es): {' '.join(stale_retry_pids)}")
            subprocess.run(["kill", "-9", *stale_retry_pids], check=False)
            time.sleep(1)

    if args.log_dir:
        workdir = Path(args.log_dir)
        workdir.mkdir(parents=True, exist_ok=True)
        keep_workdir = True
    else:
        workdir = Path(tempfile.mkdtemp(prefix="clawgress-cmdsuite."))
        keep_workdir = True

    disk_file = workdir / "test-disk.qcow2"
    transcript_path = workdir / "serial-session.log"
    summary_path = workdir / "summary.json"

    log(f"ISO: {args.iso}")
    log(f"Workdir: {workdir}")
    log(f"Creating disk image ({args.disk_size})")
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(disk_file), args.disk_size],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    kvm_exists = os.path.exists("/dev/kvm")
    kvm_accessible = kvm_exists and os.access("/dev/kvm", os.R_OK | os.W_OK)

    if args.force_kvm and not kvm_exists:
        fail("KVM forced but /dev/kvm does not exist on this host")

    # In force-kvm mode, attempt KVM regardless of os.access() pre-check and
    # fail only if QEMU itself cannot initialize KVM.
    if args.force_kvm:
        use_kvm = True
    else:
        use_kvm = args.use_kvm and kvm_accessible
        if args.use_kvm and not use_kvm:
            log("KVM requested but /dev/kvm is not accessible; using software emulation")

    summary = {
        "iso": args.iso,
        "workdir": str(workdir),
        "login": {"success": False, "used_kvm": use_kvm, "fallback_to_software": False},
        "commands": [],
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ended_at": None,
    }

    child = None
    transcript = None
    try:
        if args.force_kvm:
            attempt_order = [True]
        elif use_kvm:
            attempt_order = [True, False]
        else:
            attempt_order = [False]

        for attempt_kvm in attempt_order:
            cmd = qemu_cmd(args.iso, str(disk_file), args.ram_mb, args.cpus, attempt_kvm)
            log("Starting VM with " + ("KVM" if attempt_kvm else "software emulation"))
            child = pexpect.spawn(cmd[0], cmd[1:], encoding="utf-8", timeout=args.boot_timeout)
            transcript = open(transcript_path, "w", encoding="utf-8")
            child.logfile = transcript

            try:
                child.expect(LOGIN_RE)
                summary["login"]["success"] = True
                summary["login"]["used_kvm"] = attempt_kvm
                summary["login"]["fallback_to_software"] = (use_kvm and not attempt_kvm)
                break
            except pexpect.TIMEOUT:
                if attempt_kvm and not args.force_kvm:
                    child.close(force=True)
                    transcript.close()
                    child = None
                    transcript = None
                    continue
                fail(f"Timed out waiting for login prompt after {args.boot_timeout}s")
            except pexpect.EOF:
                output = child.before or ""
                if attempt_kvm and re.search(KVM_FAIL_RE, output, flags=re.IGNORECASE):
                    if args.force_kvm:
                        fail("KVM forced and QEMU failed to initialize KVM")
                    log("KVM launch failed; retrying without KVM")
                    child.close(force=True)
                    transcript.close()
                    child = None
                    transcript = None
                    continue
                fail("VM exited before login prompt appeared")

        if child is None or not summary["login"]["success"]:
            fail("Unable to boot VM to login prompt")

        log("Login prompt detected, authenticating")
        child.sendline(args.username)
        child.expect(PASSWORD_RE, timeout=args.cmd_timeout)
        child.sendline(args.password)
        child.expect(PROMPT_RE, timeout=args.cmd_timeout)

        for cmd_text in commands:
            marker = f"__CMD_RC__{uuid.uuid4().hex}__"
            wrapped = f"if {cmd_text}; then echo {marker}0; else echo {marker}1; fi"
            log(f"Running: {cmd_text}")
            child.sendline(wrapped)
            child.expect(PROMPT_RE, timeout=args.cmd_timeout)
            output = child.before or ""
            rc_matches = re.findall(rf"{re.escape(marker)}(\d+)", output)
            rc = int(rc_matches[-1]) if rc_matches else 999
            if re.search(INVALID_CMD_RE, output):
                rc = 1
            status = "pass" if rc == 0 else "fail"
            summary["commands"].append(
                {
                    "command": cmd_text,
                    "rc": rc,
                    "status": status,
                    "output_tail": "\n".join(output.strip().splitlines()[-30:]),
                }
            )

        child.sendline("exit")
        try:
            child.expect(pexpect.EOF, timeout=10)
        except Exception:
            pass

    finally:
        try:
            lock_handle.close()
        except Exception:
            pass
        if child is not None and child.isalive():
            child.close(force=True)
        if transcript is not None and not transcript.closed:
            transcript.close()

        summary["ended_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        if args.cleanup_on_success and all(item.get("status") == "pass" for item in summary["commands"]) and summary["login"]["success"]:
            shutil.rmtree(workdir, ignore_errors=True)
            log("All checks passed; cleaned temporary workdir")
        else:
            if keep_workdir:
                log(f"Keeping artifacts in {workdir}")

    failures = [item for item in summary["commands"] if item["status"] != "pass"]
    if not summary["login"]["success"] or failures:
        print(json.dumps(summary, indent=2))
        return 1

    log("All automated command checks passed")
    print(json.dumps(summary, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automated VyOS serial login + command suite runner")
    parser.add_argument("--iso", required=True, help="Path to ISO file")
    parser.add_argument("--username", default="vyos", help="Login username (default: vyos)")
    parser.add_argument("--password", default="vyos", help="Login password (default: vyos)")
    parser.add_argument("--boot-timeout", type=int, default=300, help="Seconds to wait for login prompt")
    parser.add_argument("--cmd-timeout", type=int, default=180, help="Seconds to wait per command")
    parser.add_argument("--ram-mb", type=int, default=2048, help="VM memory in MB")
    parser.add_argument("--cpus", type=int, default=2, help="VM CPU count")
    parser.add_argument("--disk-size", default="10G", help="QCOW2 disk size")
    parser.add_argument("--commands-file", help="Optional newline-delimited shell commands")
    parser.add_argument("--log-dir", help="Directory to store logs/artifacts")
    parser.add_argument(
        "--cleanup-on-success",
        action="store_true",
        help="Delete temp artifacts when all checks pass (default: keep logs)",
    )
    parser.add_argument("--no-kvm", dest="use_kvm", action="store_false", help="Disable KVM")
    parser.add_argument(
        "--force-kvm",
        action="store_true",
        help="Require KVM mode and fail if KVM cannot be used",
    )
    parser.set_defaults(use_kvm=True)
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(run_suite(parse_args()))
