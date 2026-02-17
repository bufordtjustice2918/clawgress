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
import pexpect.fdpexpect


DEFAULT_SMOKE_COMMANDS = [
    "show clawgress status",
    "show clawgress telemetry",
    "show clawgress firewall",
    "show clawgress rpz",
]
DEFAULT_MVP_FULL_COMMANDS = [
    "RAW: configure",
    "RAW: delete service clawgress",
    "RAW: set service clawgress enable",
    "RAW: set service clawgress listen-address 127.0.0.1",
    "RAW: set service clawgress policy domain api.openai.com label llm_provider",
    "RAW: set service clawgress policy domain api.anthropic.com label llm_provider",
    "RAW: set service clawgress policy ip 1.1.1.1/32",
    "RAW: set service clawgress policy port 443",
    "RAW: set service clawgress policy time-window day mon",
    "RAW: set service clawgress policy time-window start 09:00",
    "RAW: set service clawgress policy time-window end 17:00",
    "RAW: set service clawgress policy rate-limit-kbps 8000",
    "RAW: set service clawgress policy proxy mode sni-allowlist",
    "RAW: set service clawgress policy proxy domain api.openai.com",
    "RAW: set service clawgress policy host agent1 source 192.168.10.10/32",
    "RAW: set service clawgress policy host agent1 proxy mode sni-allowlist",
    "RAW: set service clawgress policy host agent1 proxy domain api.openai.com",
    "RAW: set service clawgress policy host agent1 exfil domain api.openai.com bytes 1048576",
    "RAW: set service clawgress policy host agent1 exfil domain api.openai.com period hour",
    "RAW: commit",
    "RAW: save",
    # Run operational checks from config-mode with "run" first.
    "RAW: run show configuration commands | match service clawgress | no-more",
    "RAW: run show clawgress status | no-more",
    "RAW: run show clawgress telemetry | no-more",
    "RAW: run show clawgress firewall | no-more",
    "RAW: run show clawgress rpz | no-more",
    # Return to op-mode for regular show commands.
    "RAW: exit discard",
    "show configuration commands | match service clawgress | no-more",
    "show configuration commands | match \"service clawgress policy rate-limit-kbps\" | no-more | grep -q rate-limit-kbps",
    "show configuration commands | match \"service clawgress policy proxy mode\" | no-more | grep -q sni-allowlist",
    "show configuration commands | match \"service clawgress policy host agent1 source\" | no-more | grep -q 192.168.10.10/32",
    "show configuration commands | match \"service clawgress policy host agent1 exfil domain api.openai.com bytes\" | no-more | grep -q api.openai.com",
    "show configuration commands | match \"service clawgress policy host agent1 exfil domain api.openai.com period\" | no-more | grep -q hour",
    "show configuration commands | match \"service clawgress policy time-window\" | no-more | grep -q time-window",
    "show clawgress status | no-more",
    "show clawgress status | no-more | grep -q '\"policy_present\": true'",
    "show clawgress status | no-more | grep -q '\"rpz_allow_present\": true'",
    "show clawgress status | no-more | grep -q '\"nft_table_present\": true'",
    "show clawgress telemetry | no-more",
    "show clawgress firewall | no-more",
    "show clawgress rpz | no-more",
    "sudo tail -n 400 /var/log/messages",
]
DEFAULT_FAIL_PATTERNS = [
    r"(?im)^\s*Invalid command:",
    r"(?im)\bTable not found\b",
    r"(?im)\bRPZ not configured\b",
    r"(?im)\bCommit failed\b",
    r"(?im)\bSet failed\b",
    r"(?im)\bConfiguration path: .* is not valid\b",
]
QEMU_LOCK_FILE = "/tmp/clawgress-qemu.lock"
QEMU_PROCESS_PATTERN = r"qemu-system-.*clawgress-(local-test|cmd-suite|smoke-test)"

PROMPT_RE = r"(?m)^[^\r\n]*@[^\r\n]*(?::[^\r\n]*)?[$#] ?$"
LOGIN_RE = r"(?i)login:"
PASSWORD_RE = r"(?i)password:"
KVM_FAIL_RE = r"failed to initialize kvm|Could not access KVM kernel module"
INVALID_CMD_RE = r"(?im)^\s*Invalid command:"


def log(msg: str) -> None:
    print(f"[test-iso-commands] {msg}")


def fail(msg: str, code: int = 1) -> None:
    print(f"[test-iso-commands] ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def qemu_cmd(
    iso: str, disk: str, ram_mb: int, cpus: int, use_kvm: bool, serial_pty: bool = False
) -> list[str]:
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
        "-monitor",
        "none",
        "-display",
        "none",
        "-netdev",
        "user,id=net0",
        "-device",
        "virtio-net-pci,netdev=net0",
    ]
    if serial_pty:
        cmd.extend(["-nographic", "-serial", "pty"])
    else:
        cmd.extend(["-nographic", "-serial", "mon:stdio"])
    if use_kvm:
        cmd.extend(["-enable-kvm", "-cpu", "host"])
    return cmd


def load_commands(commands_file: str | None, suite: str) -> list[str]:
    if not commands_file:
        if suite == "mvp-full":
            return list(DEFAULT_MVP_FULL_COMMANDS)
        return list(DEFAULT_SMOKE_COMMANDS)
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

    commands = load_commands(args.commands_file, args.suite)
    fail_patterns = []
    if not args.no_default_fail_patterns:
        fail_patterns.extend(DEFAULT_FAIL_PATTERNS)
    fail_patterns.extend(args.fail_on_pattern or [])

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
        "diagnostics": [],
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ended_at": None,
    }

    child = None
    transcript = None
    qemu_process = None
    qemu_boot_log = None
    serial_fd = None
    serial_pty_path = None
    keep_vm_alive = False
    try:
        if args.force_kvm:
            attempt_order = [True]
        elif use_kvm:
            attempt_order = [True, False]
        else:
            attempt_order = [False]

        for attempt_kvm in attempt_order:
            cmd = qemu_cmd(
                args.iso, str(disk_file), args.ram_mb, args.cpus, attempt_kvm, serial_pty=args.serial_pty
            )
            log("Starting VM with " + ("KVM" if attempt_kvm else "software emulation"))
            transcript = open(transcript_path, "w", encoding="utf-8")
            if args.serial_pty:
                qemu_boot_log_path = workdir / "qemu-boot.log"
                qemu_boot_log = open(qemu_boot_log_path, "w", encoding="utf-8")
                qemu_process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=qemu_boot_log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    start_new_session=True,
                )
                pty_re = re.compile(r"/dev/pts/\d+")
                serial_pty_path = None
                for _ in range(60):
                    if qemu_process.poll() is not None:
                        break
                    try:
                        with open(qemu_boot_log_path, "r", encoding="utf-8", errors="ignore") as handle:
                            boot_text = handle.read()
                        match = pty_re.search(boot_text)
                        if match:
                            serial_pty_path = match.group(0)
                            break
                    except Exception:
                        pass
                    time.sleep(0.2)
                if not serial_pty_path:
                    if qemu_process.poll() is None:
                        qemu_process.terminate()
                    if qemu_boot_log and not qemu_boot_log.closed:
                        qemu_boot_log.close()
                    transcript.close()
                    qemu_boot_log = None
                    transcript = None
                    qemu_process = None
                    continue
                serial_fd = os.open(serial_pty_path, os.O_RDWR | os.O_NOCTTY)
                child = pexpect.fdpexpect.fdspawn(
                    serial_fd, encoding="utf-8", timeout=args.boot_timeout
                )
            else:
                child = pexpect.spawn(cmd[0], cmd[1:], encoding="utf-8", timeout=args.boot_timeout)
            child.logfile = transcript

            try:
                child.expect(LOGIN_RE)
                summary["login"]["success"] = True
                summary["login"]["used_kvm"] = attempt_kvm
                summary["login"]["fallback_to_software"] = (use_kvm and not attempt_kvm)
                summary["login"]["serial_pty"] = serial_pty_path
                break
            except pexpect.TIMEOUT:
                if attempt_kvm and not args.force_kvm:
                    child.close(force=True)
                    if qemu_process is not None and qemu_process.poll() is None:
                        qemu_process.terminate()
                    if serial_fd is not None:
                        os.close(serial_fd)
                        serial_fd = None
                    if transcript is not None and not transcript.closed:
                        transcript.close()
                    if qemu_boot_log is not None and not qemu_boot_log.closed:
                        qemu_boot_log.close()
                    child = None
                    transcript = None
                    qemu_process = None
                    qemu_boot_log = None
                    serial_pty_path = None
                    continue
                fail(f"Timed out waiting for login prompt after {args.boot_timeout}s")
            except pexpect.EOF:
                output = child.before or ""
                boot_output = ""
                if qemu_boot_log is not None:
                    try:
                        qemu_boot_log.flush()
                        with open(workdir / "qemu-boot.log", "r", encoding="utf-8", errors="ignore") as handle:
                            boot_output = handle.read()
                    except Exception:
                        boot_output = ""
                if attempt_kvm and re.search(KVM_FAIL_RE, output, flags=re.IGNORECASE):
                    if args.force_kvm:
                        fail("KVM forced and QEMU failed to initialize KVM")
                    log("KVM launch failed; retrying without KVM")
                    child.close(force=True)
                    if qemu_process is not None and qemu_process.poll() is None:
                        qemu_process.terminate()
                    if serial_fd is not None:
                        os.close(serial_fd)
                        serial_fd = None
                    if transcript is not None and not transcript.closed:
                        transcript.close()
                    if qemu_boot_log is not None and not qemu_boot_log.closed:
                        qemu_boot_log.close()
                    child = None
                    transcript = None
                    qemu_process = None
                    qemu_boot_log = None
                    serial_pty_path = None
                    continue
                if attempt_kvm and re.search(KVM_FAIL_RE, boot_output, flags=re.IGNORECASE):
                    if args.force_kvm:
                        fail("KVM forced and QEMU failed to initialize KVM")
                    log("KVM launch failed; retrying without KVM")
                    if qemu_process is not None and qemu_process.poll() is None:
                        qemu_process.terminate()
                    if serial_fd is not None:
                        os.close(serial_fd)
                        serial_fd = None
                    if transcript is not None and not transcript.closed:
                        transcript.close()
                    if qemu_boot_log is not None and not qemu_boot_log.closed:
                        qemu_boot_log.close()
                    child = None
                    transcript = None
                    qemu_process = None
                    qemu_boot_log = None
                    serial_pty_path = None
                    continue
                fail("VM exited before login prompt appeared")

        if child is None or not summary["login"]["success"]:
            fail("Unable to boot VM to login prompt")

        log("Login prompt detected, authenticating")
        child.sendline(args.username)
        child.expect(PASSWORD_RE, timeout=args.cmd_timeout)
        child.sendline(args.password)
        child.expect(PROMPT_RE, timeout=args.cmd_timeout)

        in_config_mode = False

        messages_snapshot_count = 0

        def run_diag_command(diag_cmd: str, mode: str) -> dict:
            entry = {
                "mode": mode,
                "command": diag_cmd,
                "status": "pass",
                "output_tail": "",
                "matched_fail_patterns": [],
            }
            try:
                child.sendline(diag_cmd)
                child.expect(PROMPT_RE, timeout=60)
                diag_output = child.before or ""
                entry["output_tail"] = "\n".join(diag_output.strip().splitlines()[-80:])
                for pattern in fail_patterns:
                    if re.search(pattern, diag_output):
                        entry["matched_fail_patterns"].append(pattern)
                if entry["matched_fail_patterns"]:
                    entry["status"] = "fail"
            except Exception as exc:
                entry["status"] = "fail"
                entry["output_tail"] = f"diagnostic collection failed: {exc}"
            return entry

        def capture_messages_snapshot(reason: str) -> None:
            nonlocal messages_snapshot_count
            if child is None or not child.isalive():
                return
            diag_cmd = f"sudo tail -n {args.diag_log_lines} /var/log/messages"
            if in_config_mode:
                diag_cmd = f"run {diag_cmd}"
            entry = run_diag_command(diag_cmd, "config" if in_config_mode else "op")
            entry["for_command"] = reason
            entry["diagnostic_type"] = "messages_snapshot"
            summary["diagnostics"].append(entry)

            messages_snapshot_count += 1
            snapshot_path = workdir / f"var-log-messages-{messages_snapshot_count:02d}.log"
            snapshot_path.write_text(entry["output_tail"] + "\n", encoding="utf-8")

        def collect_diagnostics(for_command: str) -> None:
            if in_config_mode:
                diag_commands = [
                    "run show configuration commands | match service clawgress | no-more",
                    "run show clawgress status | no-more",
                    "run show clawgress telemetry | no-more",
                    "run show log | no-more | match clawgress",
                    "run show log | no-more | match rpz",
                    f"run sudo tail -n {args.diag_log_lines} /var/log/messages",
                ]
            else:
                diag_commands = [
                    "show configuration commands | match service clawgress | no-more",
                    "show clawgress status | no-more",
                    "show clawgress telemetry | no-more",
                    "sudo named-checkconf -z",
                    "sudo journalctl -xeu named.service --no-pager -n 200",
                    "sudo sh -c \"grep -R -n 'clawgress\\|rpz' /run/named /etc/bind 2>/dev/null | tail -n 200\"",
                    f"sudo tail -n {args.diag_log_lines} /var/log/messages",
                ]

            for diag_cmd in diag_commands:
                diag_entry = run_diag_command(diag_cmd, "config" if in_config_mode else "op")
                diag_entry["for_command"] = for_command
                summary["diagnostics"].append(diag_entry)

        stop_after_failure = False
        for cmd_text in commands:
            if stop_after_failure:
                break
            raw_mode = False
            effective_cmd = cmd_text
            if cmd_text.startswith("RAW: "):
                raw_mode = True
                effective_cmd = cmd_text[len("RAW: "):].strip()
            if (not raw_mode) and cmd_text.strip().startswith("show ") and "| no-more" not in cmd_text:
                effective_cmd = f"{cmd_text} | no-more"
            marker = f"__CMD_RC__{uuid.uuid4().hex}__"
            log(f"Running: {cmd_text}")
            if raw_mode:
                child.sendline(effective_cmd)
            else:
                wrapped = f"if {effective_cmd}; then echo {marker}0; else echo {marker}1; fi"
                child.sendline(wrapped)
            expect_timeout = args.cmd_timeout
            if raw_mode and effective_cmd == "commit":
                expect_timeout = args.commit_timeout
            try:
                child.expect(PROMPT_RE, timeout=expect_timeout)
                timed_out = False
            except pexpect.TIMEOUT:
                timed_out = True
            output = child.before or ""
            if "[edit]" in output:
                in_config_mode = True
            elif raw_mode and effective_cmd.startswith("configure"):
                in_config_mode = True
            elif raw_mode and effective_cmd.startswith("exit"):
                if "Cannot exit" not in output and "[edit]" not in output:
                    in_config_mode = False
            if timed_out:
                rc = 124
                matched_patterns = ["timeout"]
                if raw_mode and effective_cmd == "commit":
                    log("Commit timed out; attempting interrupt and diagnostics")
                    try:
                        child.sendcontrol("c")
                        child.expect(PROMPT_RE, timeout=30)
                    except Exception:
                        pass
                if args.diag_on_failure:
                    collect_diagnostics(cmd_text)
                status = "fail"
                summary["commands"].append(
                    {
                        "command": cmd_text,
                        "rc": rc,
                        "status": status,
                        "matched_fail_patterns": matched_patterns,
                        "output_tail": "\n".join(output.strip().splitlines()[-30:]),
                    }
                )
                stop_after_failure = True
                continue
            if raw_mode:
                rc = 0
            else:
                rc_matches = re.findall(rf"{re.escape(marker)}(\d+)", output)
                rc = int(rc_matches[-1]) if rc_matches else 999
            if re.search(INVALID_CMD_RE, output):
                rc = 1
            matched_patterns = []
            for pattern in fail_patterns:
                if re.search(pattern, output):
                    matched_patterns.append(pattern)
            if matched_patterns:
                rc = 1
            status = "pass" if rc == 0 else "fail"
            summary["commands"].append(
                {
                    "command": cmd_text,
                    "rc": rc,
                    "status": status,
                    "matched_fail_patterns": matched_patterns,
                    "output_tail": "\n".join(output.strip().splitlines()[-30:]),
                }
            )
            if args.diag_after_each or (args.diag_on_failure and status == "fail"):
                collect_diagnostics(cmd_text)

        capture_messages_snapshot("final")

        child.sendline("exit")
        try:
            child.expect(pexpect.EOF, timeout=10)
        except Exception:
            pass

    finally:
        had_failures = (not summary["login"]["success"]) or any(
            item.get("status") != "pass" for item in summary.get("commands", [])
        )
        vm_running = (
            (qemu_process is not None and qemu_process.poll() is None) or
            (child is not None and child.isalive())
        )
        keep_vm_alive = bool(args.keep_vm_on_failure and had_failures and vm_running)

        if args.debug_on_failure and had_failures and child is not None and child.isalive():
            log("Failure detected; entering interactive serial console (Ctrl-] then Enter to return)")
            try:
                child.interact(escape_character=chr(29))
            except Exception:
                pass
            vm_running = (
                (qemu_process is not None and qemu_process.poll() is None) or
                (child is not None and child.isalive())
            )
            keep_vm_alive = bool(args.keep_vm_on_failure and vm_running)

        try:
            lock_handle.close()
        except Exception:
            pass
        if child is not None and child.isalive() and not keep_vm_alive:
            child.close(force=True)
        if qemu_process is not None and qemu_process.poll() is None and not keep_vm_alive:
            qemu_process.terminate()
            try:
                qemu_process.wait(timeout=5)
            except Exception:
                qemu_process.kill()
        if serial_fd is not None:
            try:
                os.close(serial_fd)
            except Exception:
                pass
        if transcript is not None and not transcript.closed:
            transcript.close()
        if qemu_boot_log is not None and not qemu_boot_log.closed:
            qemu_boot_log.close()

        summary["ended_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        if args.cleanup_on_success and all(item.get("status") == "pass" for item in summary["commands"]) and summary["login"]["success"]:
            shutil.rmtree(workdir, ignore_errors=True)
            log("All checks passed; cleaned temporary workdir")
        else:
            if keep_workdir:
                log(f"Keeping artifacts in {workdir}")
        if keep_vm_alive:
            vm_pid = None
            if qemu_process is not None and qemu_process.poll() is None:
                vm_pid = qemu_process.pid
            elif child is not None and child.isalive():
                vm_pid = child.pid
            if vm_pid is not None:
                log(f"Leaving VM running for debug (PID: {vm_pid})")
            if serial_pty_path:
                log(f"Attach to live serial console with: screen {serial_pty_path} 115200")

    failures = [item for item in summary["commands"] if item["status"] != "pass"]
    diag_failures = [item for item in summary["diagnostics"] if item.get("status") != "pass"]
    if not summary["login"]["success"] or failures or diag_failures:
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
    parser.add_argument(
        "--commit-timeout",
        type=int,
        default=420,
        help="Seconds to wait for commit command before collecting diagnostics",
    )
    parser.add_argument("--ram-mb", type=int, default=2048, help="VM memory in MB")
    parser.add_argument("--cpus", type=int, default=2, help="VM CPU count")
    parser.add_argument("--disk-size", default="10G", help="QCOW2 disk size")
    parser.add_argument("--commands-file", help="Optional newline-delimited shell commands")
    parser.add_argument(
        "--suite",
        choices=["smoke", "mvp-full"],
        default="smoke",
        help="Built-in command suite when --commands-file is not provided",
    )
    parser.add_argument(
        "--fail-on-pattern",
        action="append",
        help="Regex pattern that marks a command as failed if matched in output (repeatable)",
    )
    parser.add_argument(
        "--no-default-fail-patterns",
        action="store_true",
        help="Disable built-in fail patterns (Invalid command/Table not found/RPZ not configured)",
    )
    parser.add_argument("--log-dir", help="Directory to store logs/artifacts")
    parser.add_argument(
        "--diag-after-each",
        action="store_true",
        help="Collect diagnostics after every command (state-aware, more verbose/slower)",
    )
    parser.add_argument(
        "--diag-on-failure",
        action="store_true",
        help="Collect diagnostics after failed/timed-out commands (default: enabled)",
    )
    parser.add_argument(
        "--diag-log-lines",
        type=int,
        default=220,
        help="Number of /var/log/messages lines to collect per diagnostic snapshot in op mode",
    )
    parser.add_argument(
        "--cleanup-on-success",
        action="store_true",
        help="Delete temp artifacts when all checks pass (default: keep logs)",
    )
    parser.add_argument(
        "--keep-vm-on-failure",
        action="store_true",
        help="Do not terminate QEMU when checks fail; keep VM running for manual debugging",
    )
    parser.add_argument(
        "--debug-on-failure",
        action="store_true",
        help="On failure, enter interactive serial console for live debugging before summary is written",
    )
    parser.add_argument(
        "--serial-pty",
        action="store_true",
        help="Run QEMU with serial PTY backend to allow post-run reattachment for debugging",
    )
    parser.add_argument("--no-kvm", dest="use_kvm", action="store_false", help="Disable KVM")
    parser.add_argument(
        "--force-kvm",
        action="store_true",
        help="Require KVM mode and fail if KVM cannot be used",
    )
    parser.set_defaults(use_kvm=True)
    parser.set_defaults(diag_on_failure=True)
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(run_suite(parse_args()))
