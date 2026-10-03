#!/usr/bin/env python3
"""End-to-end test: the whole setup on a real virtual machine.

Run by CI (.github/workflows/ci.yml), once per supported release:

    python3 -u tools/e2e.py <cloud-image.qcow2> <name>

The pieces of harden.sh are tested one by one elsewhere. This runs all of it, the way a
person would on a fresh VPS: a cloud image boots under QEMU/KVM with cloud-init, root logs
in with a key, the script asks its questions on a real terminal, a password is typed for
the new user, the login on the new port is tried from outside before it is confirmed.
Then the result is checked from outside and from inside, --answers and --refresh are run,
the machine is rebooted and checked again, the setup is run a second time through the
installed `sudo harden`, and at the end --undo takes it all back.

It exists because a part that passed every piece-by-piece test still failed as a whole:
versions 2026.10.8 to 2026.10.17 could not finish on an Ubuntu 24.04 cloud image, and
that was found only when someone ran one by hand. Its own first run found two more: the
setup stopped on Debian 12 and on Ubuntu 26.04.
"""
import os
import pathlib
import secrets
import shlex
import socket
import subprocess
import sys
import time

import pexpect

IMAGE = pathlib.Path(sys.argv[1]).resolve()
NAME = sys.argv[2]
CROWDSEC = sys.argv[3] if len(sys.argv) > 3 else "yes"
ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK = pathlib.Path("e2e-work").resolve()
KEY = WORK / "key"
OLD = 2222          # host port forwarded to the guest's port 22
NEW = 2233          # the new SSH port, the same number on host and guest
GATEWAY = "10.0.2.2"  # how the guest sees this host under QEMU user networking

# The units the setup switches off where they are on, and how each one stands: --undo has
# to leave them the way they were found.
UNITS_PROBE = ("for u in apport.service apport-autoreport.path apport-autoreport.timer apport-forward.socket "
               "ModemManager.service udisks2.service; do "
               "echo \"$u: $(systemctl is-enabled $u 2>/dev/null)\"; done")

SSH = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
       "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "-o", "IdentitiesOnly=yes",
       "-i", str(KEY)]


def say(msg):
    print(f"\n=== {msg}", flush=True)


def fail(msg):
    print(f"\nE2E FAILED ({NAME}): {msg}", flush=True)
    for port, user in ((NEW, "alex"), (OLD, "root")):
        r = ssh(port, user, "tail -n 60 /var/log/harden.log 2>/dev/null || sudo -n tail -n 60 /var/log/harden.log",
                check=False)
        if r.stdout.strip():
            print(f"--- /var/log/harden.log via {user}@{port}\n{r.stdout}", flush=True)
            break
    sys.exit(1)


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def ssh(port, user, command, check=True, timeout=180, extra=()):
    try:
        r = subprocess.run(["ssh", *SSH, "-o", "BatchMode=yes", *extra, "-p", str(port),
                            f"{user}@127.0.0.1", command],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        r = subprocess.CompletedProcess([], 255, "", "timed out")
    if check and r.returncode != 0:
        print(r.stdout, r.stderr, flush=True)
        fail(f"`{command}` as {user} on port {port} returned {r.returncode}")
    return r


def banner(port):
    """The first bytes a server on that port sends, or nothing. QEMU accepts the TCP
    connection itself, so "connected" proves nothing; an SSH banner does."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.settimeout(5)
            return s.recv(64)
    except OSError:
        return b""


def wait_for_login(port, user, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if banner(port).startswith(b"SSH-") and ssh(port, user, "true", check=False).returncode == 0:
            return
        time.sleep(5)
    fail(f"no SSH login as {user} on port {port} within {seconds} s")


def boot():
    say(f"booting {NAME}")
    WORK.mkdir(exist_ok=True)
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(KEY))
    pub = KEY.with_suffix(".pub").read_text().strip()
    # A provider's image as an admin meets it: root with a key, and one more account with
    # passwordless sudo, the way cloud-init makes "ubuntu" or "debian".
    (WORK / "user-data").write_text(f"""#cloud-config
hostname: e2e
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - {pub}
  - name: provider
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - {pub}
""")
    (WORK / "meta-data").write_text(f"instance-id: e2e-{NAME}\nlocal-hostname: e2e\n")
    run("cloud-localds", str(WORK / "seed.iso"), str(WORK / "user-data"), str(WORK / "meta-data"))
    run("qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(IMAGE), str(WORK / "disk.qcow2"), "20G")
    run("sudo", "qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "2048", "-smp", "2",
        "-display", "none", "-serial", f"file:{WORK / 'serial.log'}",
        "-drive", f"file={WORK / 'disk.qcow2'},if=virtio",
        "-drive", f"file={WORK / 'seed.iso'},if=virtio,format=raw",
        "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{OLD}-:22,hostfwd=tcp:127.0.0.1:{NEW}-:{NEW}",
        "-device", "virtio-net-pci,netdev=n0",
        "-daemonize", "-pidfile", str(WORK / "qemu.pid"))
    wait_for_login(OLD, "root", 420)
    print(ssh(OLD, "root", "grep PRETTY_NAME /etc/os-release; uname -r; ssh -V 2>&1; systemctl is-enabled ssh.socket 2>&1 || true").stdout)
    return pub


def answers(pub, tmux=False, **more):
    env = {
        "HARDEN_LANG": "en",
        "NEW_USER": "alex", "SSH_PORT": str(NEW), "SSH_PUBKEY": pub,
        "EXTRA_PORTS": "80,443", "ADMIN_IP": GATEWAY,
        "AUTO_REBOOT": "no", "LOCK_ROOT": "yes", "LOCK_OTHER_USERS": "yes",
        "INSTALL_CROWDSEC": CROWDSEC, "RUN_LYNIS": "no", "TELEGRAM": "no",
        "DISABLE_PING": "yes", "REBOOT_NOW": "no",
    }
    if not tmux:
        env["HARDEN_NO_TMUX"] = "1"
    env.update(more)
    return " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())


def drive(port, user, command, password, stage, finish=r"Done!", login_check=True, term="xterm-256color"):
    """Runs a command on a terminal and answers what a person would be asked."""
    say(f"{stage}: {user}@{port}")
    # A real terminal type and a wide window: the first setup moves itself into tmux where
    # the image has it, and tmux draws for the terminal it is told about.
    child = pexpect.spawn("ssh", [*SSH, "-tt", "-p", str(port), f"{user}@127.0.0.1", command],
                          encoding="utf-8", codec_errors="replace", timeout=1800,
                          env={**os.environ, "TERM": term}, dimensions=(50, 220))
    child.logfile_read = sys.stdout
    patterns = [
        r"(Start|Undo the setup)\? \[y/n",        # 0
        r"New password:",                         # 1
        r"Retype new password:",                  # 2
        r"Does key login on port \d+ work\?",     # 3
        finish,                                   # 4
        r"Error at line|rolled back|\[✗\]",       # 5
        r"\[sudo[^\]\n]*\][^\n]*:",               # 6  sudo and sudo-rs both start with "[sudo"
        pexpect.EOF,                              # 7
        pexpect.TIMEOUT,                          # 8
        r"Press Enter to close tmux",             # 9
    ]
    done = False
    confirmed = not login_check
    in_tmux = False
    while True:
        i = child.expect(patterns)
        if i == 0:
            child.sendline("y")
        elif i in (1, 2, 6):
            child.sendline(password)
        elif i == 3:
            # What the script asks a person to do: try the new port from outside, and only
            # then say yes. The old way in has to be open still.
            r = ssh(NEW, "alex", "id -un", check=False)
            if r.stdout.strip() != "alex":
                print(r.stdout, r.stderr)
                fail("the login on the new port does not work at the moment the script asks about it")
            if stage == "first setup":
                if not banner(OLD).startswith(b"SSH-"):
                    fail("the old port was closed before the new one was confirmed")
                # Until the answer is given the old port lets the admin in the old way, and
                # the new port already refuses what it will refuse afterwards.
                if ssh(OLD, "root", "true", check=False).returncode != 0:
                    fail("the old way in (root, on the old port) stopped working before the new one was confirmed")
                if ssh(NEW, "root", "true", check=False).returncode == 0:
                    fail("root can log in on the new port while the question is being asked")
                if ssh(NEW, "provider", "true", check=False).returncode == 0:
                    fail("an account other than the new user can log in on the new port")
            confirmed = True
            child.sendline("y")
        elif i == 4:
            done = True
        elif i == 5:
            child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=30)
            fail(f"{stage} reported an error")
        elif i == 7:
            break
        elif i == 9:
            in_tmux = True
            child.sendline("")
        else:
            fail(f"{stage}: no progress for 30 minutes — an unexpected question?")
    child.close()
    if not (done and confirmed):
        fail(f"{stage} ended without finishing (done={done}, login confirmed={confirmed})")
    return in_tmux


def sudo(password, command):
    return f"printf '%s\\n' {shlex.quote(password)} | sudo -S {command} 2>/dev/null"


def verify(password, when):
    say(f"checking the result — {when}")
    if banner(OLD).startswith(b"SSH-"):
        fail("an SSH server still answers on the old port")
    if ssh(NEW, "alex", "id -un").stdout.strip() != "alex":
        fail("alex cannot log in on the new port")
    if ssh(NEW, "root", "true", check=False).returncode == 0:
        fail("root can log in over SSH")
    if ssh(NEW, "provider", "true", check=False).returncode == 0:
        fail("the provider's account can still log in")
    r = ssh(NEW, "alex", "true", check=False,
            extra=("-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"))
    if r.returncode == 0 or "publickey" not in r.stderr:
        print(r.stderr)
        fail("the server offers something other than public keys")

    # systemd has to be answering: a frozen PID 1 is the failure CI once produced here
    if ssh(NEW, "alex", sudo(password, "systemctl is-active ssh")).stdout.strip() != "active":
        fail("ssh.service is not active")
    r = ssh(NEW, "alex", sudo(password, "ss -Hltnp") + " | grep sshd | grep -v 127.0.0.1 | grep -v '\\[::1\\]'")
    print(r.stdout)
    if f":{NEW} " not in r.stdout or ":22 " in r.stdout:
        fail("sshd is not listening on the new port only")
    pids = {line.split("pid=")[1].split(",")[0] for line in r.stdout.splitlines() if "pid=" in line}
    if len(pids) != 1:
        fail(f"more than one sshd daemon is listening: {pids}")

    fw = ssh(NEW, "alex", sudo(password, "ufw status")).stdout
    print(fw)
    if "Status: active" not in fw or f"{NEW}/tcp" not in fw or "LIMIT" not in fw:
        fail("the firewall is not what the setup should have left")
    if any(line.split()[:1] in (["22"], ["22/tcp"]) for line in fw.splitlines()):
        fail("the old port is still open in the firewall")

    r = ssh(NEW, "alex", sudo(password, "harden --check"), check=False, timeout=300)
    print(r.stdout)
    if "Summary:" not in r.stdout:
        fail("--check did not reach its summary (or asked for the language)")
    if r.returncode != 0:
        fail("--check reports a failure (a line marked ✗) on a server this script has just set up")
    for must in ("root password locked", "Kernel settings (sysctl)", "Ping: not answered",
                 "PasswordAuthentication no", "fail2ban protects SSH"):
        if must not in r.stdout:
            fail(f"--check does not say: {must}")
    if "Differ from recommended" in r.stdout:
        fail("a kernel setting the setup wrote is not in effect")


def answers_and_refresh(password, pub):
    say("--answers and --refresh")
    r = ssh(NEW, "alex", sudo(password, "harden --answers"))
    print(r.stdout)
    for must in ("NEW_USER='alex'", f"SSH_PORT='{NEW}'", f"SSH_PUBKEY='{pub}'", "bash harden.sh"):
        if must not in r.stdout:
            fail(f"--answers does not give back: {must}")
    # A server set up by a version that did not save its answers yet: --refresh has to
    # read them back from what the setup left behind, and save them.
    ssh(NEW, "alex", sudo(password, "rm /etc/harden/setup.conf"))
    r = ssh(NEW, "alex", sudo(password, "harden --refresh"), check=False, timeout=900)
    print(r.stdout)
    if r.returncode != 0 or "Settings refreshed" not in r.stdout:
        fail("--refresh did not finish")
    r = ssh(NEW, "alex", sudo(password, "harden --answers"))
    print(r.stdout)
    for must in ("NEW_USER='alex'", f"SSH_PORT='{NEW}'", f"SSH_PUBKEY='{pub}'",
                 f"ADMIN_IP='{GATEWAY}'", "DISABLE_PING='yes'", "LOCK_ROOT='yes'"):
        if must not in r.stdout:
            fail(f"the answers read back from the server do not include: {must}")

    # What was switched by hand after the setup has to survive a refresh: ping turned back
    # on with --ping, and the login hook removed the way its own first line says. Going by
    # the answers of the setup, a refresh used to undo both.
    ssh(NEW, "alex", sudo(password, "harden --ping on"))
    ssh(NEW, "alex", sudo(password, "rm /etc/profile.d/99-server-status.sh"))
    r = ssh(NEW, "alex", sudo(password, "harden --refresh"), check=False, timeout=900)
    if r.returncode != 0 or "Settings refreshed" not in r.stdout:
        print(r.stdout)
        fail("the second --refresh did not finish")
    r = ssh(NEW, "alex", sudo(password, "harden --answers") + "; echo ping=$(sysctl -n net.ipv4.icmp_echo_ignore_all); "
                         "ls /usr/local/bin/server-status /etc/profile.d/99-server-status.sh 2>&1", check=False)
    print(r.stdout)
    if "DISABLE_PING='no'" not in r.stdout or "ping=0" not in r.stdout:
        fail("--refresh stopped answering ping again after `harden --ping on`")
    if "No such file or directory" not in r.stdout:     # of the two, only the hook may be missing
        fail("--refresh brought back the login hook that had been removed")
    if "/usr/local/bin/server-status\n" not in r.stdout:
        fail("--refresh did not keep the server-status command")
    ssh(NEW, "alex", sudo(password, "harden --ping off"))
    r = ssh(NEW, "alex", sudo(password, "harden --answers"))
    if "DISABLE_PING='yes'" not in r.stdout:
        print(r.stdout)
        fail("--ping off is not recorded with the saved answers")


def verify_undone(units_before):
    say("checking that the setup is undone")
    if not banner(OLD).startswith(b"SSH-"):
        fail("after --undo nothing answers on the old port")
    if banner(NEW).startswith(b"SSH-"):
        fail("after --undo sshd still listens on the new port")
    r = ssh(OLD, "root", "id -un", check=False)
    if r.stdout.strip() != "root":
        print("root:", r.returncode, r.stderr)
        d = ssh(OLD, "provider", "sudo -n journalctl -u ssh -n 25 --no-pager -o cat; sudo -n passwd -S root; "
                                 "sudo -n ls -la /root/.ssh; sudo -n sshd -T | grep -i -E 'permitroot|allowusers'",
                check=False)
        print(d.stdout, d.stderr)
        fail("after --undo root cannot log in with its key, as it could before the setup")
    if ssh(OLD, "provider", "sudo -n id -un").stdout.strip() != "root":
        fail("after --undo the provider's account does not have its sudo back")
    r = ssh(OLD, "root", "systemctl is-active ssh; ufw status | head -1; "
                         "ls /etc/ssh/sshd_config.d/00-hardening.conf /etc/sysctl.d/99-hardening.conf "
                         "/etc/harden /etc/fail2ban/jail.d/99-hardening.local /usr/local/bin/server-status 2>&1",
            check=False)   # ls is meant to find nothing, and says so with its exit status
    print(r.stdout)
    if "active" not in r.stdout.splitlines()[:1][0] or "Status: inactive" not in r.stdout:
        fail("after --undo: sshd is not running, or the firewall is still on")
    if r.stdout.count("No such file or directory") != 5:
        fail("after --undo some of the files the setup added are still there")
    units_after = ssh(OLD, "root", UNITS_PROBE, check=False).stdout
    print(units_after)
    if units_after != units_before:
        fail("after --undo a service the setup switched off is not back the way it was")


def main():
    pub = boot()
    password = "E2e-" + secrets.token_urlsafe(9) + "-7q"
    run("scp", *SSH, "-P", str(OLD), str(ROOT / "harden.sh"), "root@127.0.0.1:/root/harden.sh")

    # The first setup runs the way a person starts it: no HARDEN_NO_TMUX, so where the image
    # has tmux the script moves itself into it. The later runs stay outside, to keep both
    # ways covered.
    units_before = ssh(OLD, "root", UNITS_PROBE, check=False).stdout
    print(units_before)
    has_tmux = ssh(OLD, "root", "command -v tmux", check=False).returncode == 0
    print(f"tmux in the image: {has_tmux}")
    # ...and from a terminal type the image has no description of, as kitty or ghostty are
    # on a fresh server: tmux refuses to start on one, and the setup used to end right there.
    in_tmux = drive(OLD, "root", f"{answers(pub, tmux=True)} bash /root/harden.sh", password, "first setup",
                    term="xterm-nosuchterm")
    if has_tmux and not in_tmux:
        fail("the image has tmux, but the setup did not move itself into it")
    verify(password, "after the setup")
    answers_and_refresh(password, pub)
    verify(password, "after --refresh")

    say("reboot")
    ssh(NEW, "alex", sudo(password, "systemctl reboot"), check=False)
    time.sleep(20)
    wait_for_login(NEW, "alex", 420)
    verify(password, "after the reboot")

    # The setup once more, through the copy it installed: the way a server gets a newer
    # version, and a path that used to end in an error just before the final report.
    drive(NEW, "alex", f"sudo env {answers(pub, REUSE_USER='yes')} harden", password, "second setup")
    verify(password, "after the second setup")

    # What the machine looks like afterwards is printed from the same session: if the undo
    # leaves no way in, this is the only place it can be seen from.
    drive(NEW, "alex", "sudo harden --undo; echo '--- after the undo'; sudo -n ufw status 2>&1 | head -3; "
                       "sudo -n ss -Hltnp 2>&1 | grep sshd | grep -v 127.0.0.1 | grep -v '::1'; "
                       "sudo -n systemctl is-active fail2ban; sudo -n passwd -S root; sudo -n ls -la /root/.ssh; "
                       "sudo -n iptables -S 2>&1 | grep -ciE 'f2b|reject|drop'; sudo -n nft list ruleset 2>&1 | grep -ci f2b",
          password, "undo", finish=r"The setup is undone", login_check=False)
    verify_undone(units_before)

    say(f"OK: {NAME}")


if __name__ == "__main__":
    try:
        main()
    finally:
        subprocess.run(["sudo", "pkill", "-F", str(WORK / "qemu.pid")], check=False)
