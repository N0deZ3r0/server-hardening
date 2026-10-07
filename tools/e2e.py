#!/usr/bin/env python3
"""End-to-end test: the whole setup on a real virtual machine.

Run by CI (.github/workflows/ci.yml), once per supported release:

    python3 -u tools/e2e.py <cloud-image.qcow2> <name>

The pieces of harden.sh are tested one by one elsewhere. This runs all of it, the way a
person would on a fresh VPS: a cloud image boots under QEMU/KVM with cloud-init, root logs
in with a key, the script asks every one of its questions on a real terminal and gets
them answered one by one — nothing is preset — a password is typed for the new user, the
login on the new port is tried from outside before it is confirmed.
Then the result is checked from outside and from inside, and the server is taken through
what happens to it afterwards:

  - --answers and --refresh, also after settings were switched by hand;
  - Telegram alerts, sent to a stand-in for the Bot API that runs here: a real login, the
    daily report, the message after a boot;
  - a reboot;
  - the setup a second time, through the installed `sudo harden`, keeping the saved bot;
  - the setup a third time with another SSH port and a network as the admin's address —
    the old port has to keep the rules of the earlier setup until the new one is confirmed;
  - --undo, after which the system files have to be byte for byte what they were.

It exists because a part that passed every piece-by-piece test still failed as a whole:
versions 2026.10.8 to 2026.10.17 could not finish on an Ubuntu 24.04 cloud image, and
that was found only when someone ran one by hand. Its own first run found two more: the
setup stopped on Debian 12 and on Ubuntu 26.04.
"""
import hashlib
import http.server
import json
import os
import pathlib
import re
import secrets
import shlex
import socket
import subprocess
import sys
import threading
import time
import urllib.parse

import pexpect

IMAGE = pathlib.Path(sys.argv[1]).resolve()
NAME = sys.argv[2]
CROWDSEC = sys.argv[3] if len(sys.argv) > 3 else "yes"
ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK = pathlib.Path("e2e-work").resolve()
KEY = WORK / "key"
OLD = 2222          # host port forwarded to the guest's port 22
NEW = 2233          # the new SSH port, the same number on host and guest
THIRD = 2244        # the port of the last setup: the same server, set up again on another port
GATEWAY = "10.0.2.2"  # how the guest sees this host under QEMU user networking
NETWORK = "10.0.2.0/24"

# A stand-in for the Telegram Bot API, on this host. The token has the shape of a real one
# and belongs to no bot.
API_PORT = 8099
API = f"http://{GATEWAY}:{API_PORT}"
TG_TOKEN = "12345678:" + "e2e-" * 9
TG_CHAT = "4242"

# The units the setup switches off where they are on, and how each one stands: --undo has
# to leave them the way they were found.
UNITS_PROBE = ("for u in apport.service apport-autoreport.path apport-autoreport.timer apport-forward.socket "
               "ModemManager.service udisks2.service; do "
               "echo \"$u: $(systemctl is-enabled $u 2>/dev/null)\"; done")

# The files the setup replaces or edits, and the modes it changes. After --undo each one
# that was there before has to be what it was.
FILES_PROBE = ("md5sum /etc/motd /etc/issue /etc/issue.net /etc/login.defs /etc/hosts /etc/ssh/sshd_config "
               "/etc/default/motd-news /etc/default/apport /etc/apt/apt.conf.d/20auto-upgrades "
               "/etc/ufw/ufw.conf /etc/ufw/sysctl.conf /etc/sudoers.d/90-cloud-init-users 2>/dev/null; "
               "stat -c '%a %n' /etc/crontab /etc/cron.d /etc/ssh/sshd_config 2>/dev/null")

SSH = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
       "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "-o", "IdentitiesOnly=yes",
       "-i", str(KEY)]


def say(msg):
    print(f"\n=== {msg}", flush=True)


PASSWORD = ""       # of the user the setup creates; set once it is chosen

# What the machine looks like at the moment something went wrong: who listens where, what
# the firewall and fail2ban hold, what sshd and the kernel logged last.
STATE = ("echo '--- sshd listeners'; ss -Hltnp | grep -E 'sshd|systemd' ; "
         "echo '--- units'; systemctl is-active ssh ssh.socket fail2ban crowdsec; systemctl show -p MainPID -p NRestarts ssh; "
         "echo '--- firewall'; ufw status numbered; "
         "echo '--- fail2ban'; fail2ban-client status sshd; tail -n 15 /var/log/fail2ban.log; "
         "echo '--- crowdsec'; cscli decisions list 2>&1 | tail -n 8; "
         "echo '--- sshd, last lines'; journalctl -u ssh -n 30 --no-pager -o short-precise; "
         "echo '--- kernel, firewall lines'; journalctl -k --since -5min --no-pager -o short-precise | grep -i ufw | tail -n 15; "
         "echo '--- setup log'; tail -n 40 /var/log/harden.log")


def fail(msg):
    print(f"\nE2E FAILED ({NAME}): {msg}", flush=True)
    for port, user in ((THIRD, "alex"), (NEW, "alex"), (OLD, "root")):
        if user == "root":
            command = f"sh -c {shlex.quote(STATE)} 2>&1"
        else:
            command = f"printf '%s\\n' {shlex.quote(PASSWORD)} | sudo -S sh -c {shlex.quote(STATE)} 2>&1"
        r = ssh(port, user, command, check=False, timeout=60)
        if "--- firewall" in r.stdout:
            print(f"--- the machine, seen through {user}@{port}\n{r.stdout}", flush=True)
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


class BotAPI(http.server.BaseHTTPRequestHandler):
    """Answers the three calls the script and its helpers make, and keeps what was sent."""
    messages = []

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        method = self.path.rsplit("/", 1)[-1].split("?")[0]
        result = {}
        if method == "getMe":
            result = {"username": "e2e_bot"}
        elif method == "getUpdates":
            result = [{"message": {"chat": {"id": int(TG_CHAT)}}}]
        elif method == "sendMessage":
            text = urllib.parse.parse_qs(body).get("text", [""])[0]
            BotAPI.messages.append(text)
            print(f"[bot api] {text!r}"[:400], flush=True)
        # compact, the way Telegram answers: the script looks for "ok":true
        payload = json.dumps({"ok": True, "result": result}, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = _answer

    def log_message(self, *args):
        pass


def wait_message(text, since, seconds, what):
    """A message containing `text` among those received after the first `since`."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        for m in BotAPI.messages[since:]:
            if text in m:
                return m
        time.sleep(1)
    fail(f"Telegram: {what} — no message containing {text!r} within {seconds} s")


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
    forward = ",".join(f"hostfwd=tcp:127.0.0.1:{h}-:{g}" for h, g in ((OLD, 22), (NEW, NEW), (THIRD, THIRD)))
    run("sudo", "qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "2048", "-smp", "2",
        "-display", "none", "-serial", f"file:{WORK / 'serial.log'}",
        "-drive", f"file={WORK / 'disk.qcow2'},if=virtio",
        "-drive", f"file={WORK / 'seed.iso'},if=virtio,format=raw",
        "-netdev", f"user,id=n0,{forward}",
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


def interview(pub):
    """The questions of a setup with nothing preset, and what a person answers: in the
    order they are asked, each as (what the question looks like, the answer)."""
    yn = r"[^\n]*\[y/n"
    return [
        (r"Language / Язык:[^\n]*\]: ", "1"),
        (r"Name of the new sudo user \[sysop\]: ", "alex"),
        (r"Choice \[1\]: ", "1"),
        (r"Paste the public key \(ssh-ed25519 AAAA\.\.\.\): ", pub),
        (r"New SSH port \[\d+\]: ", str(NEW)),
        (r"Other ports to open in the firewall[^\n]*: ", "80,443"),
        # the address is the one the script has to find by itself, from the SSH session
        (r"Your IP is " + re.escape(GATEWAY) + r" — whitelist it" + yn, "y"),
        (r"Allow a nightly automatic reboot" + yn, "n"),
        (r"Lock the root password" + yn, "y"),
        (r"Lock them AFTER" + yn, "y"),
        (r"Install CrowdSec" + yn, "y" if CROWDSEC == "yes" else "n"),
        (r"Run a Lynis audit at the end\?" + yn, "y"),
        (r"Telegram alerts \(SSH logins" + yn, "n"),
        (r"Stop answering ping\?" + yn, "y"),
        (r"Reboot now\?" + yn, "n"),
    ]


def drive(port, user, command, password, stage, finish=r"Done!", login_check=True, term="xterm-256color",
          at_question=None, close_tmux=True, typeahead=False, questions=()):
    """Runs a command on a terminal and answers what a person would be asked.

    Each question is answered once. tmux repaints the screen now and then, the question
    appears in the output a second time, and a second "y" sent for it sat in the terminal
    until the next question — "does the login on the new port work?" — took it for its
    answer. That was this test's mistake, and it is how the script's own was found: it
    should never have taken it. `typeahead` now makes that mistake on purpose."""
    say(f"{stage}: {user}@{port}")
    # A real terminal type and a wide window: the setup moves itself into tmux where the
    # image has it, and tmux draws for the terminal it is told about.
    child = pexpect.spawn("ssh", [*SSH, "-tt", "-p", str(port), f"{user}@127.0.0.1", command],
                          encoding="utf-8", codec_errors="replace", timeout=1800,
                          env={**os.environ, "TERM": term}, dimensions=(50, 220))
    child.logfile_read = sys.stdout
    patterns = [
        r"(Start|Undo the setup|arrive in Telegram|already saved)\? \[y/n",   # 0
        r"New password:",                         # 1
        r"Retype new password:",                  # 2
        r"Does key login on port \d+ work\?",     # 3
        finish,                                   # 4
        r"Error at line|rolled back|\[✗\]",       # 5
        r"\[sudo[^\]\n]*\][^\n]*:",               # 6  sudo and sudo-rs both start with "[sudo"
        pexpect.EOF,                              # 7
        pexpect.TIMEOUT,                          # 8
        r"Press Enter to close tmux",             # 9
    ] + [q for q, _ in questions]                 # 10 and on: the interview
    done = False
    confirmed = not login_check
    in_tmux = False
    answered = set()
    while True:
        i = child.expect(patterns)
        key = child.match.group(1) if i == 0 else i
        if (i in (0, 1, 2, 3, 6, 9) or i >= 10) and key in answered:
            continue        # the same question, painted again
        answered.add(key)
        if i >= 10:
            child.sendline(questions[i - 10][1])
        elif i == 0:
            child.sendline("y")
            if typeahead and key == "Start":
                # a key pressed once too often, minutes before the questions that matter
                child.sendline("y")
        elif i in (1, 2, 6):
            child.sendline(password)
        elif i == 3:
            # What the script asks a person to do: try the new port from outside, and only
            # then say yes.
            asked = int(re.search(r"port (\d+)", child.after).group(1))
            r = ssh(asked, "alex", "id -un", check=False)
            if r.stdout.strip() != "alex":
                print(r.stdout, r.stderr)
                fail("the login on the new port does not work at the moment the script asks about it")
            if at_question:
                at_question(password)
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
            if not close_tmux:
                break       # the window is left as a person leaves it: finished, and open
            child.sendline("")
        else:
            fail(f"{stage}: no progress for 30 minutes — an unexpected question?")
    child.close(force=True)
    if not (done and confirmed):
        fail(f"{stage} ended without finishing (done={done}, login confirmed={confirmed})")
    # every question of the interview has to have been asked, bar the one about a reboot,
    # which is asked only when one is due
    missed = [q for n, (q, _) in enumerate(questions) if n + 10 not in answered and "Reboot now" not in q]
    if missed:
        fail(f"{stage}: these questions were never asked: {missed}")
    return in_tmux


def sudo(password, command):
    return f"printf '%s\\n' {shlex.quote(password)} | sudo -S {command} 2>/dev/null"


def first_setup_question(password):
    """Until the answer is given the old port lets the admin in the old way, and the new
    port already refuses what it will refuse afterwards."""
    if not banner(OLD).startswith(b"SSH-"):
        fail("the old port was closed before the new one was confirmed")
    if ssh(OLD, "root", "true", check=False).returncode != 0:
        fail("the old way in (root, on the old port) stopped working before the new one was confirmed")
    if ssh(NEW, "root", "true", check=False).returncode == 0:
        fail("root can log in on the new port while the question is being asked")
    if ssh(NEW, "provider", "true", check=False).returncode == 0:
        fail("an account other than the new user can log in on the new port")


def port_change_question(password):
    """A server that is already set up: until the new port is confirmed the old one keeps
    the rules of the earlier setup — it must not fall back to what the image came with."""
    tries = []
    for _ in range(4):
        tries.append(banner(NEW)[:8])
        time.sleep(1.5)
    if not all(t.startswith(b"SSH-") for t in tries):
        fail(f"the old port does not answer while the new one waits to be confirmed (four tries, 1.5 s apart: {tries})")
    if ssh(NEW, "alex", "id -un", check=False).stdout.strip() != "alex":
        fail("the old way in (alex, on the old port) stopped working before the new one was confirmed")
    r = ssh(THIRD, "alex", sudo(password, f"sshd -T -C user=alex,host=localhost,addr=127.0.0.1,lport={NEW}"))
    for must in ("permitrootlogin no", "passwordauthentication no", "allowusers alex", "authenticationmethods publickey"):
        if must not in r.stdout:
            print(r.stdout)
            fail(f"until the new port is confirmed the old one has to keep the rules of the earlier setup; missing: {must}")
    r = ssh(NEW, "alex", "true", check=False,
            extra=("-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"))
    if r.returncode == 0 or "publickey" not in r.stderr or "password" in r.stderr:
        print(r.stderr)
        fail("the old port offers something other than public keys while the question is being asked")


def verify(password, when, port=NEW, admin=GATEWAY):
    say(f"checking the result — {when}")
    closed = [p for p in (OLD, NEW, THIRD) if p != port]
    for p in closed:
        if banner(p).startswith(b"SSH-"):
            fail(f"an SSH server still answers on a port that should be closed (host port {p})")
    if ssh(port, "alex", "id -un").stdout.strip() != "alex":
        fail("alex cannot log in on the new port")
    if ssh(port, "root", "true", check=False).returncode == 0:
        fail("root can log in over SSH")
    if ssh(port, "provider", "true", check=False).returncode == 0:
        fail("the provider's account can still log in")
    r = ssh(port, "alex", "true", check=False,
            extra=("-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"))
    if r.returncode == 0 or "publickey" not in r.stderr:
        print(r.stderr)
        fail("the server offers something other than public keys")

    # systemd has to be answering: a frozen PID 1 is the failure CI once produced here
    if ssh(port, "alex", sudo(password, "systemctl is-active ssh")).stdout.strip() != "active":
        fail("ssh.service is not active")
    r = ssh(port, "alex", sudo(password, "ss -Hltnp") + " | grep sshd | grep -v 127.0.0.1 | grep -v '\\[::1\\]'")
    print(r.stdout)
    gone = [22] + [p for p in (NEW, THIRD) if p != port]
    if f":{port} " not in r.stdout or any(f":{p} " in r.stdout for p in gone):
        fail("sshd is not listening on the new port only")
    pids = {line.split("pid=")[1].split(",")[0] for line in r.stdout.splitlines() if "pid=" in line}
    if len(pids) != 1:
        fail(f"more than one sshd daemon is listening: {pids}")

    fw = ssh(port, "alex", sudo(password, "ufw status")).stdout
    print(fw)
    if "Status: active" not in fw or f"{port}/tcp" not in fw or "LIMIT" not in fw:
        fail("the firewall is not what the setup should have left")
    for line in fw.splitlines():
        first = (line.split() or [""])[0]
        if first.split("/")[0] in [str(p) for p in gone]:
            fail(f"a rule for an old SSH port is still in the firewall: {line.strip()}")
    # the admin's exception: one rule, for the address of the latest run
    rules = [line for line in fw.splitlines() if "ALLOW" in line and line.split()[:1] == [f"{port}/tcp"]]
    if len(rules) != 1 or admin not in rules[0]:
        fail(f"the firewall exception for the admin's address is not the one rule for {admin}: {rules}")

    r = ssh(port, "alex", sudo(password, "harden --check"), check=False, timeout=300)
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
    # the answers of the setup, a refresh used to undo both. The saved answers are cut down
    # to two lines as well: a file edited by hand must not stop the refresh half-way.
    ssh(NEW, "alex", sudo(password, "harden --ping on"))
    ssh(NEW, "alex", sudo(password, "rm /etc/profile.d/99-server-status.sh"))
    ssh(NEW, "alex", sudo(password, "sed -i -n '/^NEW_USER=/p; /^LOCK_ROOT=/p' /etc/harden/setup.conf"))
    r = ssh(NEW, "alex", sudo(password, "harden --refresh"), check=False, timeout=900)
    if r.returncode != 0 or "Settings refreshed" not in r.stdout:
        print(r.stdout, r.stderr)
        fail("the second --refresh did not finish")
    r = ssh(NEW, "alex", sudo(password, "harden --answers") + "; echo ping=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all); "
                         "ls /usr/local/bin/server-status /etc/profile.d/99-server-status.sh 2>&1", check=False)
    print(r.stdout)
    if "DISABLE_PING='no'" not in r.stdout or "ping=0" not in r.stdout:
        fail("--refresh stopped answering ping again after `harden --ping on`")
    if "No such file or directory" not in r.stdout:     # of the two, only the hook may be missing
        fail("--refresh brought back the login hook that had been removed")
    if "/usr/local/bin/server-status\n" not in r.stdout:
        fail("--refresh did not keep the server-status command")
    for must in (f"SSH_PORT='{NEW}'", f"ADMIN_IP='{GATEWAY}'", "LOCK_ROOT='yes'"):
        if must not in r.stdout:
            fail(f"after a refresh from a cut-down answers file, the answers lack: {must}")
    ssh(NEW, "alex", sudo(password, "harden --ping off"))
    r = ssh(NEW, "alex", sudo(password, "harden --answers"))
    if "DISABLE_PING='yes'" not in r.stdout:
        print(r.stdout)
        fail("--ping off is not recorded with the saved answers")


def report_time(password, port=NEW):
    return ssh(port, "alex", sudo(password, "grep OnCalendar /etc/systemd/system/harden-daily-report.timer"),
               check=False).stdout.strip()


def telegram(password):
    """Alerts, with the Bot API played by this host: what the helpers really send for a
    real login, in the log format of each release's own sshd."""
    say("Telegram alerts")
    n = len(BotAPI.messages)
    drive(NEW, "alex",
          f"sudo env HARDEN_LANG=en HARDEN_TG_API={API} TG_TOKEN={TG_TOKEN} TG_CHAT_ID={TG_CHAT} TG_REPORT_TIME=20:15 "
          "harden --setup-telegram",
          password, "--setup-telegram", finish=r"Telegram: SSH logins, failed services", login_check=False)
    wait_message("test message from harden.sh", n, 30, "the test message")
    if "20:15" not in wait_message("Alerts on", n, 30, "the message that alerts are on"):
        fail("Telegram: the message that alerts are on does not name the chosen report time")

    n = len(BotAPI.messages)
    ssh(NEW, "alex", "true")
    m = wait_message("SSH login: alex from " + GATEWAY, n, 40, "a login was not reported")
    if "publickey" not in m:
        fail(f"Telegram: the login alert does not say how the login was made: {m!r}")

    # --refresh rewrites the helpers: the bot, the address of the API and the hour of the
    # report have to be what they were
    n = len(BotAPI.messages)
    r = ssh(NEW, "alex", sudo(password, "harden --refresh"), check=False, timeout=900)
    if r.returncode != 0 or "Settings refreshed" not in r.stdout:
        print(r.stdout, r.stderr)
        fail("--refresh with Telegram set up did not finish")
    if "20:15" not in report_time(password):
        fail("--refresh moved the daily report away from the hour it was set to")
    wait_message("Alerts on", n, 30, "after --refresh the helpers do not reach the API they were set up with")
    n = len(BotAPI.messages)
    ssh(NEW, "alex", "true")
    wait_message("SSH login: alex from " + GATEWAY, n, 40, "after --refresh a login was not reported")

    n = len(BotAPI.messages)
    ssh(NEW, "alex", sudo(password, "systemctl start harden-daily-report.service"), timeout=600)
    m = wait_message("Daily report", n, 60, "the daily report")
    for must in ("SSH logins (24 h):", "alex@" + GATEWAY, "fail2ban:", "Check: ", "✗ 0"):
        if must not in m:
            fail(f"Telegram: the daily report lacks {must!r}: {m!r}")


def third_setup_checks(password):
    say("checking what the setup with another port and a network left")
    r = ssh(THIRD, "alex", sudo(password, "fail2ban-client get sshd ignoreip"))
    print(r.stdout)
    if NETWORK not in r.stdout or GATEWAY + "\n" in r.stdout:
        fail("fail2ban's whitelist is not the network given at the latest run")
    r = ssh(THIRD, "alex", sudo(password, "grep -E 'port|ignoreip' /etc/fail2ban/jail.d/99-hardening.local"))
    if f"port      = {THIRD}" not in r.stdout:
        print(r.stdout)
        fail("fail2ban still watches the old SSH port")
    if CROWDSEC == "yes":
        r = ssh(THIRD, "alex", sudo(password, "cat /etc/crowdsec/parsers/s02-enrich/99-harden-admin-whitelist.yaml"))
        print(r.stdout)
        if "cidr:" not in r.stdout or f'"{NETWORK}"' not in r.stdout:
            fail("CrowdSec: a network as the admin's address is not written as a network")
        # it was restarted with the new whitelist a minute ago, and takes a while to come up
        deadline = time.time() + 120
        while ssh(THIRD, "alex", "systemctl is-active crowdsec", check=False).stdout.strip() != "active":
            if time.time() > deadline:
                fail("CrowdSec does not run with a network in its whitelist")
            time.sleep(5)


def verify_undone(units_before, files_before):
    say("checking that the setup is undone")
    if not banner(OLD).startswith(b"SSH-"):
        fail("after --undo nothing answers on the old port")
    for p in (NEW, THIRD):
        if banner(p).startswith(b"SSH-"):
            fail("after --undo sshd still listens on a port the setup had moved it to")
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
                         "/etc/harden /etc/fail2ban/jail.d/99-hardening.local /usr/local/bin/server-status "
                         "/usr/local/sbin/harden-notify /etc/systemd/system/harden-login-watch.service 2>&1; "
                         "echo watch=$(systemctl is-active harden-login-watch.service)",
            check=False)   # ls is meant to find nothing, and says so with its exit status
    print(r.stdout)
    if "active" not in r.stdout.splitlines()[:1][0] or "Status: inactive" not in r.stdout:
        fail("after --undo: sshd is not running, or the firewall is still on")
    if r.stdout.count("No such file or directory") != 7:
        fail("after --undo some of the files the setup added are still there")
    if "watch=active" in r.stdout:
        fail("after --undo the Telegram login watcher is still running")
    units_after = ssh(OLD, "root", UNITS_PROBE, check=False).stdout
    print(units_after)
    if units_after != units_before:
        fail("after --undo a service the setup switched off is not back the way it was")
    files_after = ssh(OLD, "root", FILES_PROBE, check=False).stdout
    print(files_after)
    changed = [line for line in files_before.splitlines() if line not in files_after.splitlines()]
    if changed:
        fail(f"after --undo these files are not what they were before the setup: {changed}")


def get_the_script():
    """Puts harden.sh on the fresh machine the way a reader of the README gets it: with the
    install command printed there, as it stands — the download of the release and the
    check of its SHA-256. What it needs has to be on the image as it comes.

    The file fetched that way is the one the first setup runs whenever it is the file of
    this checkout, byte for byte: then the published release itself is what is tested.
    On a commit that changes the script, or before its release exists, the checkout's copy
    is put in its place."""
    say("getting the script the way the README says")
    lines = [line.strip() for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
             if line.startswith("curl -fsSLo harden.sh ") and line.rstrip().endswith("&& sudo bash harden.sh")]
    if not lines:
        fail("README.md has no install command of the shape this test knows")
    fetch = lines[0].rsplit(" && sudo bash harden.sh", 1)[0]
    r = ssh(OLD, "root", "for t in curl sha256sum sudo bash; do command -v $t >/dev/null || echo $t; done", check=False)
    if r.stdout.split():
        fail(f"the README's install command needs these, and the fresh image does not have them: {r.stdout.split()}")
    r = ssh(OLD, "root", f"cd /root && rm -f harden.sh && {fetch} && sha256sum harden.sh", check=False, timeout=180)
    print(r.stdout, r.stderr)
    ours = hashlib.sha256((ROOT / "harden.sh").read_bytes()).hexdigest()
    if r.returncode == 0 and ours in r.stdout:
        print("the first setup runs the published release, fetched and verified by the README's own command")
        return
    print("the checkout's harden.sh is not a published release (or not yet): using the checkout's copy")
    run("scp", *SSH, "-P", str(OLD), str(ROOT / "harden.sh"), "root@127.0.0.1:/root/harden.sh")


def main():
    global PASSWORD
    pub = boot()
    password = PASSWORD = "E2e-" + secrets.token_urlsafe(9) + "-7q"
    get_the_script()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", API_PORT), BotAPI)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    units_before = ssh(OLD, "root", UNITS_PROBE, check=False).stdout
    files_before = ssh(OLD, "root", FILES_PROBE, check=False).stdout
    print(units_before, files_before, sep="\n")
    has_tmux = ssh(OLD, "root", "command -v tmux", check=False).returncode == 0
    print(f"tmux in the image: {has_tmux}")

    # The first setup runs the way a person starts it: no HARDEN_NO_TMUX, so where the image
    # has tmux the script moves itself into it — and from a terminal type the image has no
    # description of, as kitty or ghostty are on a fresh server: tmux refuses to start on
    # one, and the setup used to end right there.
    # And with a "y" typed ahead, right after "Start?": it must not become the answer to
    # the question about the login — the checks made at that question would find the old
    # port closed.
    # Nothing is preset: every question is asked and answered, the key is pasted, the
    # admin's address is the one the script finds for itself, and Lynis runs at the end.
    # It is started with the last words of the README's command, sudo included: under sudo
    # the address of the SSH client is not in the environment, and has to be found another way.
    in_tmux = drive(OLD, "root", "cd /root && sudo bash harden.sh", password, "first setup",
                    term="xterm-nosuchterm", at_question=first_setup_question, typeahead=True,
                    questions=interview(pub))
    if has_tmux and not in_tmux:
        fail("the image has tmux, but the setup did not move itself into it")
    verify(password, "after the setup")
    answers_and_refresh(password, pub)
    verify(password, "after --refresh")
    telegram(password)

    say("reboot")
    n = len(BotAPI.messages)
    ssh(NEW, "alex", sudo(password, "systemctl reboot"), check=False)
    time.sleep(20)
    wait_for_login(NEW, "alex", 420)
    verify(password, "after the reboot")
    wait_message("Server started", n, 120, "the message after a boot")

    # The setup once more, through the copy it installed: the way a server gets a newer
    # version, and a path that used to end in an error just before the final report. It
    # keeps the saved bot — and with it, the hour its report was set to. Its tmux window is
    # left open when it has finished, as a person leaves it.
    in_tmux = drive(NEW, "alex", f"sudo env {answers(pub, tmux=True, REUSE_USER='yes', TELEGRAM='yes')} harden",
                    password, "second setup", close_tmux=False)
    if has_tmux and not in_tmux:
        fail("the second setup did not move itself into tmux")
    verify(password, "after the second setup")
    if "20:15" not in report_time(password):
        fail("the setup run again with the saved bot moved the daily report away from the hour it was set to")
    n = len(BotAPI.messages)
    ssh(NEW, "alex", "true")
    wait_message("SSH login: alex from " + GATEWAY, n, 40, "after the second setup a login was not reported")

    # ...and a third time, on another port, with a network as the admin's address. The
    # finished run still sitting in tmux must not be what this one attaches to: if it were,
    # nothing below would have changed.
    in_tmux = drive(NEW, "alex",
                    f"sudo env {answers(pub, tmux=True, REUSE_USER='yes', SSH_PORT=str(THIRD), ADMIN_IP=NETWORK)} harden",
                    password, "third setup: another port", at_question=port_change_question)
    if has_tmux and not in_tmux:
        fail("the third setup did not move itself into tmux")
    verify(password, "after the setup with another port", port=THIRD, admin=NETWORK)
    third_setup_checks(password)

    # A backup taken on a server that was hardened by then is not what --undo may restore
    # from, even when it is the oldest one there.
    ssh(THIRD, "alex", sudo(password, "mkdir /root/harden-backup-20000101-000000")
        + " && " + sudo(password, "cp -a /etc/ssh /root/harden-backup-20000101-000000/ssh"))

    # What the machine looks like afterwards is printed from the same session: if the undo
    # leaves no way in, this is the only place it can be seen from.
    drive(THIRD, "alex", "sudo harden --undo; echo '--- after the undo'; sudo -n ufw status 2>&1 | head -3; "
                         "sudo -n ss -Hltnp 2>&1 | grep sshd | grep -v 127.0.0.1 | grep -v '::1'; "
                         "sudo -n systemctl is-active fail2ban; sudo -n passwd -S root; sudo -n ls -la /root/.ssh; "
                         "sudo -n iptables -S 2>&1 | grep -ciE 'f2b|reject|drop'; sudo -n nft list ruleset 2>&1 | grep -ci f2b",
          password, "undo", finish=r"The setup is undone", login_check=False)
    verify_undone(units_before, files_before)

    say(f"OK: {NAME}")


if __name__ == "__main__":
    try:
        main()
    finally:
        subprocess.run(["sudo", "pkill", "-F", str(WORK / "qemu.pid")], check=False)
