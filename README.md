<div align="center">

# Server Hardening

**One command turns a fresh Debian or Ubuntu VPS into a server that only lets in your key — and it will not close the old door until you have walked through the new one.**

[![CI](https://github.com/N0deZ3r0/server-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/N0deZ3r0/server-hardening/actions/workflows/ci.yml)
![version](https://img.shields.io/badge/version-2026.10.22-3b5bdb)
![Debian](https://img.shields.io/badge/Debian-12%20%2F%2013-a80030)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20%2F%2024.04%20%2F%2026.04-e95420)
![bash](https://img.shields.io/badge/bash-single%20file-2f9e44)
![Lynis](https://img.shields.io/badge/Lynis-86%2F100-2f9e44)
![license](https://img.shields.io/badge/license-MIT-4c6ef5)

**English** · [Русский](README.ru.md)

</div>

A single bash script, run once as root on a new server. It asks a handful of questions,
creates a sudo user with your SSH key, moves SSH to a new port with key-only login and no
root, turns on a firewall, fail2ban and optionally CrowdSec, hardens the kernel, enables
security auto-updates and audit logging, replaces the login greeting with a short server
summary, can report to Telegram, and finishes with a Lynis audit. Later, `sudo harden --check`
audits the server without changing anything. The interface is in English and Russian.

```bash
curl -fsSLo harden.sh https://github.com/N0deZ3r0/server-hardening/releases/download/v2026.10.22/harden.sh && echo "6617af889051804999ed390626ebf0d35006e24942f3de6de3168733f0b113a1  harden.sh" | sha256sum -c - && sudo bash harden.sh
```

The command downloads a fixed release and checks its SHA-256 before running it: if a single
byte differs, `sha256sum` stops the chain and nothing is executed. See
[Releases and verification](#releases-and-verification) for what that does and does not prove.

## First, honestly, about what this protects

**What actually keeps people out is key-only login.** After the run the server does not
accept a password over SSH at all — not for root, not for anyone. Guessing is no longer a
strategy; an attacker needs your private key.

**The rest reduces noise and blast radius.** A new port cuts the log spam from bots that
only try 22, but anyone who scans finds it in seconds — it is not a lock. fail2ban and
CrowdSec ban the addresses that keep trying. Kernel settings, AppArmor and auditd make a
compromise harder to extend and easier to reconstruct. Auto-updates close known holes
without waiting for you.

**None of that helps** if the private key on your own computer is stolen, if you later
install a web application with a hole in it, or if the hosting provider itself is
compromised. Those are the realistic ways to lose a server, and this script cannot reach
any of them.

## It will not lock you out

Losing access to a remote server is the one mistake that cannot be fixed from the
outside, so most of the script is about not making it.

- **The old SSH port stays open until you prove the new one works.** The script starts
  SSH on both ports, prints the exact command, and waits while you log in from a *second*
  window. Only a "yes" closes the old port. A "no" puts SSH back exactly as it was.
- **Your own IP is whitelisted** in fail2ban, CrowdSec and the firewall rate limit —
  offered, not forced. Without it, a few quick test logins get the administrator banned
  (this happened during testing).
- **Pre-existing accounts** (`ubuntu`, `opc`, `admin` from the provider) are locked only
  *after* the new user's login is confirmed — on AWS or Oracle that is the account you
  are logged in with. If you keep them, the script says that SSH will accept only the new
  user and asks whether to let them in as well — it does not shut them out silently.
- **It runs inside tmux.** Fresh VPS images often restart SSH in the first minutes and
  drop the session; the setup keeps going, and `tmux attach -t harden` brings you back.
- **It waits for the provider.** Many images run a full upgrade from cloud-init after
  first boot — GRUB and kernel included — for 5–20 minutes. Rebooting in the middle of
  that left a test server unbootable, so the script waits, and before its own reboot it
  checks that no package is being installed.
- **The root password is never locked** if the new user has no password — otherwise sudo
  would be unreachable.
- Every file it replaces or edits in place is copied to `/root/harden-backup-<date>/` first.
- **Your own fail2ban jails stay.** The script writes its two SSH jails to a file of its
  own in `jail.d` and leaves an existing `jail.local` alone.

## What it asks

1. Interface language (English / Русский) — asked once and remembered; `sudo harden --lang` changes it
2. Name of the new sudo user
3. SSH public key — paste it, fetch it from `github.com/<user>.keys`, or copy root's
4. New SSH port (a random one is suggested)
5. Other ports to open, e.g. `80,443`
6. Whether to whitelist your current IP
7. Nightly reboot after kernel updates, locking root, locking other accounts — or, if they
   stay, whether they keep SSH login — CrowdSec, Lynis
8. Telegram alerts — if yes, it walks you through creating the bot
9. Whether to stop answering ping (default: no)

Then a password for the new user — sudo needs it.

Every yes/no question carries the same hint, with what a bare Enter does said in words:
`[y/n, Enter — yes]` or `[y/n, Enter — no]`. `y`, `yes`, `д`, `да` and `n`, `no`, `н`, `нет`
are understood; anything else is asked again rather than taken for a "no".

## What it does

| Area | Changes |
|---|---|
| **SSH** | New port, `AuthenticationMethods publickey`, no passwords, `PermitRootLogin no`, `AllowUsers <you>` (plus the accounts you name), `sshd_config` readable by root only, post-quantum key exchange first (`mlkem768x25519`, `sntrup761x25519` — whichever the installed OpenSSH supports), no weak ciphers, MACs, DH groups or host keys, no forwarding, `MaxAuthTries 3`, version banner hidden |
| **Accounts** | sudo user with your key, password policy (12+ characters, 3 classes), every sudo command logged, root password locked, provider accounts locked with their `NOPASSWD` sudo rules disabled |
| **Firewall** | UFW: all incoming denied except SSH; SSH rate-limited for everyone except your whitelisted IP; optionally no answer to ping |
| **Brute force** | fail2ban (`sshd` aggressive + `recidive`, bans grow up to 4 weeks), optional CrowdSec with the nftables bouncer |
| **Kernel** | `kptr_restrict`, `dmesg_restrict`, BPF hardening, `ptrace_scope`, protected links/FIFOs, anti-spoofing and redirect filters, SYN cookies, BBR; unused filesystems and protocols (dccp, sctp, rds, tipc) disabled |
| **Audit** | auditd rules for accounts, sudoers, SSH config, cron, kernel modules, clock, commands run as root; process accounting; sysstat |
| **Updates** | unattended-upgrades for security updates, needrestart, optional nightly reboot; local config files are kept on upgrade (`--force-confold`), so a package whose config this script edited is not held back |
| **System** | AppArmor, chrony, persistent size-capped journal, no core dumps (apport off), `UMASK 027`, per-user `/tmp` (libpam-tmpdir), ModemManager and udisks2 off, legal pre-login banner, the server's own name in `/etc/hosts` |
| **Login** | The stock Ubuntu greeting (Welcome, ESM, ads, legal) replaced by `server-status` |
| **Alerts** | Optional Telegram messages: every SSH login, a protective service failing, boot, a daily report |
| **Report** | Lynis audit, report in `/root/harden-report.txt`, log in `/var/log/harden.log`; the script stays as `/usr/local/sbin/harden` for `--check` |

## The login summary

Shown once per SSH session (not again in every tmux window), and available any time as
`server-status`:

```
========================================
       🖥️  SYSTEM STATUS
========================================
 IP: 203.0.113.10
 Hostname: my-server
 OS: Ubuntu 24.04.5 LTS (6.8.0-142-generic)
 User: sysop
 Loadavg: 0.08 0.05 0.01
 Uptime: 3 days, 4 hours
 Updates: 0
----------------------------------------
 CPU: 2 cores
 RAM: 1967 MB total, 1447 MB free (73%)
 Disk /: 29G total, 26G free (89%)
 Gateway: 203.0.113.1
----------------------------------------
 ufw        ✓
 ssh        ✓
 fail2ban   ✓
 crowdsec   ✓
 auditd     ✓
========================================
```

Only installed services are listed (nginx, x-ui and docker appear once they exist). The
update count comes from Ubuntu's cache, so logging in does not wait for apt. A `Reboot:
required` line appears when a new kernel is pending; free RAM and disk turn yellow below
25% and red below 10%.

The stock greeting is switched off with `dpkg-statoverride` rather than by `chmod` or by
editing files: the override survives package upgrades, where a plain `chmod` is undone the
next time the package is updated.

On a server hardened by an earlier version: `sudo bash harden.sh --install-status`.

## Telegram alerts

Optional, asked during setup; on a server that is already hardened:
`sudo harden --setup-telegram`. Create the bot at https://t.me/BotFather — the official one
with the blue check mark; searching for the name turns up look-alikes. The script checks the
bot token with Telegram, finds your
chat id once you press Start in the bot, and sends a test message that you confirm before
anything is installed.

| Alert | When |
|---|---|
| 🔑 SSH login | every accepted login — user, IP, key type and fingerprint; connections with the same three within 3 s arrive as one message marked `×2` (MobaXterm, WinSCP and the like open a second connection for files) |
| ❌ service failed | `ssh`, `fail2ban`, `crowdsec`, its bouncer, `auditd` or `unattended-upgrades` ends in a failed state |
| 🔄 server started | after every boot, with the running kernel |
| 📊 daily report | 09:00 server time: pending updates, reboot required, logins and bans in 24 h, failed services, disk and RAM |

A login you did not make is the alert that matters; the rest tells you the server needs
attention before you happen to log in.

How it is built, and why:

- **Logins are read from the journal** by a small service, so neither PAM nor `sshd_config`
  is edited.
- **Failure alerts are systemd `OnFailure=` drop-ins** — the script's own files next to the
  units, removable by deleting them.
- **The bot token** is stored in `/etc/harden/telegram.conf`, readable by root only, and is
  handed to curl on stdin. It never appears on a command line, where any local user could
  read it from `ps`, and it is not written into any script or unit. CI checks both.
- Individual fail2ban bans are **not** sent: a public server collects dozens a day. They are
  counted in the daily report.

After installing a newer `harden`, run `sudo harden --setup-telegram` again and answer yes
to "Use the bot that is already saved?" — the helpers are replaced and restarted without
asking for the token.

To turn it off: `sudo systemctl disable --now harden-login-watch harden-daily-report.timer
harden-boot-alert && sudo rm /etc/harden/telegram.conf`.

## Checking a server

```bash
sudo harden --check          # or: sudo bash harden.sh --check
```

Changes nothing — it does not create so much as a directory. It reads the effective SSH
configuration (`sshd -T`), accounts and sudo rules, firewall, fail2ban and CrowdSec, auditd,
AppArmor, updates, clock and kernel settings, and prints one line each. On a server this
script set up, every kernel value it wrote is compared with the live one, so a setting that
something else has put back shows up. Package configs that an update kept back for review
are listed by name. A firewall other than UFW — firewalld, or nftables or iptables dropping
incoming traffic — is recognised and reported with `!`; its rules are not read. Where it
cannot look — a container that will not let it read the SSH config
without creating a directory — it says so with `!` instead of calling the config broken.
An illustration of the format:

```
SSH
  ✓ Port 10022
  ✓ PermitRootLogin no
  ✓ PasswordAuthentication no
  ✓ Post-quantum key exchange
  ✓ No weak algorithms
Accounts
  ✓ root password locked
  ! Passwordless sudo (NOPASSWD): deploy
Network and protection
  ✓ UFW on, incoming denied
  · Ports listening publicly: 80 443 10022
  ✗ fail2ban does not protect SSH
...
Summary: ✓ 21  ! 2  ✗ 1
```

`✗` is something that lets people in or leaves holes unpatched; `!` is worth a look; `·` is a
fact with no verdict — which ports should be open is your call, the check only lists them. The exit
code is 1 when there is any `✗`, so it can run from cron or monitoring. It works on servers
this script never touched — that is the point: a quick answer to "what state is this box in".

## Unattended run

Every question can be answered in advance. The login check on the new port is still asked
— it is the one step that should never be skipped.

```bash
sudo HARDEN_LANG=en NEW_USER=sysop SSH_PORT=42222 GITHUB_KEYS_USER=yourname \
     EXTRA_PORTS=80,443 ADMIN_IP=203.0.113.5 AUTO_REBOOT=yes LOCK_ROOT=yes \
     LOCK_OTHER_USERS=yes INSTALL_CROWDSEC=no RUN_LYNIS=yes REBOOT_NOW=no bash harden.sh
```

| Variable | Meaning |
|---|---|
| `HARDEN_LANG` | `en` or `ru`; without it the script asks once and remembers the answer |
| `NEW_USER`, `SSH_PORT` | the new user and port |
| `SSH_PUBKEY` / `GITHUB_KEYS_USER` | the key itself, or a GitHub user to fetch keys from |
| `EXTRA_PORTS` | comma-separated, `80,443` or `51820/udp` |
| `ADMIN_IP` | IP to whitelist; empty for none |
| `AUTO_REBOOT`, `REBOOT_TIME` | nightly reboot after kernel updates, default `04:00` |
| `LOCK_ROOT`, `LOCK_OTHER_USERS` | lock the root password / provider accounts |
| `SSH_EXTRA_USERS` | existing accounts that keep SSH login besides the new user, `"deploy monitoring"`; empty for none |
| `INSTALL_CROWDSEC`, `RUN_LYNIS`, `REBOOT_NOW`, `SERVER_STATUS` | `yes` / `no` |
| `REUSE_USER` | `yes` to use an account that already exists (asked otherwise) |
| `TELEGRAM`, `TG_CHAT_ID`, `TG_REPORT_TIME` | `yes` / `no`, the chat to write to, time of the daily report (`09:00`) |
| `DISABLE_PING` | `yes` to stop answering ping (ICMP echo); default `no` |
| `TG_TOKEN` | the bot token; not carried into tmux (it would show in `ps`), so it is asked for there with hidden input |
| `SET_USER_PASSWORD=no` | skip the sudo password now; root then stays unlocked |

## Compatibility

| | |
|---|---|
| OS | Debian 12/13, Ubuntu 22.04/24.04/26.04. RHEL, Alma, Rocky and CentOS are not supported |
| Virtualisation | KVM, VMware, Hyper-V, Xen fully. LXC/OpenVZ partly — auditd, AppArmor and some sysctl values are skipped |
| Architecture | x86_64 and ARM64 |
| Run live | Ubuntu 24.04.5, KVM (OpenStack with cloud-init), 2 vCPU / 2 GB: a complete run from a clean image with versions 2026.10.7 (Lynis 78 → 84, 86 after the reboot) and 2026.10.19; see Limits for the versions in between |
| Run in CI | every push: the whole setup on a virtual machine of each of the five releases — a cloud image boots, the questions are answered on a terminal, the login is tried from outside, then a reboot, `--refresh`, a second run and `--undo`; plus the pieces on Ubuntu 24.04 and `--check` in containers |

**Cloud providers** (AWS, Oracle, Hetzner Cloud, GCP, Azure) have a firewall of their own
in the control panel. Open the new SSH port there *before* confirming the login. If you
forget, the check fails, you answer "no", and SSH rolls back.

**Oracle Cloud** Ubuntu images ship iptables rules that fight UFW. Remove them first:
`sudo apt purge -y iptables-persistent netfilter-persistent`.

## After the run

```bash
ssh -p <port> <user>@<server>          # the only way in now
sudo ufw allow 443/tcp                 # open a port
sudo fail2ban-client status sshd       # banned addresses
sudo cscli decisions list              # CrowdSec bans
sudo ausearch -k identity -i           # who changed accounts
sudo lynis audit system                # full audit
server-status                          # summary
sudo harden --check                    # audit, nothing is changed
sudo harden --setup-telegram           # add Telegram alerts
sudo harden --ping off                 # stop answering ping (--ping on to resume)
sudo harden --lang ru                  # change the remembered language (en or ru)
sudo harden --refresh                  # apply a newer version's settings, no questions
sudo harden --answers                  # the command that repeats this setup
sudo harden --undo                     # take the setup back from the backup
```

To undo a part: SSH settings live in `/etc/ssh/sshd_config.d/00-hardening.conf`, kernel
settings in `/etc/sysctl.d/99-hardening.conf` and `99-protect-links.conf`, and the originals in
`/root/harden-backup-<date>/`. A locked account comes back with
`sudo usermod -U -s /bin/bash <name>`.

## Updating

On a server that is already set up, download the newer script and let it apply its
settings — the same download and checksum, then `--refresh` instead of the setup:

```bash
curl -fsSLo harden.sh https://github.com/N0deZ3r0/server-hardening/releases/download/v2026.10.22/harden.sh && echo "6617af889051804999ed390626ebf0d35006e24942f3de6de3168733f0b113a1  harden.sh" | sha256sum -c - && sudo bash harden.sh --refresh
```

`--refresh` asks nothing. It writes the kernel settings, audit rules, auto-update settings,
fail2ban jails, login summary and Telegram helpers the way this version does, and replaces
the installed `harden`. Accounts, SSH and the firewall are left as they are: those are the
parts where a mistake costs access, and they change only in the full setup, with its login
check. `sudo harden --check` afterwards shows what still differs.

## Repeating a setup, and taking it back

The answers of a setup are kept on the server in `/etc/harden/setup.conf` — no secrets: the
bot token is elsewhere, the password is stored nowhere. The final report prints the command
that repeats the setup with the same answers, and `sudo harden --answers` prints it again.
Keep it off the server if you reinstall often. The password for the new user, the bot
token and the login check are still asked.

`sudo harden --undo` takes the setup back from the oldest backup in `/root/harden-backup-*`,
the one made before the first run. SSH (port and logins), the firewall, root, the locked
accounts and the system files the setup replaced come back; every file it added is removed.
Installed packages and the user it created stay; kernel settings return after a reboot.
fail2ban is stopped, unless it had a configuration of its own before the setup: on the
distribution's defaults it has no exception for your address and bans on what is already in
the log. It
asks before it starts, and the session it runs in stays up — try the old way in before you
close it.

## Releases and verification

A script that runs as root deserves to be the one you meant to run. Each version is
published as a [release](https://github.com/N0deZ3r0/server-hardening/releases) with
`harden.sh`, `SHA256SUMS` and a signed provenance attestation, and the install command above
names one release and one checksum.

**What the checksum proves:** the file you downloaded is byte for byte the file that was
released — not truncated, not altered on the way, and not whatever happens to be on `main`
today. A release is published only if the tag, the version inside the script and the
checksum in this README all agree, and only from a commit on `main` that passed the checks.

**What it does not prove:** that the release itself is honest. The checksum sits in the same
repository as the script, so someone who took over the GitHub account could change both.
Three things narrow that:

- **Releases are immutable.** From 2026.10.22 on, a published release cannot be changed:
  GitHub refuses to move its tag or replace its files, for the owner of the account too.
  What a version number pointed to yesterday is what it points to today. Earlier releases
  were published before this was switched on.
- **Provenance.** With the GitHub CLI, `gh attestation verify harden.sh --repo
  N0deZ3r0/server-hardening` shows which commit and which workflow produced the file, signed
  through Sigstore — a file built anywhere else does not verify.
- **Your own copy of the checksum.** Read the script once, note the checksum of the version
  you read, and keep using that exact command. It will keep installing what you reviewed.

The newest unreleased code is on `main` —
`curl -fsSL https://raw.githubusercontent.com/N0deZ3r0/server-hardening/main/harden.sh -o harden.sh`
— with no checksum to compare against; use it for development, not for servers.

## Limits

Knowingly open, with the reason for each:

- **Run by a person on one system, by CI on five.** A person has run the setup only on
  Ubuntu 24.04 (KVM, one provider). CI runs it whole on a virtual machine of every
  supported release ([tools/e2e.py](tools/e2e.py)). The first time it did, it found that
  the setup had never worked on Ubuntu 26.04 — sudo there is sudo-rs, which does not know
  one of the settings written — and had stopped working on Debian 12 in 2026.10.15,
  on a `cp` option that is broken in that release's coreutils. Both had been listed as
  supported. What the VM runs leave out: the move into tmux, Telegram, Lynis, IPv6, and
  whatever a real provider's image does differently from the stock cloud image.
- **Versions 2026.10.8 to 2026.10.17 could not finish a setup on an Ubuntu 24.04 cloud
  image.** They stopped at the SSH switch and rolled back: access was never lost, and the
  setup was never completed. systemd had the SSH unit down as inactive while its listener
  was still running, and the script spared that listener as the unit's main process — so
  the one daemon that had to go kept port 22. CI reproduces that state — `systemctl enable
  ssh.service` on a running, socket-activated unit — in some runs and not in others. It
  also showed the trap in the obvious fix: signalling that listener while systemd reads
  the unit as inactive freezes PID 1. The script now stops sshd before it switches the
  units, puts systemd's books straight if the state is already there, and reads success
  from the socket table. The last
  complete run from a clean image before that was version 2026.10.7. Version 2026.10.19
  has since run from a clean image to the end, socket-activated sshd included. That run
  took the new order — sshd stopped first, units switched after — and never got into the
  broken state, so the branch that repairs it when it is already there has still run
  only in CI.
- **Live runs are on one server** (Ubuntu 24.04, KVM): the full setup from a clean image,
  Telegram alerts, `--check`. Those runs found nine things CI had missed — a false failure
  in the audit, key-lookup log lines reported as logins, two alerts per connect from clients
  that open a second connection, `journalctl -f -n 0` dropping lines, files written
  unreadable under the script's own `UMASK 027`, UFW turning ping back on, an sshd left on the
  old port through the switch, apport re-enabling dumps of privileged programs at every
  boot, and the distribution's own sysctl file lowering `fs.protected_fifos` after ours —
  and each is now replayed in CI. The failure alert is
  verified in CI only, with a unit that really fails, against a stand-in for the Bot API.
- **Paths no live run took were found by reading the code**, line by line, and are now
  tested: a re-run through `sudo harden` ended in an error just before the final report;
  a run from the provider's console, before any SSH connection, stopped while looking
  for the current port; a cloud-init that is installed but never runs was waited for
  for 45 minutes; a failed CrowdSec install or an extra port UFW refused ended the whole
  setup half-way; a key was glued onto the last line of an `authorized_keys` file that
  did not end in a newline. That such things were there says what an untested path is
  worth — see the first point of this list.
- **Not answering ping is obscurity, not protection.** It takes the server out of ping
  sweeps; a port scan finds it just the same. The practical reason to turn it on is a VPN
  server: detectors such as 2ip compare the ping time to your address with the latency
  seen from the browser ("two-way ping"), and with no answer that test has nothing to
  measure. Other signals stay — above all, that the address belongs to a hosting provider. It also blinds anything that checks the
  server by ping — including some providers' monitoring, which will report it as down — so
  it is off unless you ask. Only echo requests are ignored; the ICMP that path MTU discovery
  and IPv6 need is untouched. The setting is written twice — in a sysctl file of its own
  and in UFW's `sysctl.conf`, which UFW re-applies on every start and which otherwise turns
  ping back on.
- **Telegram sees your alerts.** Messages carry the hostname and the IP addresses of
  logins and pass through Telegram's servers. Anyone with root on the server can read the
  bot token and write to that chat as the bot — use a bot made for this server only.
- **Docker bypasses UFW.** Published container ports are reachable whatever UFW says.
  Publish as `-p 127.0.0.1:8080:80`, or use `ufw-docker`.
- **No port forwarding over SSH**, which also breaks VS Code Remote-SSH. Set
  `AllowTcpForwarding local` (and `MaxSessions 10` if needed) in
  `/etc/ssh/sshd_config.d/00-hardening.conf`, then `sudo systemctl restart ssh`.
- **The whitelisted IP is trusted** by fail2ban, CrowdSec and the rate limit. If your IP
  is dynamic, whoever holds it next gets that too — they still need your key.
- **The provider's web console** needs the new user's password once root is locked.
- **CrowdSec comes from its vendor's repository**, which means trusting its signing key.
  No vendor script is run: the script adds the repository itself, accepts the key only if
  its fingerprint is `6A89E3C2 303A901A 889971D3 376ED532 6E93CD0C` (checked against
  packagecloud.io, keyserver.ubuntu.com and keys.openpgp.org), and pins apt so that only
  `crowdsec` and `crowdsec-firewall-bouncer-nftables` can come from there — a compromised
  repository still cannot ship a new openssh or sudo. If the vendor rotates the key,
  CrowdSec is skipped until the fingerprint here is updated; CI checks it on every push.
- **The audit rule set is loaded as a whole** from `/etc/audit/rules.d`. Rule files that
  were already there are kept and loaded together with ours; rules typed in with
  `auditctl` and saved nowhere are gone after the reload, as after any restart.
- **The IP whitelist covers the SSH jails only.** Jails you add yourself keep fail2ban's
  own defaults — backend, action, ban time — and do not know about the whitelisted IP.
- **USB storage is disabled** — irrelevant on a VPS, noticeable on bare metal, where the
  final report says so and how to undo it.
- **Lynis suggestions left alone:** separate `/home` `/tmp` `/var` partitions (only
  possible at install time), a GRUB password (gets in the way of the provider console),
  AIDE and malware scanners (slow, noisy, false positives), forced password expiry
  (current NIST guidance advises against it), remote log shipping (needs a second server),
  `kernel.modules_disabled=1` (the firewall and a VPN load their modules later).
  `dccp`, `sctp`, `rds` and `tipc` are disabled with `install … /bin/false`; Lynis only
  recognises `/bin/true`, so it keeps suggesting them.

## License

[MIT](LICENSE)
