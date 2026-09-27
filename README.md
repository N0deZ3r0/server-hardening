<div align="center">

# Server Hardening

**One command turns a fresh Debian or Ubuntu VPS into a server that only lets in your key — and it will not close the old door until you have walked through the new one.**

[![CI](https://github.com/N0deZ3r0/server-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/N0deZ3r0/server-hardening/actions/workflows/ci.yml)
![version](https://img.shields.io/badge/version-2026.09-3b5bdb)
![Debian](https://img.shields.io/badge/Debian-12%20%2F%2013-a80030)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20%2F%2024.04%20%2F%2026.04-e95420)
![bash](https://img.shields.io/badge/bash-single%20file-2f9e44)
![Lynis](https://img.shields.io/badge/Lynis-84%2F100-2f9e44)
![license](https://img.shields.io/badge/license-MIT-4c6ef5)

**English** · [Русский](README.ru.md)

</div>

A single bash script, run once as root on a new server. It asks a handful of questions,
creates a sudo user with your SSH key, moves SSH to a new port with key-only login and no
root, turns on a firewall, fail2ban and optionally CrowdSec, hardens the kernel, enables
security auto-updates and audit logging, replaces the login greeting with a short server
summary, and finishes with a Lynis audit. The interface is in English and Russian.

```bash
curl -fsSL https://raw.githubusercontent.com/N0deZ3r0/server-hardening/main/harden.sh -o harden.sh && sudo bash harden.sh
```

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
  are logged in with.
- **It runs inside tmux.** Fresh VPS images often restart SSH in the first minutes and
  drop the session; the setup keeps going, and `tmux attach -t harden` brings you back.
- **It waits for the provider.** Many images run a full upgrade from cloud-init after
  first boot — GRUB and kernel included — for 5–20 minutes. Rebooting in the middle of
  that left a test server unbootable, so the script waits, and before its own reboot it
  checks that no package is being installed.
- **The root password is never locked** if the new user has no password — otherwise sudo
  would be unreachable.
- Every file it replaces is copied to `/root/harden-backup-<date>/` first.

## What it asks

1. Interface language (English / Русский)
2. Name of the new sudo user
3. SSH public key — paste it, fetch it from `github.com/<user>.keys`, or copy root's
4. New SSH port (a random one is suggested)
5. Other ports to open, e.g. `80,443`
6. Whether to whitelist your current IP
7. Nightly reboot after kernel updates, locking root, locking other accounts, CrowdSec, Lynis

Then a password for the new user — sudo needs it.

## What it does

| Area | Changes |
|---|---|
| **SSH** | New port, `AuthenticationMethods publickey`, no passwords, `PermitRootLogin no`, `AllowUsers <you>`, post-quantum key exchange first (`mlkem768x25519`, `sntrup761x25519` — whichever the installed OpenSSH supports), no weak ciphers, MACs, DH groups or host keys, no forwarding, `MaxAuthTries 3`, version banner hidden |
| **Accounts** | sudo user with your key, password policy (12+ characters, 3 classes), every sudo command logged, root password locked, provider accounts locked with their `NOPASSWD` sudo rules disabled |
| **Firewall** | UFW: all incoming denied except SSH; SSH rate-limited for everyone except your whitelisted IP |
| **Brute force** | fail2ban (`sshd` aggressive + `recidive`, bans grow up to 4 weeks), optional CrowdSec with the nftables bouncer |
| **Kernel** | `kptr_restrict`, `dmesg_restrict`, BPF hardening, `ptrace_scope`, protected links/FIFOs, anti-spoofing and redirect filters, SYN cookies, BBR; unused filesystems and protocols (dccp, sctp, rds, tipc) disabled |
| **Audit** | auditd rules for accounts, sudoers, SSH config, cron, kernel modules, clock, commands run as root; process accounting; sysstat |
| **Updates** | unattended-upgrades for security updates, needrestart, optional nightly reboot |
| **System** | AppArmor, chrony, persistent size-capped journal, no core dumps, `UMASK 027`, per-user `/tmp` (libpam-tmpdir), ModemManager and udisks2 off, legal pre-login banner |
| **Login** | The stock Ubuntu greeting (Welcome, ESM, ads, legal) replaced by `server-status` |
| **Report** | Lynis audit, report in `/root/harden-report.txt`, log in `/var/log/harden.log` |

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

The stock greeting is switched off with `dpkg-statoverride` rather than by editing files:
the setting survives package upgrades, and an edited config file would make
unattended-upgrades skip security updates for the package that owns it.

On a server hardened by an earlier version: `sudo bash harden.sh --install-status`.

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
| `HARDEN_LANG` | `en` or `ru` |
| `NEW_USER`, `SSH_PORT` | the new user and port |
| `SSH_PUBKEY` / `GITHUB_KEYS_USER` | the key itself, or a GitHub user to fetch keys from |
| `EXTRA_PORTS` | comma-separated, `80,443` or `51820/udp` |
| `ADMIN_IP` | IP to whitelist; empty for none |
| `AUTO_REBOOT`, `REBOOT_TIME` | nightly reboot after kernel updates, default `04:00` |
| `LOCK_ROOT`, `LOCK_OTHER_USERS` | lock the root password / provider accounts |
| `INSTALL_CROWDSEC`, `RUN_LYNIS`, `REBOOT_NOW`, `SERVER_STATUS` | `yes` / `no` |
| `SET_USER_PASSWORD=no` | skip the sudo password now; root then stays unlocked |

## Compatibility

| | |
|---|---|
| OS | Debian 12/13, Ubuntu 22.04/24.04/26.04. RHEL, Alma, Rocky and CentOS are not supported |
| Virtualisation | KVM, VMware, Hyper-V, Xen fully. LXC/OpenVZ partly — auditd, AppArmor and some sysctl values are skipped |
| Architecture | x86_64 and ARM64 |
| Run live | Ubuntu 24.04.5, KVM (OpenStack with cloud-init), 2 vCPU / 2 GB: clean run, Lynis 78 → 84 |

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
```

To undo a part: SSH settings live in `/etc/ssh/sshd_config.d/00-hardening.conf`, kernel
settings in `/etc/sysctl.d/99-hardening.conf`, and the originals in
`/root/harden-backup-<date>/`. A locked account comes back with
`sudo usermod -U -s /bin/bash <name>`.

## Limits

Knowingly open, with the reason for each:

- **Live-tested on one system.** Ubuntu 24.04 on KVM ran end to end several times; the
  other versions are supported by design — version checks, algorithm filtering — not by a
  run on each.
- **Docker bypasses UFW.** Published container ports are reachable whatever UFW says.
  Publish as `-p 127.0.0.1:8080:80`, or use `ufw-docker`.
- **No port forwarding over SSH**, which also breaks VS Code Remote-SSH. Set
  `AllowTcpForwarding local` (and `MaxSessions 10` if needed) in
  `/etc/ssh/sshd_config.d/00-hardening.conf`, then `sudo systemctl restart ssh`.
- **The whitelisted IP is trusted** by fail2ban, CrowdSec and the rate limit. If your IP
  is dynamic, whoever holds it next gets that too — they still need your key.
- **The provider's web console** needs the new user's password once root is locked.
- **CrowdSec** is installed from its own repository through `install.crowdsec.net`, which
  means trusting that script.
- **USB storage is disabled** — irrelevant on a VPS, noticeable on bare metal.
- **Lynis suggestions left alone:** separate `/home` `/tmp` `/var` partitions (only
  possible at install time), a GRUB password (gets in the way of the provider console),
  AIDE and malware scanners (slow, noisy, false positives), forced password expiry
  (current NIST guidance advises against it), remote log shipping (needs a second server).
  `dccp`, `sctp`, `rds` and `tipc` are disabled with `install … /bin/false`; Lynis only
  recognises `/bin/true`, so it keeps suggesting them.

## License

[MIT](LICENSE)
