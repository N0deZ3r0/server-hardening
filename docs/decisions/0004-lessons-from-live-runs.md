# 0004 — What live servers and VM runs showed

The comments in the code say why a line is the way it is. The stories behind them — how
each case was found — were in those comments too; they are collected here, so the code
reads as what it does. Each case is reproduced in CI or in `tools/e2e.py`.

| Where in the code | What happened |
|---|---|
| `umask 022` at the top (`src/00-header.sh`) | The setup sets `UMASK 027`. `sudo harden …` from such a session passed 027 on to root, the drop-ins came out unreadable for normal users, and the login summary lost every service that had one. |
| `cloud_init_busy` | cloud-init that is installed but never runs says "not started" for ever; the setup waited 45 minutes for it and gave up. |
| `current_ssh_ports` | From the provider's console, before the first SSH login, `sshd -T` failed for want of `/run/sshd`, and under `pipefail` that ended the run. |
| `backup_originals` | `cp --parents` fails in coreutils 9.1 (Debian 12); the first VM run on Debian 12 stopped there. |
| `preflight`, cloud-init wait | A reboot during the provider's first-boot upgrade left a test server unbootable. |
| `setup_user`, sudoers lines tried one at a time | sudo-rs (Ubuntu 25.10+) does not know `logfile`; one unknown line made the whole file invalid and stopped the setup on Ubuntu 26.04. |
| `set_ping`, UFW's `sysctl.conf` | UFW re-applies its own sysctl file after `sysctl.d`; the first full run said "no longer answers ping" and the server went on answering. |
| `setup_firewall`, defaults | A second run used to put back the routed default an admin had changed for a VPN. |
| `setup_firewall`, extra ports | A port UFW refused used to end the setup half-way. |
| `server-status`, `svc` | Asked through `systemctl cat`, a service with one unreadable drop-in vanished from the summary; only ufw was left. |
| `harden-login-watch` | With `LogLevel VERBOSE`, sshd's per-key lookup line was reported as a login "from at". |
| `--check`, "sshd listens only on configured ports" | After a port switch a leftover daemon kept the old port on the old settings (see ADR 0001). |
| `--check`, NOPASSWD | A rule for a group (`%sudo … NOPASSWD`) used to be skipped. |
| `--check`, output captured before `grep` | `cmd \| grep -q` under `pipefail` reported a passing check as failed (SIGPIPE). |
| `--undo`, ping | After an undo the server stayed silent to ping until the next reboot. |
| `install_self` | Run as `sudo harden`, installing the script onto itself failed and ended a re-run just before the report. |
| SSH switch | See [ADR 0001](0001-ssh-port-switch.md). |
