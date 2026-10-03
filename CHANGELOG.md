# Changelog

**English** · [Русский](CHANGELOG.ru.md)

What changed in each release, newest first. A line that starts with **Known problem** says
where that version does not work — it is there because someone ran it and it did not.

The text of each release on GitHub is generated from this file.

## 2026.10.26

Found by running what no test had run before, not by reading.

- A key pressed while the setup was working answered the next question. What is typed
  ahead stays in the terminal's buffer, and the first question after the long package
  step is "does the login on the new port work?" — a stray "y" closed the old port with
  nobody having tried the new one. What is typed before a question appears is now thrown
  away. The same stray Enter also closed the tmux window with the final report in it.
- A setup run again with the saved bot moved the daily report back to 09:00.
- `--refresh` stopped half-way when the saved answers lacked a line (a file edited by
  hand, or written by another version).
- A Telegram message is tried again when the network is not there yet: the one after a
  boot was lost when it went out before the network or DNS was up.
- CI: the run on virtual machines now also covers Telegram alerts against a stand-in for
  the Bot API (a real login in each release's own sshd log format, the daily report, the
  message after a boot), a third setup with another port and a network as the admin's
  address, a finished run left open in tmux, a key pressed ahead of the questions, and
  `--undo` with the system files compared byte for byte with what they were.

## 2026.10.25

Found by reading the script once more.

- `--refresh` no longer takes back what was switched by hand after the setup. It turned
  ping back on after `harden --ping off`, brought back the login hook that had been
  removed, and moved the daily report back to 09:00. `--ping`, `--setup-telegram` and
  `--install-status` are now recorded with the saved answers.
- The setup run again with another port: until the new port was confirmed, the old port
  fell back to the provider's `sshd_config` — passwords included — instead of keeping the
  rules of the earlier run. Run again with the same port, the accounts that could log in
  stay allowed until the login is confirmed.
- From a terminal type the server does not know (kitty, ghostty on a fresh image) tmux
  refused to start, and the setup ended there with tmux's one line for an explanation.
- The marker files in users' home directories are written as that user. Written by root,
  one landed wherever a symlink in that home pointed, owned by that user.
- `--undo` also brings back `/etc/motd` (Debian), and switches on again the services the
  setup had switched off (apport, ModemManager, udisks2).
- A second run from another address left the firewall exception for the earlier address
  in place; a network given as the admin address (`203.0.113.0/24`) was not whitelisted in
  CrowdSec; a firewall that refuses the admin's address no longer ends the setup.
- Smaller: key source 3 also reads the keys of the account `sudo` was called from (AWS,
  Oracle, Azure); the reboot line names a new kernel only when there is one; the login
  summary no longer fails on a root file system `df` cannot size.

## 2026.10.24

Found by reading the script again, the parts added since the last such read included.

- The SSH switch: until the login on the new port is confirmed, the old port keeps the
  rules it had. Before, both ports got the new rules at once — if the new key turned out not
  to work and the session dropped, the provider's console was the only way back.
- `--undo` takes only a backup made before the setup; one taken on an already hardened
  server would have put the hardening back.
- `--refresh` on a server set up by a version older than 2026.10.15 lost the whitelisted
  address.
- A second run of the setup no longer resets the firewall's defaults for outgoing and
  routed traffic — a VPN server that allows routing kept losing it.
- A finished run left open in tmux is no longer what the next run attaches to.
- Smaller: a port typed with a leading zero is accepted; the CrowdSec whitelist follows the
  answer of the latest run.

## 2026.10.23

- Telegram: the daily report now carries the result of `--check` — the summary line and
  the lines that need attention — so a setting that has drifted is seen the next morning.
- A release is refused unless CI passed for its commit and this file has an entry for it.
- CI: the run on virtual machines goes through tmux where the image has it, as a real run does.
- README: notes for a VPN server.

## 2026.10.22

- The whole setup now runs in CI on a virtual machine of every supported release (Ubuntu
  22.04, 24.04, 26.04, Debian 12, 13): a clean cloud image, the questions answered on a
  terminal, the login tried from outside, a reboot, a second run, and the new commands.
- Fixed: on Debian 12 the setup stopped in its first step (since 2026.10.15).
- Fixed: on Ubuntu 26.04 the setup stopped when creating the user — it had never worked there.
- New: `--refresh` applies a newer version's settings without questions; `--answers` prints
  the command that repeats a setup; `--undo` takes the setup back from the backup.
- Releases are immutable from this one on.

## 2026.10.21

- After the SSH switch, the packaged `sshd_config` that an upgrade set aside is moved to the
  backup, so `--check` does not end with a standing `!` on images whose provider edited it.

**Known problem:** the setup does not finish on Debian 12 or Ubuntu 26.04. Fixed in 2026.10.22.

## 2026.10.20

- The messages of the SSH step say that the old port is open only until the login on the
  new one is confirmed, and name the port that was closed.

**Known problem:** the setup does not finish on Debian 12 or Ubuntu 26.04. Fixed in 2026.10.22.

## 2026.10.19

- `--check` names the package configs waiting for review instead of only counting them.

**Known problem:** the setup does not finish on Debian 12 or Ubuntu 26.04. Fixed in 2026.10.22.

## 2026.10.18

- Fixed: the SSH switch where sshd is started through a socket (Ubuntu 24.04 cloud images).
  Versions 2026.10.8 to 2026.10.17 rolled back at that step.
- When sshd does not come up as it should, the script prints who holds each port.

**Known problem:** the setup does not finish on Debian 12 or Ubuntu 26.04. Fixed in 2026.10.22.

## 2026.10.17

- Every yes/no question carries the same hint, with what Enter does said in words; an
  answer that is neither yes nor no is asked again.

**Known problem:** the setup rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed
in 2026.10.18) and does not finish on Debian 12 or Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.16

- Found by reading the code line by line, and fixed: a re-run through `sudo harden` ended in
  an error before the final report; a run from the provider's console stopped while looking
  for the current port; a cloud-init that never runs was waited for for 45 minutes; a failed
  CrowdSec install or a refused extra port ended the whole setup; a key was glued onto the
  last line of an `authorized_keys` file with no final newline.
- `--check` counts `NOPASSWD` rules for groups and recognises firewalls other than UFW.
- Leftover configs of removed packages are counted, not purged. Logs are readable by root only.

**Known problem:** the setup rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed
in 2026.10.18) and does not finish on Debian 12 or Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.15

- fail2ban: the setup's two SSH jails live in a file of their own; an existing `jail.local`
  is kept. Every file the setup replaces or edits is backed up first.

**Known problem:** from this version on the setup stops at once on Debian 12 (fixed in
2026.10.22). It also rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed in
2026.10.18) and does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.14

- `--check`: where it cannot read the SSH config without creating something, it says so with
  `!` instead of calling the config broken.
- ECDSA host key files are no longer deleted.
- CI runs `--check` inside containers of all five supported releases.

**Known problem:** the setup rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed
in 2026.10.18) and does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.13

- From an outside review: the setup says that SSH will accept only the new user and asks
  whether other accounts keep their login (`SSH_EXTRA_USERS`); `--check` creates nothing;
  open ports are shown as facts, not as passes; package configs kept back are counted.

**Known problem:** the setup rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed
in 2026.10.18) and does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.12

- `fs.protected_fifos` stays at 2: the distribution's own file used to put it back to 1.
- `--check` compares every kernel value the setup wrote with the live one.
- `sshd_config` is readable by root only; the server's own name is added to `/etc/hosts`.

**Known problem:** the setup rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed
in 2026.10.18) and does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.11

- The warning frame is sized from its text; its sides stood one column short.

**Known problem:** the setup rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed
in 2026.10.18) and does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.10

- The interface language is remembered; `--lang` changes it.

**Known problem:** the setup rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed
in 2026.10.18) and does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.9

- apport no longer turns memory dumps of privileged programs back on at every boot.

**Known problem:** the setup rolls back at the SSH switch on Ubuntu 24.04 cloud images (fixed
in 2026.10.18) and does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.8

- A leftover sshd is looked for and stopped at the port switch.
- "Do not answer ping" is also written where UFW would otherwise turn it back.

**Known problem:** from this version to 2026.10.17 the setup rolls back at the SSH switch
where sshd is started through a socket — Ubuntu 24.04 cloud images (fixed in 2026.10.18).
It does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.7

- New: optionally stop answering ping (`DISABLE_PING`, `--ping off|on`).

**Known problem:** up to this version, where sshd is started through a socket the old daemon
is left listening on port 22 until the next reboot, kept out only by the firewall (fixed in
2026.10.18). The setup does not finish on Ubuntu 26.04 (fixed in 2026.10.22).

## 2026.10.6

- Files are written with ordinary modes whatever the caller's umask. Under the script's own
  `UMASK 027` the login summary had lost every service with a drop-in.

**Known problem:** where sshd is started through a socket the old daemon is left listening
on port 22 until the next reboot (fixed in 2026.10.18). The setup does not finish on Ubuntu
26.04 (fixed in 2026.10.22).

## 2026.10.5

- Login summary: services are found by their unit file on disk. (The cause named in this
  release was wrong; the real fix is 2026.10.6.)

**Known problem:** where sshd is started through a socket the old daemon is left listening
on port 22 until the next reboot (fixed in 2026.10.18). The setup does not finish on Ubuntu
26.04 (fixed in 2026.10.22).

## 2026.10.4

- Telegram: the login watcher no longer misses the first lines after it starts, and is
  restarted when the setup is run again.

**Known problem:** where sshd is started through a socket the old daemon is left listening
on port 22 until the next reboot (fixed in 2026.10.18). The setup does not finish on Ubuntu
26.04 (fixed in 2026.10.22).

## 2026.10.3

- Telegram: only real logins are reported; connections from one client within 3 seconds
  arrive as one message marked `×2`.

**Known problem:** where sshd is started through a socket the old daemon is left listening
on port 22 until the next reboot (fixed in 2026.10.18). The setup does not finish on Ubuntu
26.04 (fixed in 2026.10.22).

## 2026.10.2

- `--check` no longer reports a failure for a check that passes (the auto-updates line).

**Known problem:** where sshd is started through a socket the old daemon is left listening
on port 22 until the next reboot (fixed in 2026.10.18). The setup does not finish on Ubuntu
26.04 (fixed in 2026.10.22).

## 2026.10.1

- The setup links straight to the official BotFather: searching for it turns up look-alikes.

**Known problem:** where sshd is started through a socket the old daemon is left listening
on port 22 until the next reboot (fixed in 2026.10.18). The setup does not finish on Ubuntu
26.04 (fixed in 2026.10.22).

## 2026.10.0

- First release with a checksum in the install command and a signed provenance record.
- New: Telegram alerts, `--check`.

**Known problem:** where sshd is started through a socket the old daemon is left listening
on port 22 until the next reboot (fixed in 2026.10.18). The setup does not finish on Ubuntu
26.04 (fixed in 2026.10.22).
