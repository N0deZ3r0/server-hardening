# 0001 — Moving SSH to a new port

**Status:** in force since the release after 2026.10.28. Replaces the two-stage restart of
the server's own sshd.

## The problem

Moving SSH is the one step that can lock the admin out of a remote server for good. It
has to be proven from outside before anything closes, and it must be able to go back
even when the person or the script is no longer there to do it.

## What was there before

Stage 1 rewrote the server's own `sshd` config to listen on both ports, with the new
login rules on the new port only (`Match LocalPort`), and restarted it. Stage 2 rewrote it
again for the new port alone and restarted it once more.

On Ubuntu 22.10 and later sshd is started through `ssh.socket`, which ignored the `Port`
lines as the script used them, so the script turned socket activation off and the plain
service on. Done under a running daemon, that switch could leave systemd reading the unit
as stopped while its daemon still held port 22 and was still named as `MainPID`. What
followed was a run of workarounds, each from a live server or CI:

- a `start` + `stop` of the unit to make systemd forget the stale `MainPID`;
- killing leftover `sshd` listeners, but never the process systemd names as `MainPID`
  (signalling it while systemd reads the unit as inactive froze PID 1 in CI);
- a forced `KillMode=process`, so stopping the unit would not close the admin's session;
- the rules of an earlier run carried over to the old port, so a second run with another
  port did not let passwords in for as long as the question stood on the screen.

Versions 2026.10.8 to 2026.10.17 could not finish on an Ubuntu 24.04 cloud image because
of the first of these. Every one of them was correct, and every one was there because the
running daemon was being changed before the new port was proven.

## The decision

1. **Stage 1 does not touch the running sshd.** A second sshd is started for the test
   alone — `systemd-run`, `sshd -D -f <test config> -p <new port>` — with the whole
   configuration the server is about to get: the provider's `sshd_config` and its other
   drop-ins, with the new `00-hardening.conf` in place of any earlier one. The admin logs
   in through it from another window. "No" stops it, and that is all there is to undo.
   It runs with `KillMode=process`, so stopping it does not close the window the admin
   tested from.
2. **Stage 2 arms the way back first.** A small script that restores `/etc/ssh` from the
   backup and makes sshd take it is written to `/run/harden`, and a transient timer
   (`systemd-run --on-active`, ten minutes by default) is set to run it. Only then does the
   server's own sshd take the new settings, and the admin confirms a new login through it.
   "Yes" stops the timer; "no" runs the script at once. If the session drops, the script
   is killed, or the new settings let nobody in to answer, the timer runs it anyway. This
   is the `commit confirmed` of network equipment.
3. **The socket is kept.** Where sshd runs through `ssh.socket`, its ports come from
   `sshd_config` by way of `sshd-socket-generator`. A new port is `daemon-reload`, then the
   socket and service stopped (socket first, so nothing can start the service on the old
   sockets in between) and the socket started again — the way Ubuntu documents it. Where
   sshd is a plain service, a `reload` re-executes the listener on the new settings.
   Sessions survive both. Nothing is enabled or disabled, so systemd's bookkeeping never
   goes out of step with the daemon, and the workarounds above are gone.
4. **Success is read from the kernel.** A port counts as served when `ss` shows `sshd`, or
   `systemd` holding the socket for it, listening there. Another program on the port does
   not count, so an sshd that could not bind one of its ports shows up as a failure.

On a re-run with the port sshd is already on there is no second port for a test sshd;
stage 2 with its timer is the test then.

## Consequences

- The README's promise holds in a stronger form: the old door is not just open while the
  new one is tried — it is not touched at all.
- A server without `sshd-socket-generator` but with `ssh.socket` enabled is refused before
  anything changes, with the command to switch it to the plain service. All supported
  releases that use the socket have the generator.
- Stage 2 asks one more question than before. The VM test (`tools/e2e.py`) answers it the
  way a person should: by logging in from outside first.
- After a reboot during the ten minutes there is no timer (it lives in `/run`), and the
  settings confirmed through the test sshd stay.
