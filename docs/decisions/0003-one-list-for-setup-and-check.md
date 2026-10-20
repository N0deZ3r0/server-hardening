# 0003 — One list for what the setup writes and what `--check` expects

**Status:** in force since 2026.10.29.

## The problem

The kernel settings were written from one list in a heredoc and checked from another: the
setup's own file on a server it had set up, a shorter list typed into `--check` for any
other. The SSH login rules were written in one place and checked line by line in another.
Two lists of the same thing drift apart, and nothing notices.

## The decision

- `SYSCTL_SETTINGS` is the list of kernel settings. `write_sysctl_conf` writes it (and
  derives `99-protect-links.conf` from its `fs.protected_*` entries), and
  `sysctl_overridden` compares every entry with the live value — after the setup, and in
  `--check` on any server. `SYSCTL_PERFORMANCE` (BBR, fq) is written but not checked: it
  is speed, not security.
- `SSH_AUTH_POLICY` is the list of login rules. `write_sshd_config` writes it,
  `ssh_settings_not_in_effect` compares it with what `sshd -T` says sshd will really do,
  and `--check` reports each entry.

## Consequences

- On a server the setup has not touched, `--check` now compares all the kernel settings,
  not a short list. A setting that differs is a `!`, as before.
- On a server set up by an older version, a setting this version added shows as differing
  until `sudo harden --refresh` writes it.
- `--check` also reports `AuthenticationMethods publickey`, which it did not before.
