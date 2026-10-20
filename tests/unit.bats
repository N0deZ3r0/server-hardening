#!/usr/bin/env bats
# Unit tests: single functions of harden.sh, sourced, with what they touch pointed at a
# temporary directory and the system commands they ask replaced by stubs where needed.
# No root, no network, no VM. Run: bats tests/
#
# What only a real system can show — systemd, sshd, ufw, fail2ban — is tested in CI on
# the runner and in tools/e2e.py on virtual machines.

setup() {
  # shellcheck source=../harden.sh
  source "$BATS_TEST_DIRNAME/../harden.sh"
  # harden.sh turns errexit, nounset, pipefail and an ERR trap on for itself; bats keeps
  # its own rules
  set +eu +o pipefail
  trap - ERR
  UI=en
  TMP=$BATS_TEST_TMPDIR
}

# `! cmd` does not fail a bats test (errexit ignores it); this does
refute() {
  if "$@"; then echo "expected to fail: $*" >&2; return 1; fi
}

# strict "snippet" — runs it the way the script runs, with its own set -Eeuo pipefail and
# ERR trap. There a function that ends on a false test returns 1 and stops the setup; the
# relaxed settings of the other tests would hide that.
strict() {
  run bash -c 'source "$1"; eval "$2"' _ "$BATS_TEST_DIRNAME/../harden.sh" "$1"
  if [ "$status" -ne 0 ] || [[ $output == *"Error at line"* ]]; then
    echo "$output" >&2
    return 1
  fi
}

# ---- interface ----

@test "T picks the language of the interface" {
  UI=ru; [ "$(T да yes)" = да ]
  UI=en; [ "$(T да yes)" = yes ]
}

@test "env_yn: a preset answer is used without a question" {
  AUTO_REBOOT=yes; env_yn AUTO_REBOOT "?" n
  AUTO_REBOOT=Yes; env_yn AUTO_REBOOT "?" n
  AUTO_REBOOT=no; run env_yn AUTO_REBOOT "?" y
  [ "$status" -ne 0 ]
}

# ---- input that goes into files and URLs ----

@test "valid_github_user accepts what GitHub allows and nothing else" {
  for u in octocat a a-b A1 "$(printf 'a%.0s' {1..39})"; do valid_github_user "$u"; done
  for u in "" -a a- a--b a/b ../x 'a b' 'a;b' "$(printf 'a%.0s' {1..40})"; do
    run valid_github_user "$u"
    [ "$status" -ne 0 ] || { echo "accepted: '$u'"; false; }
  done
}

@test "valid_extra_users keeps existing accounts only, never root" {
  NEW_USER=nobody
  run valid_extra_users "root,daemon nosuchuser-ci nobody"
  [ "$status" -eq 0 ]
  [ "${lines[-1]}" = daemon ] || [ "$output" = daemon ]
}

@test "shq quotes a value so that a shell reads it back unchanged" {
  for v in "plain" "with space" "it's" "\$(id)" '`id`' 'a"b'; do
    [ "$(eval "printf '%s' $(shq "$v")")" = "$v" ]
  done
}

# ---- SSH keys ----

@test "normalize_pubkeys keeps key lines and drops the rest" {
  ssh-keygen -q -t ed25519 -N '' -f "$TMP/k" -C ci
  { echo '# a comment'; echo 'command="x" ssh-ed25519 AAAA forced'; cat "$TMP/k.pub"; echo; } >"$TMP/in"
  normalize_pubkeys "$TMP/in"
  [ "$(cat "$TMP/in")" = "$(cat "$TMP/k.pub")" ]
}

@test "normalize_pubkeys refuses a file without a key, and an empty one" {
  echo '-----BEGIN OPENSSH PRIVATE KEY-----' >"$TMP/priv"
  run normalize_pubkeys "$TMP/priv"
  [ "$status" -ne 0 ]
  : >"$TMP/empty"
  run normalize_pubkeys "$TMP/empty"
  [ "$status" -ne 0 ]
}

@test "check_pubkeys changes nothing, refuses a damaged key and names a weak one" {
  ssh-keygen -q -t ed25519 -N '' -f "$TMP/k"
  cp "$TMP/k.pub" "$TMP/keys"
  check_pubkeys "$TMP/keys"
  cmp "$TMP/k.pub" "$TMP/keys"
  echo 'ssh-ed25519 AAAAnotbase64 broken' >"$TMP/bad"
  run check_pubkeys "$TMP/bad"
  [ "$status" -ne 0 ]
  ssh-keygen -q -t rsa -b 2048 -N '' -f "$TMP/rsa"
  run check_pubkeys "$TMP/rsa.pub"
  [ "$status" -eq 0 ]
  [[ $output == *"2048-bit RSA key is weak"* ]]
}

@test "add_keys puts a new key on a line of its own and adds nothing twice" {
  printf 'ssh-ed25519 AAAAold old' >"$TMP/ak"      # no newline at the end
  printf 'ssh-ed25519 AAAAnew new\nssh-ed25519 AAAAold old\n' >"$TMP/new"
  add_keys "$TMP/new" "$TMP/ak"
  add_keys "$TMP/new" "$TMP/ak"
  [ "$(wc -l <"$TMP/ak")" -eq 2 ]
  grep -qx 'ssh-ed25519 AAAAold old' "$TMP/ak"
  grep -qx 'ssh-ed25519 AAAAnew new' "$TMP/ak"
}

# ---- SSH config ----

@test "write_sshd_config writes the ports, the users and every line of the policy" {
  NEW_USER=alex; SSH_EXTRA_USERS="deploy"
  write_sshd_config "22 2233" "$TMP/sshd.conf"
  grep -qx 'Port 22' "$TMP/sshd.conf"
  grep -qx 'Port 2233' "$TMP/sshd.conf"
  grep -qx 'AllowUsers alex deploy' "$TMP/sshd.conf"
  for line in "${SSH_AUTH_POLICY[@]}"; do grep -qx "$line" "$TMP/sshd.conf"; done
  # no Match block: the rules hold on every port
  refute grep -q '^Match' "$TMP/sshd.conf"
  [ "$(stat -c %a "$TMP/sshd.conf")" = 600 ]
}

@test "write_sshd_config leaves out an algorithm line this OpenSSH would have nothing for" {
  ssh() { return 1; }        # `ssh -Q` knows no algorithm at all
  NEW_USER=alex
  write_sshd_config 2233 "$TMP/sshd.conf"
  refute grep -qE '^(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms)' "$TMP/sshd.conf"
  grep -qx 'Port 2233' "$TMP/sshd.conf"
}

@test "ssh_apply_script: socket mode restarts the socket, never turns it off" {
  systemctl() {
    case "$*" in
      "list-unit-files ssh.service") return 0 ;;
      "is-enabled --quiet ssh.socket") return 0 ;;
    esac
    return 1
  }
  run ssh_apply_script
  [[ $output == *"systemctl daemon-reload"* ]]
  [[ $output == *"systemctl stop ssh.socket ssh.service"* ]]
  [[ ${lines[-1]} == "systemctl start ssh.socket" ]]
  [[ $output != *disable* && $output != *enable* ]]
}

@test "ssh_apply_script: a plain service is reloaded" {
  systemctl() { [ "$*" = "list-unit-files ssh.service" ]; }
  run ssh_apply_script
  [ "$output" = "systemctl reload-or-restart ssh.service" ]
}

@test "write_ssh_rollback: a script of its own that restores the backup and applies it" {
  systemctl() { [ "$*" = "list-unit-files ssh.service" ]; }
  SSH_ROLLBACK=$TMP/run/ssh-rollback.sh
  BACKUP_DIR="$TMP/backup dir"
  SSHD_DROPIN=/etc/ssh/sshd_config.d/00-hardening.conf
  write_ssh_rollback
  [ -x "$SSH_ROLLBACK" ]
  bash -n "$SSH_ROLLBACK"
  grep -qF 'rm -f /etc/ssh/sshd_config.d/00-hardening.conf' "$SSH_ROLLBACK"
  grep -qF 'cp -a '"$TMP"'/backup\ dir/ssh/. /etc/ssh/' "$SSH_ROLLBACK"
  grep -qx 'systemctl reload-or-restart ssh.service' "$SSH_ROLLBACK"
  grep -qF "systemctl stop $SSHD_TEST_UNIT" "$SSH_ROLLBACK"
}

@test "sshd_still_on names the ports sshd or its socket still holds" {
  ss() {
    case "$*" in
      *:22)   echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=7,fd=3),("systemd",pid=1,fd=50))' ;;
      *:2224) echo 'LISTEN 0 5 0.0.0.0:2224 0.0.0.0:* users:(("python3",pid=9,fd=3))' ;;
    esac
  }
  [ "$(sshd_still_on 22 2224 2233)" = 22 ]
  refute sshd_listening 2224   # another program on the port is not sshd
  sshd_listening 22
}

# ---- kernel settings ----

@test "write_sysctl_conf writes every setting once, and the link protection file from the same list" {
  SYSCTL_CONF=$TMP/99-hardening.conf PROTECT_LINKS_CONF=$TMP/99-protect-links.conf
  write_sysctl_conf
  for kv in "${SYSCTL_SETTINGS[@]}" "${SYSCTL_PERFORMANCE[@]}"; do
    [ "$(grep -cx "${kv%%=*} = ${kv#*=}" "$SYSCTL_CONF")" -eq 1 ]
  done
  [ "$(grep -c '^fs\.protected_' "$PROTECT_LINKS_CONF")" -eq 4 ]
  grep -qx 'fs.protected_fifos = 2' "$PROTECT_LINKS_CONF"
}

@test "sysctl_overridden names the settings whose live value differs, and skips unknown keys" {
  sysctl() {   # sysctl -n KEY: everything as wanted, except two
    case $2 in
      fs.protected_fifos) echo 1 ;;
      kernel.sysrq) echo 176 ;;
      net.core.bpf_jit_harden) return 1 ;;      # this kernel has no such key
      *) for kv in "${SYSCTL_SETTINGS[@]}"; do [ "${kv%%=*}" = "$2" ] && echo "${kv#*=}"; done ;;
    esac
  }
  run sysctl_overridden
  [ "$output" = "kernel.sysrq fs.protected_fifos " ]
}

# ---- under the script's own errexit ----

@test "the functions that write files finish under the script's own set -e" {
  strict "SYSCTL_CONF=$TMP/99-hardening.conf PROTECT_LINKS_CONF=$TMP/99-protect-links.conf; write_sysctl_conf"
  [ "$(grep -c . "$TMP/99-protect-links.conf")" -eq 6 ]
  strict "NEW_USER=alex; write_sshd_config 2233 $TMP/sshd.conf"
  strict "systemctl() { [ \"\$*\" = 'list-unit-files ssh.service' ]; }
          SSH_ROLLBACK=$TMP/run/ssh-rollback.sh BACKUP_DIR=$TMP; write_ssh_rollback; ssh_apply_script"
  strict "printf '%s\n' 'ssh-ed25519 AAAA a' >$TMP/k; normalize_pubkeys $TMP/k"
}

@test "the checks that may find nothing finish under the script's own set -e" {
  strict "sysctl() { return 1; }; sysctl_overridden"                 # a kernel with none of the keys
  strict "ss() { :; }; sshd_still_on 22 2233"                       # nothing listens
  strict "systemctl() { return 1; }; ssh_apply_script"              # neither socket nor service found
}

# ---- saved answers ----

@test "print_answers gives a command that sets the same answers again" {
  NEW_USER=alex SSH_PORT=2233 SSH_PUBKEY="ssh-ed25519 AAAA it's mine" EXTRA_PORTS=80,443
  ADMIN_IP=203.0.113.5 AUTO_REBOOT=no LOCK_ROOT=yes LOCK_OTHER_USERS=yes SSH_EXTRA_USERS=
  INSTALL_CROWDSEC=no RUN_LYNIS=yes TELEGRAM=no DISABLE_PING=no
  line=$(print_answers)
  [[ $line == "sudo HARDEN_LANG=en "*" bash harden.sh" ]]
  [[ $line != *REBOOT_TIME* && $line != *SSH_EXTRA_USERS* ]]
  # read back by a shell, the values are what they were
  vars=${line#sudo }; vars=${vars% bash harden.sh}
  got=$(env -i "$BASH" -c 'eval "export $1"; printf "%s|%s" "$SSH_PUBKEY" "$SSH_PORT"' _ "$vars")
  [ "$got" = "ssh-ed25519 AAAA it's mine|2233" ]
}
