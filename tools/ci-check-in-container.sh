#!/usr/bin/env bash
# Run by CI inside a plain Docker container, once per supported release (see
# .github/workflows/ci.yml). Such a container has no systemd, sshd is installed but was
# never started, and a new mount namespace is refused. `harden.sh --check` has to reach
# its summary there, create nothing, and report "cannot look at the SSH config" as a
# warning — not as a broken config.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
fail() { echo "FAIL: $*" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q --no-install-recommends openssh-server iproute2 procps util-linux >/dev/null
# shellcheck disable=SC1091
. /etc/os-release
echo "== $PRETTY_NAME"

rm -rf /run/sshd
if unshare --mount true 2>/dev/null; then
  fail "this container allows mount namespaces — the test would prove nothing"
fi

set +e
out=$(HARDEN_LANG=en bash "$here/harden.sh" --check 2>&1)
set -e
printf '%s\n' "$out"
grep -q 'Summary:' <<<"$out" || fail "no summary — the check stopped half way"
if grep -q 'Error at line' <<<"$out"; then fail "an unguarded command failed"; fi
grep -q 'cannot be read without creating' <<<"$out" || fail "no warning about the unreadable SSH config"
if grep -q 'sshd -T failed' <<<"$out"; then fail "'cannot look' was reported as a broken config"; fi
[[ ! -e /run/sshd ]] || fail "--check created /run/sshd"

# With the directory there, the same config is read normally.
mkdir /run/sshd
set +e
out=$(HARDEN_LANG=en bash "$here/harden.sh" --check 2>&1)
set -e
printf '%s\n' "$out" | sed -n '/^SSH/,/^Accounts/p'
grep -q 'PermitRootLogin' <<<"$out" || fail "the SSH config was not read with /run/sshd present"
grep -q 'Summary:' <<<"$out" || fail "no summary on the second run"
echo "OK: $PRETTY_NAME"
