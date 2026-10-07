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
# Package lists first. Twice a job of this test never reached the script: from a hosted
# runner one of the addresses behind archive.ubuntu.com now and then does not answer, and
# apt sits on it — ten minutes without a line of output the first time, until the job was
# cancelled. So the default mirror gets a short while, and if no lists have come by then,
# the provider's own mirror is used: the same archive, and what the runner's own system is
# pointed at for this very reason.
apt=(-o Acquire::Retries=2 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o Acquire::ForceIPv4=true)
lists() {   # lists SECONDS — fresh package lists, and proof that they are there
  timeout "$1" apt-get "${apt[@]}" update -q >/dev/null 2>&1 && apt-cache show openssh-server >/dev/null 2>&1
}
if ! lists 75; then
  echo "the default mirror did not deliver the package lists in 75 s — trying azure.archive.ubuntu.com"
  sed -i -E 's#//(archive|security)\.ubuntu\.com#//azure.archive.ubuntu.com#g' \
    /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
  lists 240 || fail "no package lists from the default mirror or from the provider's — nothing of the script was run"
fi
timeout 300 apt-get "${apt[@]}" install -y -q --no-install-recommends openssh-server iproute2 procps util-linux >/dev/null
# shellcheck disable=SC1091
. /etc/os-release
echo "== $PRETTY_NAME"

# Every package the setup installs has to exist on this release: a renamed or dropped
# package would otherwise stop a real setup half-way.
pk=$(bash -c "source '$here/harden.sh'; setup_packages" | xargs)
# shellcheck disable=SC2086  # one argument per package
if ! sim=$(apt-get install -s --no-install-recommends $pk 2>&1); then
  printf '%s\n' "$sim" | tail -5
  fail "a package the setup installs is not available on $PRETTY_NAME"
fi
echo "packages available: $pk"

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
