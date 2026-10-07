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
# The packages this test needs, first. Several jobs of it never reached the script: from a
# hosted runner an address behind archive.ubuntu.com, or behind the provider's own mirror,
# now and then does not answer, and apt sits on it — ten minutes without a line of output
# the first time, until the job was cancelled. So each attempt is bounded, and the two
# mirrors (the same archive) are tried in turn. If none of that brings the packages, the
# job fails saying so: nothing of the script was run, and nothing is claimed about it.
apt=(-o Acquire::Retries=2 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o Acquire::ForceIPv4=true)
cp -a /etc/apt /tmp/apt.as-shipped
mirror() {   # mirror default|azure — only an Ubuntu image has the second one
  rm -rf /etc/apt && cp -a /tmp/apt.as-shipped /etc/apt
  [[ $1 == default ]] || sed -i -E 's#//(archive|security)\.ubuntu\.com#//azure.archive.ubuntu.com#g' \
    /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
}
got=no
for m in default azure default azure; do
  mirror "$m"
  if timeout 75 apt-get "${apt[@]}" update -q >/dev/null 2>&1 && apt-cache show openssh-server >/dev/null 2>&1 &&
     timeout 150 apt-get "${apt[@]}" install -y -q --no-install-recommends openssh-server iproute2 procps util-linux >/dev/null 2>&1
  then got=yes; break; fi
  echo "the packages did not arrive through the $m mirror — trying the other way"
  sleep 8
done
[[ $got == yes ]] || fail "no packages from either mirror after four attempts — the script itself was not run"
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
