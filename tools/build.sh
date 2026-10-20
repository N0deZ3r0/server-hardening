#!/usr/bin/env bash
# build.sh — put harden.sh together from src/, in the order of the file names.
#
# harden.sh stays in the repository as one file: it is what the README's command
# downloads, what CI and the releases test, and it has to run without anything else.
# src/ is where it is edited; the parts are plain pieces of one script, cut at its
# section markers, so the build is their concatenation and nothing more.
#
#   tools/build.sh           write harden.sh
#   tools/build.sh --check   fail if harden.sh is not what src/ builds (CI, releases)
set -euo pipefail
cd "$(dirname "$0")/.."

built=$(mktemp)
trap 'rm -f "$built"' EXIT
cat src/[0-9][0-9]-*.sh >"$built"

case ${1:-} in
  --check)
    if ! cmp -s "$built" harden.sh; then
      echo "harden.sh is not what src/ builds — edit src/, then run tools/build.sh" >&2
      diff -u harden.sh "$built" | head -40 >&2 || true
      exit 1
    fi ;;
  "")
    cat "$built" >harden.sh     # into the existing file: its mode (755) stays
    bash -n harden.sh ;;
  *) echo "usage: tools/build.sh [--check]" >&2; exit 2 ;;
esac
