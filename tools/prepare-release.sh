#!/usr/bin/env bash
# prepare-release.sh VERSION — set the version in harden.sh and put the matching download
# URL and checksum into both READMEs. Then commit, tag vVERSION and push the tag: the
# Release workflow refuses to publish if any of the three disagree.
#
#   tools/prepare-release.sh 2026.10.0
#   git commit -am "Release v2026.10.0" && git tag v2026.10.0 && git push origin main v2026.10.0
set -euo pipefail

v=${1:?usage: tools/prepare-release.sh YYYY.MM.N}
[[ $v =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]+$ ]] || { echo "version must look like 2026.10.0" >&2; exit 1; }
cd "$(dirname "$0")/.."

# The release text is taken from CHANGELOG.md; a version without an entry is refused there,
# so it is refused here first.
grep -qx "## $v" CHANGELOG.md || { echo "CHANGELOG.md has no section '## $v' — write it first" >&2; exit 1; }

sed -i -E "s/^HARDEN_VERSION=\".*\"$/HARDEN_VERSION=\"$v\"/" harden.sh
bash -n harden.sh
# The checksum is taken after the version is written: the version is part of the file.
sum=$(sha256sum harden.sh | cut -d' ' -f1)

for f in README.md README.ru.md; do
  sed -i -E \
    -e "s#releases/download/v[0-9.]+/harden\.sh#releases/download/v$v/harden.sh#g" \
    -e "s#[0-9a-f]{64}  harden\.sh#$sum  harden.sh#g" \
    -e "s#badge/version-[0-9.]+-#badge/version-$v-#" "$f"
  grep -q "$sum" "$f" || { echo "$f: no checksum line to update" >&2; exit 1; }
done

echo "harden.sh $v"
echo "sha256    $sum"
