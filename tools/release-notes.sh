#!/usr/bin/env bash
# release-notes.sh vVERSION — the text of a GitHub release: that version's section of
# CHANGELOG.md, then the install command with the checksum of harden.sh as tagged.
#
# Used by the Release workflow for a new release, and by the Release notes workflow to
# bring the text of the published ones in line with CHANGELOG.md — which is how a version
# found to be broken later gets its "Known problem" line.
set -euo pipefail

tag=${1:?usage: tools/release-notes.sh vYYYY.MM.N}
v=${tag#v}
cd "$(dirname "$0")/.."

section=$(awk -v h="## $v" '$0 == h {f=1; next} /^## /{f=0} f' CHANGELOG.md)
section=${section#$'\n'}
[[ -n ${section//[[:space:]]/} ]] || { echo "CHANGELOG.md has no section '## $v'" >&2; exit 1; }

sum=$(git show "$tag:harden.sh" | sha256sum | cut -d' ' -f1)
commit=$(git rev-list -n1 "$tag")
repo=${GITHUB_REPOSITORY:-N0deZ3r0/server-hardening}

cat <<EOF
$section

\`\`\`
$sum  harden.sh
\`\`\`

Install — the checksum is verified before anything runs:

\`\`\`bash
curl -fsSLo harden.sh https://github.com/$repo/releases/download/$tag/harden.sh && echo "$sum  harden.sh" | sha256sum -c - && sudo bash harden.sh
\`\`\`

Built from $commit. With the GitHub CLI the provenance can be checked too:

\`\`\`bash
gh attestation verify harden.sh --repo $repo
\`\`\`
EOF
