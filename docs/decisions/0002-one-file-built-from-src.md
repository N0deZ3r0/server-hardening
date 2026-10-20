# 0002 — Edited in `src/`, shipped as one file

**Status:** in force since 2026.10.29.

## The problem

The script is around 2,700 lines. As one file it is hard to find one's way in and hard to
review, and every change shows up as a change to "the script". But one file is also the
point: `curl … && sudo bash harden.sh` has to work on a fresh server with nothing else,
the release is one file with one checksum, and CI and the VM test run exactly that file.

## The decision

- The script is edited in `src/NN-name.sh`: plain pieces of it, cut at its section
  markers, in the order of their numbers.
- `tools/build.sh` puts them together by concatenation and nothing else, so the result is
  a script anyone can read without knowing there was a build.
- `harden.sh` stays in the repository. CI and the release workflow run
  `tools/build.sh --check` and refuse a `harden.sh` that is not what `src/` builds.
- `tools/prepare-release.sh` writes the version into `src/00-header.sh` and builds.

## Consequences

- A change is a change to one area of the script, and is reviewed as one.
- ShellCheck runs on the built file: the pieces are not scripts of their own.
- Unit tests (`tests/*.bats`) source the built file and call single functions.
