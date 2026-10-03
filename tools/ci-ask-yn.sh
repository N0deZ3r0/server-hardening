#!/usr/bin/env bash
# Run by CI. Every yes/no question of harden.sh goes through ask_yn, so this is the one
# place where their look and their verdict are decided. The answers are typed on a real
# pseudo-terminal (script(1)), in both languages and in a C locale, where Cyrillic is
# just bytes.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
fail() { echo "FAIL: $*" >&2; exit 1; }

# run ANSWERS DEFAULT LANG LOCALE -> everything the terminal showed
# The answers are typed one at a time, each after its question has had time to appear:
# what is typed before a question is on the screen is thrown away, on purpose (see the end).
run() {
  ( sleep 0.7; printf '%b' "$1" | while IFS= read -r a; do printf '%s\n' "$a"; sleep 0.7; done || true ) \
    | LC_ALL=$4 script -qec \
        "bash -c 'source \"$here/harden.sh\"; UI=$3; if ask_yn Question $2; then echo RESULT=yes; else echo RESULT=no; fi'" \
        /dev/null | tr -d '\r'
}

# expect WANT ANSWERS DEFAULT [LANG] [LOCALE]
expect() {
  local out
  out=$(run "$2" "$3" "${4:-en}" "${5:-C.UTF-8}")
  if [[ $out != *"RESULT=$1"* ]]; then
    printf '%s\n' "$out"
    fail "answers '$2', default $3, ${4:-en}, ${5:-C.UTF-8}: expected $1"
  fi
}

# No hint is written by hand anywhere else: one format for the whole script.
n=$(grep -v '^[[:space:]]*#' "$here/harden.sh" | grep -c 'Y/n\|y/N' || true)
[[ $n == 0 ]] || fail "a hand-written [Y/n] or [y/N] hint outside ask_yn"

# The hint has the same shape for both defaults and says what Enter does, in words.
out=$(run '\n' y en C.UTF-8); [[ $out == *'[y/n, Enter — yes]'* ]] || { printf '%s\n' "$out"; fail "hint for a yes default"; }
out=$(run '\n' n en C.UTF-8); [[ $out == *'[y/n, Enter — no]'* ]]  || { printf '%s\n' "$out"; fail "hint for a no default"; }
out=$(run '\n' y ru C.UTF-8); [[ $out == *'[y/n, Enter — да]'* ]]  || { printf '%s\n' "$out"; fail "hint, Russian, yes default"; }
out=$(run '\n' n ru C.UTF-8); [[ $out == *'[y/n, Enter — нет]'* ]] || { printf '%s\n' "$out"; fail "hint, Russian, no default"; }

# Enter takes the default.
expect yes '\n' y
expect no  '\n' n

# An answer beats the default, in either alphabet and either case.
for loc in C.UTF-8 C; do
  expect yes 'y\n'   n en "$loc"
  expect yes 'Y\n'   n en "$loc"
  expect yes 'yes\n' n en "$loc"
  expect yes 'д\n'   n ru "$loc"
  expect yes 'Да\n'  n ru "$loc"
  expect yes 'ДА\n'  n ru "$loc"
  expect no  'n\n'   y en "$loc"
  expect no  'No\n'  y en "$loc"
  # "н" and "д" share their first byte: in a C locale a careless pattern takes "нет" for yes
  expect no  'н\n'   y ru "$loc"
  expect no  'Нет\n' y ru "$loc"
done

# Anything else is asked again instead of being taken for a "no".
out=$(run 'maybe\ny\n' n en C.UTF-8)
[[ $out == *'Please answer y (yes) or n (no).'* && $out == *'RESULT=yes'* ]] \
  || { printf '%s\n' "$out"; fail "an unclear answer was not asked again"; }
out=$(run 'ok\nн\n' y ru C.UTF-8)
[[ $out == *'Ответь y (да) или n (нет).'* && $out == *'RESULT=no'* ]] \
  || { printf '%s\n' "$out"; fail "an unclear answer was not asked again (Russian)"; }

# What is typed before the question appears is not an answer to it. A key pressed while
# packages were being installed used to answer the next question — which is "does the
# login on the new port work?", and a stray "y" there closes the old port with nobody
# having tried the new one. Here "y" is in the terminal before the question is asked, a
# whole line and then half a line; the answer given afterwards is "n".
for ahead in 'y\n' 'y' '\n\ny\n'; do
  out=$( ( printf '%b' "$ahead"; sleep 2.5; printf 'n\n'; sleep 0.7 ) | LC_ALL=C.UTF-8 script -qec \
          "bash -c 'source \"$here/harden.sh\"; UI=en; sleep 1; if ask_yn Question y; then echo RESULT=yes; else echo RESULT=no; fi'" \
          /dev/null | tr -d '\r' )
  [[ $out == *'RESULT=no'* ]] || { printf '%s\n' "$out"; fail "what was typed before the question ('$ahead') was taken for the answer"; }
done

echo "OK: yes/no questions"
