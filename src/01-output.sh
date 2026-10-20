# ---------- output ----------
if [[ -t 1 ]]; then
  C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[34m'; C_BOLD=$'\e[1m'; C_0=$'\e[0m'
else
  C_R=; C_G=; C_Y=; C_B=; C_BOLD=; C_0=
fi
# T "русский" "english" — the one place that picks the interface language
T()     { if [[ $UI == ru ]]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }
info()  { echo "${C_B}[i]${C_0} $*"; }
ok()    { echo "${C_G}[✓]${C_0} $*"; }
warn()  { echo "${C_Y}[!]${C_0} $*"; }
die()   { echo "${C_R}[✗]${C_0} $*" >&2; exit 1; }
step()  { echo; echo "${C_BOLD}${C_B}==> $*${C_0}"; }
# A frame sized from the text. Drawn by hand, the side came out one column short of the
# corners. The length is taken in a UTF-8 locale: under LANG=C it would count bytes, and
# Cyrillic is two bytes per letter.
warn_box() {
  local msg=$1 bar LC_ALL=C.UTF-8
  printf -v bar '%*s' $(( ${#msg} + 4 )) ''
  bar=${bar// /═}
  echo "${C_BOLD}${C_Y}╔${bar}╗"
  echo "║  ${msg}  ║"
  echo "╚${bar}╝${C_0}"
}

# Is there a terminal to ask on? `[[ -r /dev/tty ]]` is true without one too — the device
# node is always readable — so only opening it tells.
have_tty() { { : </dev/tty; } 2>/dev/null; }
# What was typed before a question appeared is not an answer to it. A key pressed during
# the minutes of package installation stays in the terminal's buffer, and the next question
# took it — and the next question is "does the login on the new port work?", where a stray
# "y" closes the old port with nobody having tried the new one. Found by a test that
# pressed "y" once too often. -n makes read take the characters as they are, a line that
# was only half typed included.
discard_typeahead() {
  local _
  while read -r -s -t 0.1 -n 1000 _ </dev/tty; do :; done 2>/dev/null
  return 0
}
# Not every account lives in /home/<name> (a reused existing user may not)
home_of() { getent passwd "$1" 2>/dev/null | cut -d: -f6 || true; }

trap 'echo "${C_R}[✗] $(T "Ошибка в строке" "Error at line") $LINENO: $BASH_COMMAND${C_0}" >&2
      echo "$(T "Бэкап конфигов" "Config backup"): $BACKUP_DIR, $(T "лог" "log"): $LOG_FILE" >&2' ERR

# Questions are read from the terminal, so this also works as `curl ... | bash`
ask() {  # ask "question" "default" -> REPLY
  local q=$1 def=${2:-}
  discard_typeahead
  if [[ -n $def ]]; then read -r -p "$q [$def]: " REPLY </dev/tty; REPLY=${REPLY:-$def}
  else read -r -p "$q: " REPLY </dev/tty; fi
}
# ask_yn "question" y|n -> 0 on yes. Every yes/no question goes through here, so the hint
# looks the same everywhere: both letters, and what a bare Enter means said in words.
# "[Y/n]" on one question and "[y/N]" on the next read as two different formats to anyone
# who does not know that the capital marks the default.
ask_yn() {
  local q=$1 def=${2:-n} hint
  if [[ $def == y ]]; then hint="y/n, Enter — $(T "да" "yes")"; else hint="y/n, Enter — $(T "нет" "no")"; fi
  while :; do
    discard_typeahead
    # No terminal to read from is a "no": the questions guard changes, never the reverse
    read -r -p "$q [$hint]: " REPLY </dev/tty || return 1
    # Literal alternatives, not [дД] or ${REPLY,,}: in a C locale a bracket matches single
    # bytes, and "д" and "н" start with the same byte — "нет" would have read as yes
    case ${REPLY:-$def} in
      y*|Y*|д*|Д*) return 0 ;;
      n*|N*|н*|Н*) return 1 ;;
    esac
    echo "$(T "Ответь y (да) или n (нет)." "Please answer y (yes) or n (no).")"
  done
}
# Names for AllowUsers besides the new user: existing accounts only, never root. A name
# that does not exist would be a typo that locks someone out later.
valid_extra_users() {
  local u out=""
  for u in ${1//,/ }; do
    if [[ $u =~ ^[a-z_][a-z0-9_-]*$ && $u != root ]] && id -u "$u" &>/dev/null; then
      [[ $u == "${NEW_USER:-}" ]] || out+="$u "
    else
      warn "$(T "Пропущен пользователь для SSH:" "SSH user skipped:") $u" >&2
    fi
  done
  printf '%s' "${out% }"
}

env_yn() {  # env_yn VAR "question" default -> 0 on yes; an exported VAR skips the question
  local q=$2 def=$3 val=${!1:-}
  if [[ -n $val ]]; then [[ ${val,,} == y* ]]; return; fi
  ask_yn "$q" "$def"
}

usage() {
  cat <<'EOF'
harden.sh — Debian/Ubuntu server hardening

  sudo bash harden.sh                   full interactive setup
  sudo bash harden.sh --check           audit this server, change nothing (exit 1 on ✗)
  sudo bash harden.sh --setup-telegram  add Telegram alerts to a hardened server
  sudo bash harden.sh --ping off|on     stop / resume answering ping
  sudo bash harden.sh --lang en|ru      change the remembered interface language
  sudo bash harden.sh --install-status  only install the login summary (server-status)
  sudo bash harden.sh --refresh         apply this version's settings to a server that is
                                        already set up: no questions; accounts, SSH and the
                                        firewall are left as they are
  sudo bash harden.sh --answers         print the command that repeats the last setup
  sudo bash harden.sh --undo            take the setup back, from the backup made before it
  sudo HARDEN_LANG=ru bash harden.sh    interface in Russian / интерфейс на русском

After a full run the script is also installed as /usr/local/sbin/harden,
so later it is just: sudo harden --check

All options can be preset through environment variables — see the header of this file
or README.md.
EOF
}

