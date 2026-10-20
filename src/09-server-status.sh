# ---------- login summary ----------
install_server_status() {
  [[ ${SERVER_STATUS:-yes} == yes ]] || return 0
  step "$(T "Сводка о сервере при входе (server-status)" "Login summary (server-status)")"
  cat >/usr/local/bin/server-status <<'STATUS_EOF'
#!/bin/bash
# server-status — server summary shown at SSH login (installed by harden.sh).
# Run it any time: server-status
RED='\033[0;31m'; GREEN='\033[0;32m'; GOLD='\033[38;5;214m'; YELLOW='\033[38;5;226m'
CYAN='\033[0;36m'; LIME='\033[38;5;118m'; NC='\033[0m'
line() { echo -e "${CYAN}$1${NC}"; }
kv()   { echo -e " ${YELLOW}$1:${NC} $2"; }
pct()  {  # free %: red below 10, yellow below 25
  if   [ "$1" -lt 10 ]; then echo -e "${RED}$1%${NC}"
  elif [ "$1" -lt 25 ]; then echo -e "${YELLOW}$1%${NC}"
  else echo -e "${GREEN}$1%${NC}"; fi
}
svc()  {  # installed services only
  # "Installed" is decided by the unit file on disk, not by `systemctl cat`: that fails
  # for a normal user as soon as one drop-in of the unit is unreadable to them, and every
  # such service then vanished from the list (seen live: only ufw was left).
  local f state found=""
  for f in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    [ -e "$f/$1.service" ] && { found=1; break; }
  done
  [ -n "$found" ] || return 0
  state=$(systemctl is-active "$1" 2>/dev/null)
  case $state in
    active) printf " %-10s %b\n" "$1" "${GREEN}✓${NC}" ;;
    # Right after boot some services take a while (CrowdSec: ~20 s) — not a failure
    activating|reloading) printf " %-10s %b\n" "$1" "${YELLOW}… starting${NC}" ;;
    # No answer from systemd at all: say so rather than hide the service or call it dead
    "") printf " %-10s %b\n" "$1" "${YELLOW}? no answer yet${NC}" ;;
    *) printf " %-10s %b\n" "$1" "${RED}✗ ${state}${NC}" ;;
  esac
}

LOCAL_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')
OS=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")
USER_NAME=$(id -un)
if [ "$USER_NAME" = root ]; then USER_C="${RED}${USER_NAME}${NC}"; else USER_C="${GOLD}${USER_NAME}${NC}"; fi
# /proc/meminfo, not `free`: under a non-English locale free prints a translated "Mem:"
# and the summary came out with empty numbers and an arithmetic error at every login
read -r RAM_TOTAL RAM_AVAIL < <(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{printf "%d %d\n", t/1024, a/1024}' /proc/meminfo)
read -r DISK_SIZE DISK_AVAIL DISK_USED < <(df -h --output=size,avail,pcent / | awk 'NR==2{print $1, $2, $3}')

# Updates: Ubuntu's cache (instant), otherwise an apt simulation capped at 3 s
UPDATES=""
if [ -r /var/lib/update-notifier/updates-available ]; then
  UPDATES=$(grep -oE '^[0-9]+ updates? can be applied' /var/lib/update-notifier/updates-available | grep -oE '^[0-9]+')
  UPDATES=${UPDATES:-0}
fi
[ -n "$UPDATES" ] || UPDATES=$(timeout 3 apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst')

line "========================================"
line "       🖥️  SYSTEM STATUS"
line "========================================"
kv "IP"       "$LOCAL_IP"
kv "Hostname" "${LIME}$(hostname)${NC}"
kv "OS"       "$OS ($(uname -r))"
kv "User"     "$USER_C"
kv "Loadavg"  "$(cut -d' ' -f1-3 /proc/loadavg)"
kv "Uptime"   "$(LC_ALL=C uptime -p | sed 's/^up //')"
if [ "${UPDATES:-0}" -gt 0 ]; then kv "Updates" "${RED}${UPDATES}${NC}"; else kv "Updates" "${GREEN}0${NC}"; fi
[ -f /var/run/reboot-required ] && kv "Reboot" "${RED}required (sudo reboot)${NC}"
line "----------------------------------------"
kv "CPU"      "$(nproc) cores"
kv "RAM"      "${RAM_TOTAL} MB total, ${RAM_AVAIL} MB free ($(pct $(( RAM_AVAIL * 100 / (RAM_TOTAL > 0 ? RAM_TOTAL : 1) ))))"
# df prints "-" for a root it cannot size (some containers): no percentage then, rather
# than an arithmetic error at every login
DISK_PCT=${DISK_USED%\%}
case $DISK_PCT in ''|*[!0-9]*) DISK_FREE="" ;; *) DISK_FREE=" ($(pct $(( 100 - DISK_PCT ))))" ;; esac
kv "Disk /"   "${DISK_SIZE:-?} total, ${DISK_AVAIL:-?} free${DISK_FREE}"
kv "Gateway"  "$(ip route show default 2>/dev/null | awk '{print $3; exit}')"
line "----------------------------------------"
if grep -qs '^ENABLED=yes' /etc/ufw/ufw.conf; then printf " %-10s %b\n" ufw "${GREEN}✓${NC}"
elif command -v ufw >/dev/null; then printf " %-10s %b\n" ufw "${RED}✗ disabled${NC}"; fi
for s in ssh fail2ban crowdsec auditd nginx x-ui docker; do svc "$s"; done
line "========================================"
STATUS_EOF
  chmod 755 /usr/local/bin/server-status

  # Shown at SSH login once per session, not in every tmux window
  cat >/etc/profile.d/99-server-status.sh <<'HOOK_EOF'
# Server summary at SSH login (harden.sh). Disable: sudo rm /etc/profile.d/99-server-status.sh
case $- in *i*) ;; *) return 0 ;; esac
if [ -n "${SSH_CONNECTION:-}" ] && [ -z "${TMUX:-}" ] && [ -z "${SERVER_STATUS_SHOWN:-}" ] && [ -x /usr/local/bin/server-status ]; then
  export SERVER_STATUS_SHOWN=1
  /usr/local/bin/server-status
fi
HOOK_EOF
  chmod 644 /etc/profile.d/99-server-status.sh   # sourced by every user's login shell

  # Drop the whole stock greeting (Welcome, ESM, ads, legal) — the summary replaces it.
  # dpkg-statoverride instead of chmod or editing: the mode survives package upgrades,
  # where a plain chmod is undone the next time the package is updated.
  local f real u home
  for f in /etc/update-motd.d/*; do
    [[ -e $f ]] || continue
    real=$(readlink -f "$f")
    if dpkg -S "$real" &>/dev/null; then
      # 0644 = readable but not executable: pam_motd's run-parts skips it. Undo with
      # dpkg-statoverride --remove <file> && chmod 755 <file>
      dpkg-statoverride --list "$real" &>/dev/null || dpkg-statoverride --update --add root root 0644 "$real"
    else
      chmod -x "$real"
    fi
  done
  [[ -f /etc/default/motd-news ]] && sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news
  # Debian: static /etc/motd with the license text
  grep -qs 'ABSOLUTELY NO WARRANTY' /etc/motd && : >/etc/motd
  # Ubuntu one-time hints ("free software…", "To run a command as administrator…")
  mkdir -p /etc/skel/.cache
  touch /etc/skel/.sudo_as_admin_successful /etc/skel/.cache/motd.legal-displayed
  while IFS=: read -r u _ _ _ _ home _; do
    [[ -d $home && $home == /home/* ]] || continue
    # As that user, not as root: written by root, a file in a directory someone else owns
    # lands wherever a symlink there points (~/.cache -> /etc/…), and comes out owned by them
    runuser -u "$u" -- sh -c 'cd "$1" && mkdir -p -m 700 .cache && : >.sudo_as_admin_successful && : >.cache/motd.legal-displayed' \
      sh "$home" </dev/null &>/dev/null || true
  done < <(awk -F: '$3>=1000 && $3<60000' /etc/passwd)
  ok "$(T "Сводка будет показываться при входе вместо стандартного приветствия. Вручную: server-status" \
          "The summary replaces the stock login greeting. Run it any time: server-status")"
}

