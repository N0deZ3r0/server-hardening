# ---------- ping ----------
# Only echo requests are ignored — path MTU discovery and IPv6 neighbour discovery use
# other ICMP types and keep working.
#
# The setting has to live in two places. Our own sysctl.d file is what the kernel reads at
# boot; but UFW ships /etc/ufw/sysctl.conf with icmp_echo_ignore_all=0 and re-applies it
# every time it starts, after sysctl.d. With only our file, the first full run reported
# "no longer answers ping" and the server went on answering (seen live). So the same
# value is written into UFW's file too.
PING_SYSCTL=/etc/sysctl.d/99-hardening-ping.conf
UFW_SYSCTL=/etc/ufw/sysctl.conf

ufw_sysctl_set() {  # ufw_sysctl_set net/ipv4/key value — UFW's own syntax uses slashes
  [[ -f $UFW_SYSCTL ]] || return 0
  if grep -qE "^[#[:space:]]*$1=" "$UFW_SYSCTL"; then
    sed -i -E "s|^[#[:space:]]*$1=.*|$1=$2|" "$UFW_SYSCTL"
  else
    echo "$1=$2" >>"$UFW_SYSCTL"
  fi
}

set_ping() {  # set_ping off|on
  case ${1:-} in
    off)
      cat >"$PING_SYSCTL" <<'EOF'
# harden.sh: do not answer ping (ICMP echo). Undo: sudo harden --ping on
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_all = 1
EOF
      chmod 644 "$PING_SYSCTL"
      ufw_sysctl_set net/ipv4/icmp_echo_ignore_all 1
      # -e: the IPv6 key is missing on old kernels and where IPv6 is disabled
      sysctl -e -q -p "$PING_SYSCTL" 2>/dev/null \
        || warn "$(T "Не удалось применить (нормально для контейнеров)" "Could not apply it (normal in containers)")"
      [[ $(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null) == 1 ]] \
        && ok "$(T "Сервер не отвечает на ping (вернуть: sudo harden --ping on)" "The server no longer answers ping (undo: sudo harden --ping on)")"
      ;;
    on)
      rm -f "$PING_SYSCTL"
      ufw_sysctl_set net/ipv4/icmp_echo_ignore_all 0
      sysctl -q -w net.ipv4.icmp_echo_ignore_all=0 2>/dev/null || true
      sysctl -e -q -w net.ipv6.icmp.echo_ignore_all=0 2>/dev/null || true
      ok "$(T "Сервер отвечает на ping" "The server answers ping")"
      ;;
    *) die "$(T "Использование: sudo harden --ping off|on" "Usage: sudo harden --ping off|on")" ;;
  esac
  return 0
}

# note_if_enabled unit — the name of a unit that is enabled now goes into the backup:
# --undo turns back on what the setup switched off, and only what was on before it.
note_if_enabled() {
  [[ $(systemctl is-enabled "$1" 2>/dev/null || true) == enabled* ]] || return 1
  mkdir -p "$BACKUP_DIR"
  echo "$1" >>"$BACKUP_DIR/disabled-services"
}

# Ubuntu's crash reporter. Every time it starts — so at every boot, after sysctl.d has
# been applied — it sets fs.suid_dumpable=2 and points kernel.core_pattern at itself,
# which turns memory dumps of privileged programs back on. Seen live: the audit passed
# before the reboot and warned about fs.suid_dumpable after it.
disable_apport() {
  systemctl cat apport.service &>/dev/null || return 0
  local u
  # Stop, disable and mask as separate steps. apport.service is generated from an init
  # script, and `disable --now` on such a unit skips the stop when the disable half fails
  # — it stayed active through exactly that in CI. The mask is what holds across boots.
  for u in apport.service apport-autoreport.path apport-autoreport.timer apport-forward.socket; do
    note_if_enabled "$u" || true
    systemctl stop "$u" &>/dev/null || true
    systemctl disable "$u" &>/dev/null || true
  done
  systemctl mask apport.service &>/dev/null || true
  [[ -f /etc/default/apport ]] && sed -i 's/^enabled=.*/enabled=0/' /etc/default/apport
  # Stopping it normally restores both values; set them anyway rather than rely on that
  sysctl -q -w fs.suid_dumpable=0 2>/dev/null || true
  if grep -qs apport /proc/sys/kernel/core_pattern; then
    sysctl -q -w kernel.core_pattern=core 2>/dev/null || true
  fi
  info "$(T "Отключён apport (сборщик дампов памяти)" "Disabled apport (crash dump collector)")"
}

