# ---------- 5. firewall ----------
setup_firewall() {
  step "Firewall (UFW)"
  # No reset — rules added by hand survive a re-run. Only the incoming default is set: the
  # outgoing and routed ones are what they are on a fresh system (allow, deny), and on a
  # server where the admin has changed them — routed traffic allowed for a VPN, say — a
  # second run must not put them back.
  ufw default deny incoming
  # UFW re-applies its own sysctl file on every start, after sysctl.d — keep the keys it
  # also sets in line with ours, or it quietly turns them back (it ships log_martians=0)
  ufw_sysctl_set net/ipv4/conf/all/log_martians 1
  ufw_sysctl_set net/ipv4/conf/default/log_martians 1
  local p
  # The new port is never added as a plain allow: UFW stops at the first match, and a plain
  # allow before the limit rule would switch rate limiting off (re-run with the same port)
  for p in $CURRENT_SSH_PORTS; do
    [[ $p == "$SSH_PORT" ]] && continue
    ufw allow "$p/tcp" comment 'SSH (temporary)' >/dev/null
  done
  # The admin is not rate-limited: this rule has to precede the limit rule, since UFW stops
  # at the first match. prepend, not a plain allow — on a re-run with a new address a plain
  # allow landed after the limit rule that was already there, and did nothing.
  # The exception an earlier run made goes first: set up again from another address, or
  # with another port, the old rule stayed for good.
  local rule
  while read -r rule; do
    # shellcheck disable=SC2086  # a rule the way ufw prints it: words, to be split
    ufw delete $rule >/dev/null 2>&1 || true
  done < <(ufw show added 2>/dev/null | sed -n "s/^ufw \(allow from .*\) comment 'SSH admin'\$/\1/p")
  if [[ -n $ADMIN_IP ]]; then
    # UFW's refusal (an IPv6 address with IPv6 switched off in UFW, say) costs the exception,
    # not the setup: the limit rule below lets the admin in all the same
    ufw prepend allow from "$ADMIN_IP" to any port "$SSH_PORT" proto tcp comment 'SSH admin' >/dev/null 2>&1 \
      || warn "$(T "UFW не принял правило для $ADMIN_IP — вход с него ограничен по частоте, как для всех" \
                   "UFW refused the rule for $ADMIN_IP — logins from it are rate-limited like everyone's")"
  fi
  ufw limit "$SSH_PORT/tcp" comment 'SSH' >/dev/null
  local -a extra
  IFS=, read -ra extra <<<"$EXTRA_PORTS"
  for p in "${extra[@]}"; do
    [[ -z $p ]] && continue
    # UFW has the last word (a range needs a protocol, a port has to be below 65536). Its
    # refusal is a skipped port, not the end of the setup.
    if [[ $p =~ ^[0-9]+(:[0-9]+)?(/(tcp|udp))?$ ]] && ufw allow "$p" >/dev/null 2>&1; then :
    else warn "$(T "Порт пропущен (диапазону нужен протокол: 8000:8100/tcp):" "Port skipped (a range needs a protocol: 8000:8100/tcp):") $p"; fi
  done
  ufw logging low
  ufw --force enable
  ok "$(T "UFW включён" "UFW enabled")"
}

# fail2ban 1.x prints "'allowipv6' not defined" on every command until the option is set
# explicitly. Older versions have no such option; an existing fail2ban.local is the admin's.
fail2ban_set_ipv6() {
  grep -qs 'allowipv6' /etc/fail2ban/fail2ban.conf || return 0
  [[ ! -e /etc/fail2ban/fail2ban.local ]] || return 0
  printf '[DEFAULT]\nallowipv6 = auto\n' >/etc/fail2ban/fail2ban.local
}

F2B_JAIL=/etc/fail2ban/jail.d/99-hardening.local

# jail.local the way this script wrote it up to 2026.10.14: ours, and replaced by the file
# above. A jail.local with anything else in it is the admin's and is not touched.
jail_local_is_ours() {
  local f=/etc/fail2ban/jail.local
  [[ -f $f ]] || return 1
  grep -q '^bantime\.maxtime    = 4w$' "$f" && grep -q '^mode     = aggressive$' "$f" \
    && [[ -z $(grep -E '^\[' "$f" | grep -vxE '\[(DEFAULT|sshd|recidive)\]') ]]
}

setup_fail2ban() {
  step "fail2ban"
  fail2ban_set_ipv6
  # jail.local belongs to the admin: jails for nginx, postfix and the rest live there, and
  # writing it whole wiped them. Ours is a .local file in jail.d, which fail2ban reads
  # after jail.local — the two SSH jails get these settings whatever came before, and
  # nothing is set in [DEFAULT], so no other jail changes its backend, action or ban time.
  if [[ -f /etc/fail2ban/jail.local ]]; then
    mkdir -p "$BACKUP_DIR"
    cp -a /etc/fail2ban/jail.local "$BACKUP_DIR/jail.local" 2>/dev/null || true
    if jail_local_is_ours; then
      rm -f /etc/fail2ban/jail.local
    else
      info "$(T "Твой /etc/fail2ban/jail.local оставлен как есть; защита SSH записана в $F2B_JAIL" \
                "Your /etc/fail2ban/jail.local is left as it is; SSH protection is written to $F2B_JAIL")"
    fi
  fi
  mkdir -p /etc/fail2ban/jail.d
  cat >"$F2B_JAIL" <<EOF
# Written by harden.sh. Read after jail.local, so these values hold for the two jails
# below; nothing else is set here.
[sshd]
enabled   = true
backend   = systemd
port      = $SSH_PORT
mode      = aggressive
banaction = ufw
ignoreip  = 127.0.0.1/8 ::1 ${ADMIN_IP}
bantime   = 1h
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 4w
findtime  = 10m
maxretry  = 4

[recidive]
enabled   = true
backend   = auto
logpath   = /var/log/fail2ban.log
banaction = ufw
ignoreip  = 127.0.0.1/8 ::1 ${ADMIN_IP}
bantime   = 4w
findtime  = 1d
maxretry  = 3
EOF
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban || true
  # "Restarted" is not "protecting": with someone else's jail.local in play, ask the
  # daemon whether the sshd jail is really up
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    fail2ban-client status sshd &>/dev/null && break
    sleep 1
  done
  if fail2ban-client status sshd &>/dev/null; then
    ok "$(T "fail2ban включён (статус: fail2ban-client status sshd)" "fail2ban enabled (status: fail2ban-client status sshd)")"
  else
    warn "$(T "fail2ban не поднял защиту SSH — смотри: journalctl -u fail2ban -n 30" "fail2ban did not bring up SSH protection — see: journalctl -u fail2ban -n 30")"
  fi
}

