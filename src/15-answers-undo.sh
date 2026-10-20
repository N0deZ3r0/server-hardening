# ---------- saved answers: --answers, --refresh, --undo ----------
# The answers of the last setup. --refresh re-applies settings from them without asking,
# --answers prints the command that repeats the setup. No secret is kept here: the bot
# token stays in telegram.conf, and the password is not stored anywhere.
STATE_FILE=/etc/harden/setup.conf
ANSWER_VARS="NEW_USER SSH_PORT SSH_PUBKEY EXTRA_PORTS ADMIN_IP AUTO_REBOOT REBOOT_TIME LOCK_ROOT LOCK_OTHER_USERS SSH_EXTRA_USERS INSTALL_CROWDSEC RUN_LYNIS TELEGRAM TG_REPORT_TIME DISABLE_PING SERVER_STATUS"

save_answers() {
  local v
  install -d -m 700 /etc/harden
  {
    echo "# Answers of the last setup — harden.sh $HARDEN_VERSION, $(date -Is)."
    echo "# Read by: sudo harden --refresh, sudo harden --answers."
    for v in $ANSWER_VARS; do printf '%s=%q\n' "$v" "${!v:-}"; done
  } >"$STATE_FILE"
  chmod 600 "$STATE_FILE"
}

# A choice changed after the setup by one of the small commands (--ping, --setup-telegram,
# --install-status) is recorded with the answers, or --answers would go on printing the old one.
set_saved_answer() {  # set_saved_answer VAR yes|no
  [[ -f $STATE_FILE ]] || return 0
  if grep -q "^$1=" "$STATE_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$STATE_FILE"
  else echo "$1=$2" >>"$STATE_FILE"; fi
}

shq() { printf "'%s'" "${1//\'/\'\\\'\'}"; }   # 'a value', safe to paste into a shell

# The command that repeats the setup with the same answers. What is still asked then: the
# password for the new user, the bot token, and the login check — on purpose.
print_answers() {
  local v line="sudo HARDEN_LANG=$UI"
  for v in NEW_USER SSH_PORT SSH_PUBKEY EXTRA_PORTS ADMIN_IP AUTO_REBOOT REBOOT_TIME LOCK_ROOT LOCK_OTHER_USERS \
           SSH_EXTRA_USERS INSTALL_CROWDSEC RUN_LYNIS TELEGRAM DISABLE_PING; do
    [[ $v == REBOOT_TIME && ${AUTO_REBOOT:-no} != yes ]] && continue
    [[ $v == SSH_EXTRA_USERS && -z ${SSH_EXTRA_USERS:-} ]] && continue
    line+=" $v=$(shq "${!v:-}")"
  done
  echo "$line bash harden.sh"
}

# A server set up before the answers were saved: read them back from what the setup left.
derive_answers() {
  local h v
  NEW_USER=$(awk '$1=="AllowUsers"{print $2; exit}' "$SSHD_DROPIN" 2>/dev/null || true)
  SSH_EXTRA_USERS=$(awk '$1=="AllowUsers"{$1=$2=""; sub(/^ +/,""); print; exit}' "$SSHD_DROPIN" 2>/dev/null || true)
  SSH_PORT=$(awk '$1=="Port"{p=$2} END{print p}' "$SSHD_DROPIN" 2>/dev/null || true)
  # One file at a time: given a file that is not there, awk stops before it reads the next
  # one, and a server set up by an older version (jail.local only) lost its whitelist
  ADMIN_IP=""
  for h in "$F2B_JAIL" /etc/fail2ban/jail.local; do
    [[ -r $h ]] || continue
    ADMIN_IP=$(awk '$1=="ignoreip"{print $5; exit}' "$h" || true)
    break
  done
  AUTO_REBOOT=no; REBOOT_TIME=04:00
  if grep -qs 'Automatic-Reboot "true"' /etc/apt/apt.conf.d/52-hardening-unattended; then AUTO_REBOOT=yes; fi
  v=$(sed -n 's/.*Automatic-Reboot-Time "\(.*\)";.*/\1/p' /etc/apt/apt.conf.d/52-hardening-unattended 2>/dev/null || true)
  [[ -z $v ]] || REBOOT_TIME=$v
  DISABLE_PING=no; [[ -e $PING_SYSCTL ]] && DISABLE_PING=yes
  SERVER_STATUS=no; [[ -x /usr/local/bin/server-status ]] && SERVER_STATUS=yes
  LOCK_ROOT=no; [[ $(passwd -S root 2>/dev/null | awk '{print $2}') == L ]] && LOCK_ROOT=yes
  LOCK_OTHER_USERS=yes
  INSTALL_CROWDSEC=no; systemctl cat crowdsec.service &>/dev/null && INSTALL_CROWDSEC=yes
  RUN_LYNIS=yes
  TELEGRAM=no; [[ -s /etc/harden/telegram.conf ]] && TELEGRAM=yes
  TG_REPORT_TIME=$(saved_report_time)
  EXTRA_PORTS=""
  h=$(home_of "${NEW_USER:-root}")
  SSH_PUBKEY=$(cat "$h/.ssh/authorized_keys" 2>/dev/null || true)
  return 0
}

load_answers() {
  [[ -f $SSHD_DROPIN ]] || die "$(T "Этот сервер не настраивался через harden.sh — сначала полная настройка: sudo bash harden.sh" \
                                    "This server was not set up by harden.sh — run the full setup first: sudo bash harden.sh")"
  # What the server itself shows comes first, and the saved answers go over it. A file that
  # lacks a line — edited by hand, or written by another version — then leaves no variable
  # unset for a later step to stop on, half-way through a refresh.
  derive_answers
  if [[ -r $STATE_FILE ]]; then
    # shellcheck disable=SC1090  # written by save_answers, root-only
    . "$STATE_FILE"
  fi
  [[ -n ${NEW_USER:-} && -n ${SSH_PORT:-} ]] \
    || die "$(T "Не удалось прочитать текущую настройку (пользователь, порт SSH)" "Could not read the current setup (user, SSH port)")"
}

# Apply this version's settings to a server that is already set up, without questions.
# Accounts, SSH and the firewall are left as they are: those are the parts where a mistake
# costs access, and they change only in the full setup, with its login check.
run_refresh() {
  local api v hook=/etc/profile.d/99-server-status.sh keep_hook=yes
  load_answers
  # What was switched by hand after the setup stays the way it is. The saved answers are
  # those of the setup: going by them, a refresh turned ping back on after `--ping off`,
  # brought back the login hook removed the way its own first line says, and moved the
  # daily report back to 09:00.
  DISABLE_PING=no; [[ -e $PING_SYSCTL ]] && DISABLE_PING=yes
  [[ -x /usr/local/bin/server-status ]] || SERVER_STATUS=no
  [[ -e $hook ]] || keep_hook=no
  VIRT=$(systemd-detect-virt 2>/dev/null || echo none)
  IS_CONTAINER=no
  systemd-detect-virt -cq 2>/dev/null && IS_CONTAINER=yes
  step "$(T "Обновление настроек до версии" "Refreshing the settings to version") $HARDEN_VERSION"
  T "  Аккаунты, SSH и firewall не трогаются — их меняет только полная настройка." \
    "  Accounts, SSH and the firewall are not touched — only the full setup changes those."; echo
  backup_originals
  harden_system
  install_server_status
  [[ $keep_hook == yes ]] || rm -f "$hook"
  setup_auditd
  setup_autoupdates
  setup_fail2ban
  stash_sshd_config_dist
  if [[ -s /etc/harden/telegram.conf ]]; then
    TELEGRAM=yes
    TG_TOKEN=$(sed -n 's/^TG_TOKEN=//p' /etc/harden/telegram.conf)
    TG_CHAT_ID=$(sed -n 's/^TG_CHAT_ID=//p' /etc/harden/telegram.conf)
    api=$(sed -n 's/^TG_API=//p' /etc/harden/telegram.conf)
    [[ -z $api ]] || HARDEN_TG_API=$api
    v=$(saved_report_time)
    [[ -z $v ]] || TG_REPORT_TIME=$v
    install_notifications
  fi
  install_self "$0"
  save_answers
  ok "$(T "Настройки обновлены. Проверка: sudo harden --check" "Settings refreshed. To check: sudo harden --check")"
}

# Take the setup back. The originals are in the oldest backup directory — the one made
# before the first setup. What comes back: SSH (port, logins), the firewall, root and the
# locked accounts, and the system files the setup replaced; every file it added is
# removed. What stays: the installed packages, and the user the setup created.
run_undo() {
  local -a dirs=(/root/harden-backup-*)
  local first="" b f u shell groups g real now p fw_out
  # The oldest backup that was made before the setup: one that already holds the setup's own
  # SSH file was taken on a server that was hardened by then, and "restoring" it would put
  # the hardening back.
  for b in "${dirs[@]}"; do
    if [[ -d $b/ssh && ! -e $b/ssh/sshd_config.d/${SSHD_DROPIN##*/} ]]; then first=$b; break; fi
  done
  [[ -n $first ]] || die "$(T "Нет резервной копии /root/harden-backup-*, сделанной до настройки, — откатывать не из чего" \
                              "No backup /root/harden-backup-* from before the setup — nothing to undo from")"
  have_tty || die "$(T "Нужен интерактивный терминал" "An interactive terminal is required")"
  step "$(T "Откат настройки" "Undoing the setup")"
  T "  Вернутся: SSH (порт и способы входа), firewall, root, заблокированные аккаунты, системные файлы." \
    "  Coming back: SSH (port and logins), the firewall, root, the locked accounts, the system files."; echo
  T "  Останутся: установленные пакеты и пользователь, созданный при настройке." \
    "  Staying: the installed packages and the user the setup created."; echo
  echo "  $(T "Источник:" "From:") $first"
  T "  Это окно не оборвётся. После отката проверь вход по-старому, прежде чем его закрыть." \
    "  This session stays up. After the undo, try logging in the old way before you close it."; echo
  ask_yn "$(T "Откатить настройку?" "Undo the setup?")" n || die "$(T "Отменено." "Cancelled.")"

  # SSH: the old files back, one daemon on the old ports
  rm -f "$SSHD_DROPIN"
  cp -a "$first/ssh/." /etc/ssh/
  now=$(current_ssh_ports)
  # The old ports are opened before sshd moves to them: whatever happens to the firewall
  # further down, the way back in is not left closed.
  for p in $now; do ufw allow "$p/tcp" >/dev/null 2>&1 || true; done
  # shellcheck disable=SC2086  # a list of ports
  if ssh_apply && wait_sshd_listening $now; then
    ok "$(T "SSH: как было, порты:" "SSH: as it was, ports:") $now"
  else
    warn "$(T "sshd не поднялся со старыми настройками:" "sshd did not come up on the old settings:")"
    # shellcheck disable=SC2086
    sshd_port_report $now
  fi

  # Firewall: as it was before the setup — its old rules if it was on, off if it was off
  # or not there at all. What ufw says is shown, not thrown away.
  if [[ -d $first/ufw ]] && grep -qs '^ENABLED=yes' "$first/ufw/ufw.conf"; then
    cp -a "$first/ufw/." /etc/ufw/
    fw_out=$(ufw reload 2>&1) || warn "ufw reload: $fw_out"
    ok "Firewall: $(T "прежние правила" "the old rules")"
  else
    fw_out=$(ufw --force disable 2>&1) || warn "ufw disable: $fw_out"
    if [[ -d $first/ufw ]]; then cp -a "$first/ufw/." /etc/ufw/; fi
    if ufw status 2>/dev/null | head -1 | grep -q 'inactive'; then
      ok "Firewall: $(T "выключен, как до настройки" "off, as before the setup")"
    else
      warn "$(T "Firewall не выключился ($fw_out). Порты SSH ($now) в нём открыты; выключить вручную: sudo ufw disable" \
                "The firewall did not switch off ($fw_out). The SSH ports ($now) are open in it; to switch it off by hand: sudo ufw disable")"
    fi
  fi

  # root: its keys back, and its password unlocked if this script locked it
  for b in "${dirs[@]}"; do
    [[ -f $b/root_authorized_keys ]] || continue
    install -d -m 700 /root/.ssh
    cp -a "$b/root_authorized_keys" /root/.ssh/authorized_keys
    break
  done
  if [[ -r $STATE_FILE ]] && grep -qx 'LOCK_ROOT=yes' "$STATE_FILE"; then
    passwd -u root &>/dev/null || true
  else
    T "  Пароль root не трогаю (не знаю, блокировал ли его скрипт). Разблокировать: sudo passwd -u root" \
      "  The root password is left alone (no record that this script locked it). To unlock: sudo passwd -u root"; echo
  fi

  # The accounts the setup locked: shell, groups, keys, and their sudo rules
  for b in "${dirs[@]}"; do
    [[ -f $b/locked-users.tsv ]] || continue
    while IFS=$'\t' read -r u shell groups; do
      id "$u" &>/dev/null || continue
      # two commands: -U refuses an account whose password would come out empty (a
      # provider's key-only account), and would take the shell change down with it
      usermod -s "${shell:-/bin/bash}" "$u" 2>/dev/null || true
      usermod -U "$u" 2>/dev/null || true
      for g in $groups; do gpasswd -a "$u" "$g" &>/dev/null || true; done
      f=$(home_of "$u")
      if [[ -f $b/authorized_keys.$u && -d $f/.ssh ]]; then
        cp -a --remove-destination "$b/authorized_keys.$u" "$f/.ssh/authorized_keys"   # never through a symlink
      fi
      ok "$u $(T "разблокирован" "unlocked")"
    done <"$b/locked-users.tsv"
  done
  for f in /etc/sudoers.d/*; do
    [[ -f $f ]] && grep -q '^# disabled by harden.sh: ' "$f" || continue
    sed -i -E 's/^# disabled by harden\.sh: //' "$f"
  done

  # System files the setup replaced or edited
  for f in login.defs issue issue.net motd apt/apt.conf.d/20auto-upgrades default/apport default/sysstat default/motd-news; do
    if [[ -e $first/etc/$f ]]; then cp -a "$first/etc/$f" "/etc/$f"; fi
  done
  for b in "${dirs[@]}"; do
    if [[ -f $b/hosts ]]; then cp -a "$b/hosts" /etc/hosts; break; fi
  done
  for b in "${dirs[@]}"; do
    [[ -f $b/jail.local ]] || continue
    cp -a "$b/jail.local" /etc/fail2ban/jail.local
    if jail_local_is_ours; then rm -f /etc/fail2ban/jail.local; fi   # an earlier version's own file
    break
  done

  # Ping is the one kernel setting that is watched from outside — a provider's monitoring,
  # for one — so it is answered again now, not after the next reboot like the rest. (An
  # admin's own file that switches it off is applied again by `sysctl --system` below.)
  if [[ -e $PING_SYSCTL ]]; then
    sysctl -q -w net.ipv4.icmp_echo_ignore_all=0 2>/dev/null || true
    sysctl -e -q -w net.ipv6.icmp.echo_ignore_all=0 2>/dev/null || true
  fi

  # Everything the setup added
  rm -f "$SYSCTL_CONF" "$PROTECT_LINKS_CONF" "$PING_SYSCTL" \
        /etc/modprobe.d/99-hardening.conf /etc/security/limits.d/99-nocore.conf \
        /etc/systemd/coredump.conf.d/99-hardening.conf /etc/systemd/journald.conf.d/99-hardening.conf \
        /etc/security/pwquality.conf.d/99-hardening.conf /etc/sudoers.d/99-hardening /etc/logrotate.d/harden-sudo \
        /etc/systemd/resolved.conf.d/99-hardening.conf \
        /etc/audit/rules.d/99-hardening.rules /etc/needrestart/conf.d/99-hardening.conf \
        /etc/apt/apt.conf.d/52-hardening-unattended /etc/apt/apt.conf.d/53-hardening-crowdsec \
        "$F2B_JAIL" /usr/local/bin/server-status /etc/profile.d/99-server-status.sh \
        /etc/skel/.sudo_as_admin_successful /etc/skel/.cache/motd.legal-displayed
  rmdir /etc/skel/.cache 2>/dev/null || true
  if [[ $(cat /etc/fail2ban/fail2ban.local 2>/dev/null) == $'[DEFAULT]\nallowipv6 = auto' ]]; then rm -f /etc/fail2ban/fail2ban.local; fi
  visudo -cq || warn "$(T "sudoers: проверь /etc/sudoers.d" "sudoers: check /etc/sudoers.d")"
  # the stock login greeting
  for f in /etc/update-motd.d/*; do
    [[ -e $f ]] || continue
    real=$(readlink -f "$f")
    if dpkg-statoverride --list "$real" &>/dev/null; then dpkg-statoverride --remove "$real" >/dev/null 2>&1 || true; fi
    chmod 755 "$real" 2>/dev/null || true
  done
  # Telegram alerts
  systemctl disable --now harden-login-watch.service harden-daily-report.timer harden-boot-alert.service &>/dev/null || true
  rm -f /etc/systemd/system/harden-login-watch.service /etc/systemd/system/harden-alert@.service \
        /etc/systemd/system/harden-boot-alert.service /etc/systemd/system/harden-daily-report.service \
        /etc/systemd/system/harden-daily-report.timer /etc/systemd/system/*.service.d/harden-alert.conf \
        /usr/local/sbin/harden-notify /usr/local/sbin/harden-login-watch /usr/local/sbin/harden-daily-report
  for f in /etc/systemd/system/*.service.d; do rmdir "$f" 2>/dev/null || true; done
  rm -rf /etc/harden "$SSH_ROLLBACK" "$SSHD_TEST_DIR"
  systemctl unmask apport.service &>/dev/null || true
  chmod 644 /etc/crontab 2>/dev/null || true
  chmod 755 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
  systemctl daemon-reload
  # The services the setup switched off, back on — the ones that were on before it
  for b in "${dirs[@]}"; do
    [[ -f $b/disabled-services ]] || continue
    while read -r u; do
      [[ $u =~ ^[A-Za-z0-9@_.-]+\.(service|socket|path|timer)$ ]] || continue
      systemctl unmask "$u" &>/dev/null || true
      systemctl enable --now "$u" &>/dev/null || true
    done <"$b/disabled-services"
  done
  sysctl --system >/dev/null 2>&1 || true
  systemctl restart systemd-journald || true
  systemctl try-restart systemd-resolved &>/dev/null || true
  if command -v augenrules >/dev/null; then augenrules --load >/dev/null 2>&1 || true; fi
  # fail2ban: with the setup's jail gone it would go on with the distribution's defaults
  # and no exception for the admin's address — and it reads the recent log when it starts,
  # so a few mistyped logins from before are enough for a ban on the port just restored.
  # It is left running only if it had a configuration of its own before the setup.
  if [[ -f /etc/fail2ban/jail.local ]]; then
    systemctl restart fail2ban &>/dev/null || true
  elif systemctl cat fail2ban.service &>/dev/null; then
    systemctl disable --now fail2ban &>/dev/null || true
    T "  fail2ban остановлен: без настроек скрипта он работал бы без исключения для твоего адреса. Включить: sudo systemctl enable --now fail2ban" \
      "  fail2ban is stopped: without the setup's jail it would run with no exception for your address. To start it: sudo systemctl enable --now fail2ban"; echo
  fi

  echo
  ok "$(T "Настройка откачена." "The setup is undone.")"
  T "  Параметры ядра вернутся к прежним после перезагрузки." "  Kernel settings return to what they were after a reboot."; echo
  T "  Пакеты остались (ufw, fail2ban, auditd, CrowdSec и др.); убрать: sudo apt purge <имя>." \
    "  The packages stay (ufw, fail2ban, auditd, CrowdSec and the rest); to remove one: sudo apt purge <name>."; echo
  T "  Не закрывай это окно, пока не проверишь вход по-старому." \
    "  Do not close this window until you have checked that you can log in the old way."; echo
}

