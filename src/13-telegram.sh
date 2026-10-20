# ---------- Telegram alerts ----------
# tg_api TOKEN METHOD [curl args] — the token goes to curl on stdin as a config line,
# never on a command line, where any local user could read it from ps.
tg_api() {
  local token=$1 method=$2; shift 2
  printf 'url = "%s/bot%s/%s"\n' "${HARDEN_TG_API:-https://api.telegram.org}" "$token" "$method" \
    | curl -sS --max-time 15 -K - "$@" 2>/dev/null || true
}

# The hour of the daily report as the timer has it now. It is asked nowhere — it comes from
# TG_REPORT_TIME — so a run that is not given it again has to find it here, or the report
# goes back to 09:00.
saved_report_time() {
  sed -n 's/^OnCalendar=\*-\*-\* //p' /etc/systemd/system/harden-daily-report.timer 2>/dev/null || true
}

ask_telegram() {  # sets TG_TOKEN / TG_CHAT_ID, or TELEGRAM=no if the admin gives up
  local token=${TG_TOKEN:-} chat=${TG_CHAT_ID:-} bot="" conf=/etc/harden/telegram.conf api
  # Re-running the setup (after an update, say) should not ask for the token again
  if [[ -z $token && -s $conf ]] && ask_yn "$(T "Использовать уже сохранённого бота?" "Use the bot that is already saved?")" y; then
    TG_TOKEN=$(sed -n 's/^TG_TOKEN=//p' "$conf"); TG_CHAT_ID=$(sed -n 's/^TG_CHAT_ID=//p' "$conf")
    # ...and with the bot, what else was saved for it: the hour of its report, and the
    # address of the API where one was given
    [[ -n ${TG_REPORT_TIME:-} ]] || TG_REPORT_TIME=$(saved_report_time)
    api=$(sed -n 's/^TG_API=//p' "$conf")
    [[ -n ${HARDEN_TG_API:-} || -z $api ]] || HARDEN_TG_API=$api
    TELEGRAM=yes
    return 0
  fi
  # A direct link, not "search for BotFather": the search is full of look-alike bots
  T "  1) Откройте https://t.me/BotFather — официальный, с синей галочкой (в поиске много подделок)" \
    "  1) Open https://t.me/BotFather — the official one with the blue check mark (search shows many fakes)"; echo
  T "     Отправьте /newbot, задайте имя и username (должен кончаться на bot), скопируйте токен" \
    "     Send /newbot, give a name and a username (must end in bot), copy the token"; echo
  until [[ $token =~ ^[0-9]{5,}:[A-Za-z0-9_-]{30,}$ ]] && tg_api "$token" getMe | grep -q '"ok":true'; do
    [[ -n $token ]] && warn "$(T "Telegram не принял токен" "Telegram rejected the token")"
    discard_typeahead   # an Enter typed ahead would read as "skip", and Telegram would be dropped without a word
    read -r -s -p "$(T "Токен бота (ввод скрыт, пусто — пропустить): " "Bot token (hidden, empty to skip): ")" token </dev/tty; echo
    [[ -z $token ]] && { TELEGRAM=no; return 0; }
  done
  bot=$(tg_api "$token" getMe | grep -o '"username":"[^"]*"' | cut -d'"' -f4 || true)
  if [[ ! $chat =~ ^-?[0-9]+$ ]]; then
    T "  2) Откройте https://t.me/$bot, нажмите Start (или отправьте любое сообщение) и нажмите Enter здесь" \
      "  2) Open https://t.me/$bot, press Start (or send any message), then press Enter here"; echo
    discard_typeahead
    read -r _ </dev/tty
    chat=$(tg_api "$token" getUpdates | grep -o '"chat":{"id":-\{0,1\}[0-9]*' | tail -1 | grep -o -- '-\{0,1\}[0-9]*$' || true)
    until [[ $chat =~ ^-?[0-9]+$ ]]; do
      ask "$(T "Chat ID не найден автоматически — введите вручную" "Chat ID not found automatically — enter it")"; chat=$REPLY
    done
  fi
  tg_api "$token" sendMessage --data-urlencode "chat_id=$chat" \
    --data-urlencode "text=✅ $(hostname): $(T "тестовое сообщение harden.sh. Если вы его видите — ответьте y в окне сервера" "test message from harden.sh. If you can see it, answer y on the server")" -o /dev/null
  if ask_yn "$(T "В Telegram пришло сообщение «тестовое сообщение harden.sh»?" "Did the message \"test message from harden.sh\" arrive in Telegram?")" y; then
    TG_TOKEN=$token; TG_CHAT_ID=$chat; TELEGRAM=yes
  else
    warn "$(T "Telegram пропущен. Позже: sudo harden --setup-telegram" "Telegram skipped. Later: sudo harden --setup-telegram")"
    TELEGRAM=no
  fi
}

install_notifications() {
  [[ ${TELEGRAM:-no} == yes ]] || return 0
  step "$(T "Уведомления в Telegram" "Telegram alerts")"
  [[ ${TG_REPORT_TIME:-09:00} =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || TG_REPORT_TIME=09:00
  install -d -m 700 /etc/harden
  (
    umask 077
    printf 'TG_TOKEN=%s\nTG_CHAT_ID=%s\n' "$TG_TOKEN" "$TG_CHAT_ID" >/etc/harden/telegram.conf
    [[ -n ${HARDEN_TG_API:-} ]] && echo "TG_API=$HARDEN_TG_API" >>/etc/harden/telegram.conf
    true
  )

  cat >/usr/local/sbin/harden-notify <<'NOTIFY_EOF'
#!/bin/bash
# harden-notify "text" — Telegram message from this server (installed by harden.sh).
# The token is read from a root-only file and handed to curl on stdin, never on a command line.
set -u
CONF=/etc/harden/telegram.conf
[ -r "$CONF" ] || exit 0
token=$(sed -n 's/^TG_TOKEN=//p' "$CONF")
chat=$(sed -n 's/^TG_CHAT_ID=//p' "$CONF")
api=$(sed -n 's/^TG_API=//p' "$CONF")
[ -n "$token" ] && [ -n "$chat" ] || exit 0
if [ "${1:-}" = --boot ]; then set -- "🔄 Server started — kernel $(uname -r)"; fi
# --retry-all-errors: on its own --retry gives up at once on a refused connection or a
# name that does not resolve yet — which is what the message after a boot runs into,
# sent seconds after the network comes up
printf 'url = "%s/bot%s/sendMessage"\n' "${api:-https://api.telegram.org}" "$token" \
  | curl -sS --max-time 15 --retry 3 --retry-delay 5 --retry-all-errors -K - -o /dev/null \
      --data-urlencode "chat_id=$chat" \
      --data-urlencode "text=🖥 $(hostname): $*" \
      --data-urlencode "disable_web_page_preview=true" 2>/dev/null
exit 0
NOTIFY_EOF

  cat >/usr/local/sbin/harden-login-watch <<'WATCH_EOF'
#!/bin/bash
# Follows sshd in the journal and sends a Telegram message for every accepted login
# (installed by harden.sh). Reading the journal means no PAM or sshd config is edited.
set -u
# Logins by the same user, from the same address, with the same key, within 3 seconds are
# one event to a person: MobaXterm, WinSCP, Termius and the like open a second connection
# for file transfer. They are sent as one message marked ×2 rather than as two alerts.
sig=""; msg=""; n=0; t0=0
flush() {
  [ -n "$sig" ] || return 0
  if [ "$n" -gt 1 ]; then /usr/local/sbin/harden-notify "$msg ×$n" &
  else /usr/local/sbin/harden-notify "$msg" & fi
  sig=""; n=0
}
# --since now, not -n 0: with -n 0 journalctl printed only the last line of the first
# burst on a machine with no sshd entry from the current boot (measured in CI, journalctl
# alone) — the first login after a boot could go unreported.
journalctl -f --since now -o cat SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session 2>/dev/null |
while :; do
  if IFS= read -r -t 1 line; then
    case $line in
      # Accepted <method> for <user> from <ip> port <port> ssh2[: <type> <fingerprint>]
      # The full shape is required: with LogLevel VERBOSE sshd also logs
      # "Accepted key ED25519 SHA256:… found at /home/…/authorized_keys:1" for every key it
      # looks up, which is not a login (seen live as "login: SHA256:… from at").
      "Accepted "*" for "*" from "*" port "*)
        read -r -a f <<<"$line"
        s="${f[3]:-?} ${f[5]:-?} ${f[10]:-}"
        if [ "$s" = "$sig" ]; then
          n=$((n + 1))
        else
          flush    # a different user, address or key is never merged or delayed
          sig=$s; n=1; t0=$SECONDS
          msg="🔑 SSH login: ${f[3]:-?} from ${f[5]:-?} (${f[1]:-?}${f[9]:+, ${f[9]}}${f[10]:+ ${f[10]}})"
        fi
        ;;
    esac
  elif [ $? -le 128 ]; then
    flush; break    # end of input (journalctl stopped); above 128 is just the read timeout
  fi
  if [ -n "$sig" ] && [ $((SECONDS - t0)) -ge 3 ]; then flush; fi
done
WATCH_EOF

  cat >/usr/local/sbin/harden-daily-report <<'REPORT_EOF'
#!/bin/bash
# Daily summary to Telegram (installed by harden.sh; run by harden-daily-report.timer).
set -u
since=$(date -d '-24 hours' '+%F %T')
sim=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst' || true)
upd=$(printf '%s' "$sim" | grep -c . || true)
sec=$(printf '%s' "$sim" | grep -ci security || true)
# Logins only — not the "Accepted key … found at …" lines LogLevel VERBOSE adds per key lookup
acc=$(journalctl --since "$since" -o cat SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session 2>/dev/null \
      | grep -E '^Accepted [^ ]+ for [^ ]+ from [^ ]+ port ' || true)
nlog=$(printf '%s' "$acc" | grep -c . || true)
who=$(printf '%s' "$acc" | awk 'NF{print $4"@"$6}' | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s%s×%s", (NR>1?", ":""), $2, $1}')
bans=0
[ -r /var/log/fail2ban.log ] && bans=$(awk -v s="$since" '($1" "substr($2,1,8)) >= s && / Ban /' /var/log/fail2ban.log | wc -l)
banned=$(fail2ban-client status sshd 2>/dev/null | awk -F'\t' '/Currently banned/{print $2}')
failed=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | paste -sd' ' -)
disk=$(df -h --output=avail,pcent / | awk 'NR==2{print $1" free ("$2" used)"}')
ram=$(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{printf "%d MB free of %d", a/1024, t/1024}' /proc/meminfo)

msg="📊 Daily report
Uptime: $(LC_ALL=C uptime -p | sed 's/^up //'), load $(cut -d' ' -f1-3 /proc/loadavg)
Updates: $upd pending ($sec security)"
[ -f /var/run/reboot-required ] && msg="$msg
⚠️ Reboot required"
msg="$msg
SSH logins (24 h): $nlog${who:+ — $who}
fail2ban: $bans bans in 24 h, ${banned:-0} banned now"
if command -v cscli >/dev/null; then
  msg="$msg
CrowdSec: $(cscli decisions list -o raw 2>/dev/null | tail -n +2 | grep -c . || true) active decisions"
fi
msg="$msg
Failed services: ${failed:-none}
Disk /: $disk, RAM: $ram"
# The audit in one line, and the lines that need attention: a setting that has drifted is
# seen the next morning, not at the next check someone happens to run
if [ -x /usr/local/sbin/harden ]; then
  chk=$(HARDEN_LANG=en /usr/local/sbin/harden --check 2>/dev/null)
  sum=$(printf '%s\n' "$chk" | sed -n 's/^Summary: //p')
  if [ -n "$sum" ]; then
    msg="$msg
Check: $sum"
    bad=$(printf '%s\n' "$chk" | grep -E '^  (✗|!) ' | grep -v 'Reboot required' | head -5)
    [ -n "$bad" ] && msg="$msg
$bad"
  fi
fi
/usr/local/sbin/harden-notify "$msg"
REPORT_EOF
  chmod 755 /usr/local/sbin/harden-notify /usr/local/sbin/harden-login-watch /usr/local/sbin/harden-daily-report

  cat >/etc/systemd/system/harden-login-watch.service <<'EOF'
[Unit]
Description=Telegram alert on every SSH login (harden.sh)
After=systemd-journald.service network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/harden-login-watch
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
  cat >/etc/systemd/system/harden-alert@.service <<'EOF'
[Unit]
Description=Telegram alert: %i failed (harden.sh)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/harden-notify "❌ %i failed — systemctl status %i"
EOF
  cat >/etc/systemd/system/harden-boot-alert.service <<'EOF'
[Unit]
Description=Telegram alert when the server has booted (harden.sh)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/harden-notify --boot

[Install]
WantedBy=multi-user.target
EOF
  cat >/etc/systemd/system/harden-daily-report.service <<'EOF'
[Unit]
Description=Daily Telegram report (harden.sh)
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/harden-daily-report
EOF
  cat >/etc/systemd/system/harden-daily-report.timer <<EOF
[Unit]
Description=Daily Telegram report (harden.sh)

[Timer]
OnCalendar=*-*-* ${TG_REPORT_TIME:-09:00}
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
EOF

  # A failure alert for the services that keep the server safe. Drop-ins are our own
  # files, so no package config is edited.
  local u
  for u in ssh fail2ban crowdsec crowdsec-firewall-bouncer auditd unattended-upgrades; do
    systemctl cat "$u.service" &>/dev/null || continue
    # Modes are set explicitly, and repaired if an earlier version left them tight: a
    # drop-in a normal user cannot read makes `systemctl cat` and `status` fail for them
    install -d -m 755 "/etc/systemd/system/$u.service.d"
    printf '[Unit]\nOnFailure=harden-alert@%%n.service\n' >"/etc/systemd/system/$u.service.d/harden-alert.conf"
    chmod 644 "/etc/systemd/system/$u.service.d/harden-alert.conf"
  done
  chmod 644 /etc/systemd/system/harden-login-watch.service /etc/systemd/system/harden-alert@.service \
            /etc/systemd/system/harden-boot-alert.service /etc/systemd/system/harden-daily-report.service \
            /etc/systemd/system/harden-daily-report.timer
  systemctl daemon-reload
  # restart, not just enable --now: on an update the watcher is already running the old
  # script, and enable --now leaves a running unit as it is
  systemctl enable harden-login-watch.service harden-daily-report.timer &>/dev/null \
    && systemctl restart harden-login-watch.service harden-daily-report.timer &>/dev/null \
    || warn "$(T "Не удалось запустить службы уведомлений" "Could not start the alert services")"
  systemctl enable harden-boot-alert.service &>/dev/null || true
  /usr/local/sbin/harden-notify "✅ $(T "Уведомления включены: входы по SSH, падения служб, загрузка, сводка в" "Alerts on: SSH logins, failed services, boot, daily report at") ${TG_REPORT_TIME:-09:00} $(date +%Z)"
  ok "$(T "Telegram: входы по SSH, падения служб, загрузка, ежедневная сводка" "Telegram: SSH logins, failed services, boot, daily report")"
}

