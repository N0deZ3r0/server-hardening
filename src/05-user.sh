# ---------- 3. user ----------
# add_keys FROM TO — append the keys that are not there yet. An existing file that does
# not end in a newline would get the first new key glued onto its last line, breaking both.
add_keys() {
  local line
  touch "$2"
  [[ ! -s $2 || -z $(tail -c1 "$2") ]] || echo >>"$2"
  while read -r line; do
    [[ -n $line ]] || continue
    grep -qxF -- "$line" "$2" || echo "$line" >>"$2"
  done <"$1"
}

setup_user() {
  step "$(T "Пользователь" "User") $NEW_USER"

  # Password policy first, so the new password has to meet it
  mkdir -p /etc/security/pwquality.conf.d
  cat >/etc/security/pwquality.conf.d/99-hardening.conf <<'EOF'
minlen = 12
minclass = 3
maxrepeat = 3
dictcheck = 1
usercheck = 1
enforce_for_root
EOF

  if id "$NEW_USER" &>/dev/null; then
    info "$(T "Пользователь уже существует" "The user already exists")"
  else
    adduser --disabled-password --gecos "" "$NEW_USER"
  fi
  usermod -aG sudo "$NEW_USER"

  local home grp
  home=$(home_of "$NEW_USER"); grp=$(id -gn "$NEW_USER")
  install -d -m 700 -o "$NEW_USER" -g "$grp" "$home/.ssh"
  local ak="$home/.ssh/authorized_keys"
  add_keys "$PUBKEY_FILE" "$ak"
  chown "$NEW_USER:$grp" "$ak"; chmod 600 "$ak"
  ok "$(T "Ключ добавлен в" "Key added to") $ak"

  USER_HAS_PASSWORD=no
  if passwd -S "$NEW_USER" | awk '{exit !($2=="P")}'; then
    info "$(T "Пароль уже задан" "A password is already set")"; USER_HAS_PASSWORD=yes
  elif [[ ${SET_USER_PASSWORD:-yes} == no ]]; then
    warn "$(T "Пароль для $NEW_USER не задан (SET_USER_PASSWORD=no) — sudo заработает после: passwd $NEW_USER" \
              "No password for $NEW_USER (SET_USER_PASSWORD=no) — sudo works after: passwd $NEW_USER")"
  else
    T "Задай пароль для $NEW_USER — он нужен для sudo (минимум 12 символов, 3 типа символов)." \
      "Set a password for $NEW_USER — sudo needs it (12+ characters, 3 character classes)."; echo
    discard_typeahead
    until passwd "$NEW_USER" </dev/tty >/dev/tty 2>&1; do warn "$(T "Попробуй ещё раз" "Try again")"; discard_typeahead; done
    USER_HAS_PASSWORD=yes
  fi

  # Log every sudo command, shorter credential cache. One setting at a time, each tried
  # on its own first: sudo-rs, which is sudo on Ubuntu 25.10 and later, does not know every
  # setting the classic sudo has (`logfile`, for one; it logs to the journal instead), and
  # a single unknown line makes the whole file invalid.
  local d probe
  probe=$(mktemp)
  : >/etc/sudoers.d/99-hardening
  for d in 'use_pty' 'logfile="/var/log/sudo.log"' 'timestamp_timeout=15' 'passwd_tries=3'; do
    echo "Defaults    $d" >"$probe"
    if visudo -cqf "$probe" &>/dev/null; then
      echo "Defaults    $d" >>/etc/sudoers.d/99-hardening
    else
      info "$(T "sudo на этой системе не знает настройку, пропускаю:" "sudo on this system does not know the setting, skipped:") $d"
    fi
  done
  rm -f "$probe"
  chmod 440 /etc/sudoers.d/99-hardening
  visudo -cq || { rm -f /etc/sudoers.d/99-hardening; die "$(T "Ошибка sudoers" "sudoers error")"; }
  # The sudo log would otherwise grow for ever
  cat >/etc/logrotate.d/harden-sudo <<'EOF'
/var/log/sudo.log {
    monthly
    rotate 12
    compress
    missingok
    notifempty
}
EOF
  ok "$(T "Пользователь готов" "User ready")"
}

lock_other_users() {
  [[ $LOCK_OTHER_USERS == yes ]] || return 0
  step "$(T "Блокировка лишних аккаунтов:" "Locking extra accounts:") $OTHER_USERS"
  local u f g
  for u in $OTHER_USERS; do
    # the shell and the groups taken away, for --undo
    f=$(getent passwd "$u" | cut -d: -f7)   # empty means /bin/sh, and an empty field would shift the next one
    printf '%s\t%s\t%s\n' "$u" "${f:-/bin/sh}" \
      "$(id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -xE 'sudo|adm|lxd|docker' | paste -sd' ' - || true)" \
      >>"$BACKUP_DIR/locked-users.tsv"
    usermod -L -s /usr/sbin/nologin "$u"
    for g in sudo adm lxd docker; do gpasswd -d "$u" "$g" &>/dev/null || true; done
    f=$(home_of "$u")
    [[ -f $f/.ssh/authorized_keys ]] && mv "$f/.ssh/authorized_keys" "$BACKUP_DIR/authorized_keys.$u"
    # cloud-init grants ubuntu/debian "NOPASSWD:ALL" — comment it out
    for f in /etc/sudoers.d/*; do
      [[ -f $f ]] && grep -qE "^${u}[[:space:]]" "$f" || continue
      cp -a "$f" "$BACKUP_DIR/"
      sed -i -E "s/^(${u}[[:space:]].*)/# disabled by harden.sh: \1/" "$f"
    done
    ok "$u $(T "заблокирован (вернуть:" "locked (undo:") usermod -U -s /bin/bash $u)"
  done
  visudo -cq || die "$(T "Ошибка sudoers после блокировки пользователей — см." "sudoers error after locking accounts — see") $BACKUP_DIR"
}

