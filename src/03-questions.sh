# ---------- 1. questions ----------
detect_admin_ip() {  # the IP the admin is connected from right now
  local sc=${SSH_CLIENT:-} ip filter="" p
  ip=${sc%% *}
  if [[ -z $ip ]]; then
    ip=$(who -m 2>/dev/null | grep -oE '\(([0-9]{1,3}\.){3}[0-9]{1,3}\)' | tr -d '()' || true)
  fi
  if [[ -z $ip ]]; then  # sudo/tmux lost SSH_CLIENT — use the single established SSH peer
    # With a state filter ss drops the State column: $3 is the local address, $4 the peer.
    # CI checks this layout on a real socket, since reading it as $5 is an easy mistake.
    for p in $CURRENT_SSH_PORTS; do filter+="${filter:+ or }sport = :$p"; done
    ip=$(ss -Htn state established "( $filter )" 2>/dev/null | awk '{print $4}' \
         | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//; s/^::ffff://' | sort -u || true)
    [[ $(wc -l <<<"$ip") -eq 1 ]] || ip=""
  fi
  echo "$ip"
}

valid_user() {
  [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ && $1 != root ]] \
    || { warn "$(T "Только латиница в нижнем регистре, цифры, _ и -" "Lowercase latin letters, digits, _ and - only")"; return 1; }
  if id "$1" &>/dev/null; then
    (( $(id -u "$1") >= 1000 && $(id -u "$1") < 60000 )) || { warn "$(T "'$1' — системный пользователь, выбери другое имя" "'$1' is a system user, pick another name")"; return 1; }
  elif getent group "$1" >/dev/null; then
    # Ubuntu ships a system group called "admin" — adduser admin fails on it
    warn "$(T "Имя '$1' занято системной группой, выбери другое" "'$1' is taken by a system group, pick another name")"; return 1
  fi
}

# An existing account (the provider's "ubuntu" on AWS, say) is reused only on an explicit
# yes: it may already carry other people's keys or a NOPASSWD sudo rule from cloud-init.
confirm_existing_user() {
  id "$1" &>/dev/null || return 0
  local keys=0 h
  h=$(home_of "$1")
  [[ -f $h/.ssh/authorized_keys ]] && keys=$(grep -c . "$h/.ssh/authorized_keys" || true)
  warn "$(T "Пользователь '$1' уже существует. Ключей в его authorized_keys: $keys — они останутся." \
            "User '$1' already exists. Keys in its authorized_keys: $keys — they will stay.")"
  if grep -qsE "^$1[[:space:]].*NOPASSWD" /etc/sudoers /etc/sudoers.d/*; then
    warn "$(T "У '$1' есть sudo без пароля (NOPASSWD) — скрипт его не отключит." \
              "'$1' has passwordless sudo (NOPASSWD) — the script will not remove it.")"
  fi
  if env_yn REUSE_USER "$(T "Использовать существующего '$1'?" "Use the existing '$1'?")" n; then return 0; fi
  NEW_USER=""
  return 1
}

port_busy() { [[ -n $(ss -Hltn "sport = :$1" 2>/dev/null) ]]; }

collect_answers() {
  step "$(T "Настройка параметров" "Settings")"

  NEW_USER=${NEW_USER:-}
  until [[ -n $NEW_USER ]] && valid_user "$NEW_USER" && confirm_existing_user "$NEW_USER"; do
    ask "$(T "Имя нового пользователя с sudo" "Name of the new sudo user")" "sysop"; NEW_USER=$REPLY
  done

  PUBKEY_FILE=$(mktemp)
  # The public key is not a secret, but a failed run should not leave files in /tmp
  trap 'rm -f "${PUBKEY_FILE:-}" "${PUBKEY_FILE:-}.clean"' EXIT
  if [[ -n ${SSH_PUBKEY:-} ]]; then
    printf '%s\n' "$SSH_PUBKEY" >"$PUBKEY_FILE"
  elif [[ -n ${GITHUB_KEYS_USER:-} ]]; then
    if valid_github_user "$GITHUB_KEYS_USER"; then
      curl -fsSL "https://github.com/${GITHUB_KEYS_USER}.keys" >"$PUBKEY_FILE" || true
    else
      warn "$(T "Неверный GITHUB_KEYS_USER:" "Invalid GITHUB_KEYS_USER:") $GITHUB_KEYS_USER"
    fi
  fi
  # Where the admin came in through another account and sudo (AWS, Oracle, Azure), the key
  # that works is in that account's file: root's there carries a forced command ("Please
  # login as the user…") and is skipped, being a line that does not start with a key.
  local key_from=/root/.ssh/authorized_keys
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then key_from+=" $(home_of "$SUDO_USER")/.ssh/authorized_keys"; fi
  while ! { normalize_pubkeys "$PUBKEY_FILE" && check_pubkeys "$PUBKEY_FILE"; }; do
    echo
    T "Откуда взять публичный SSH-ключ?" "Where should the public SSH key come from?"; echo
    T "  1) Вставить вручную (строка из ~/.ssh/id_ed25519.pub)" "  1) Paste it (the line from ~/.ssh/id_ed25519.pub)"; echo
    T "  2) Загрузить с GitHub (https://github.com/<ник>.keys)" "  2) Fetch from GitHub (https://github.com/<user>.keys)"; echo
    T "  3) Скопировать из ${key_from// /, }" "  3) Copy from ${key_from// /, }"; echo
    ask "$(T "Выбор" "Choice")" "1"
    case $REPLY in
      2) ask "$(T "Ник на GitHub" "GitHub username")"
         if ! valid_github_user "$REPLY"; then
           warn "$(T "Такого имени на GitHub быть не может:" "That cannot be a GitHub username:") $REPLY"
         elif ! curl -fsSL "https://github.com/${REPLY}.keys" >"$PUBKEY_FILE"; then
           warn "$(T "Не удалось скачать ключи" "Could not download the keys")"
         fi ;;
      3)
         # shellcheck disable=SC2086  # a list of paths
         cat $key_from 2>/dev/null | awk '!seen[$0]++' >"$PUBKEY_FILE" || true
         [[ -s $PUBKEY_FILE ]] || warn "$(T "Там нет ключей:" "No keys there:") ${key_from// /, }" ;;
      *) echo "$(T "Создать ключ на СВОЁМ компьютере:" "Create a key on YOUR computer:")  ssh-keygen -t ed25519 -C \"$NEW_USER@server\""
         ask "$(T "Вставь публичный ключ (ssh-ed25519 AAAA...)" "Paste the public key (ssh-ed25519 AAAA...)")"
         # A paste of several lines (PuTTYgen's "SSH2 PUBLIC KEY" block, a private key)
         # would leave its other lines in the terminal to answer the next questions
         while read -r -t 0.2 _ </dev/tty; do :; done
         case $REPLY in
           *'BEGIN SSH2 PUBLIC KEY'*|PuTTY-User-Key-File*)
             warn "$(T "Это формат PuTTY. В PuTTYgen скопируй одну строку из поля «Public key for pasting into OpenSSH authorized_keys file»." \
                       "This is PuTTY's format. In PuTTYgen copy the single line from the box \"Public key for pasting into OpenSSH authorized_keys file\".")" ;;
           *'PRIVATE KEY'*)
             warn "$(T "Это ПРИВАТНЫЙ ключ — его нельзя никуда вставлять. Публичный лежит рядом, в файле .pub." \
                       "This is a PRIVATE key — never paste it anywhere. The public one is next to it, in the .pub file.")" ;;
         esac
         printf '%s\n' "$REPLY" >"$PUBKEY_FILE" ;;
    esac
  done

  local suggested
  suggested=$(shuf -i 20000-60999 -n 1)
  SSH_PORT=${SSH_PORT:-}
  # 10#: "08080" is a number to a person and a broken octal to bash
  until [[ $SSH_PORT =~ ^[0-9]{1,5}$ ]] && SSH_PORT=$((10#$SSH_PORT)) && (( SSH_PORT >= 1024 && SSH_PORT <= 65535 )) \
        && { [[ " $CURRENT_SSH_PORTS " == *" $SSH_PORT "* ]] || ! port_busy "$SSH_PORT"; }; do
    [[ -n $SSH_PORT ]] && warn "$(T "Порт должен быть 1024–65535 и свободен." "The port must be 1024–65535 and free.")"
    ask "$(T "Новый порт SSH" "New SSH port")" "$suggested"; SSH_PORT=$REPLY
  done

  if [[ -z ${EXTRA_PORTS+x} ]]; then
    ask "$(T "Какие ещё порты открыть в firewall (через запятую, напр. 80,443; пусто — никаких)" \
             "Other ports to open in the firewall (comma-separated, e.g. 80,443; empty = none)")" ""
    EXTRA_PORTS=$REPLY
  fi
  EXTRA_PORTS=$(tr -d ' ' <<<"$EXTRA_PORTS")

  # Whitelist the admin's own IP so fail2ban/CrowdSec never ban the person setting this up
  local detected
  detected=$(detect_admin_ip)
  if [[ -n ${ADMIN_IP+x} ]]; then
    :  # preset through the environment (empty = none)
  elif [[ -n $detected ]]; then
    if ask_yn "$(T "Твой IP $detected — добавить в белый список fail2ban/CrowdSec? (не стоит, если IP часто меняется)" \
                   "Your IP is $detected — whitelist it in fail2ban/CrowdSec? (skip if your IP changes often)")" y; then
      ADMIN_IP=$detected
    else ADMIN_IP=""; fi
  else
    ADMIN_IP=""
  fi
  if [[ -n $ADMIN_IP && ! $ADMIN_IP =~ ^[0-9a-fA-F.:/]+$ ]]; then
    warn "$(T "Неверный ADMIN_IP: $ADMIN_IP — пропускаю" "Invalid ADMIN_IP: $ADMIN_IP — skipped")"; ADMIN_IP=""
  fi

  if env_yn AUTO_REBOOT "$(T "Разрешить автоперезагрузку ночью, если обновление ядра этого требует?" \
                             "Allow a nightly automatic reboot when a kernel update needs it?")" y; then
    AUTO_REBOOT=yes; REBOOT_TIME=${REBOOT_TIME:-04:00}
    [[ $REBOOT_TIME =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] \
      || { warn "$(T "REBOOT_TIME должно быть ЧЧ:ММ — беру 04:00" "REBOOT_TIME must be HH:MM — using 04:00")"; REBOOT_TIME=04:00; }
  else AUTO_REBOOT=no; fi

  if env_yn LOCK_ROOT "$(T "Заблокировать пароль root (вход только через $NEW_USER + sudo)?" \
                           "Lock the root password (log in as $NEW_USER and use sudo)?")" y; then LOCK_ROOT=yes; else LOCK_ROOT=no; fi

  # Pre-existing login accounts (ubuntu, debian, admin, opc from the provider…)
  OTHER_USERS=$(awk -F: -v me="$NEW_USER" '$3>=1000 && $3<60000 && $1!=me && $7!~/(nologin|false)$/ {print $1}' /etc/passwd | xargs)
  if [[ -n $OTHER_USERS ]]; then
    warn "$(T "Найдены другие аккаунты с доступом к shell: $OTHER_USERS" "Other accounts with shell access found: $OTHER_USERS")"
    if [[ -n ${SUDO_USER:-} && " $OTHER_USERS " == *" $SUDO_USER "* ]]; then
      warn "$(T "Ты сейчас работаешь под '$SUDO_USER' (AWS/Oracle/Azure так делают) — после настройки входи как $NEW_USER." \
                "You are working as '$SUDO_USER' (AWS/Oracle/Azure do this) — log in as $NEW_USER afterwards.")"
    fi
    if env_yn LOCK_OTHER_USERS "$(T "Заблокировать их ПОСЛЕ проверки входа под $NEW_USER (пароль, shell, sudo; данные не удаляются)?" \
                                    "Lock them AFTER the $NEW_USER login is confirmed (password, shell, sudo; no data is deleted)?")" y; then
      LOCK_OTHER_USERS=yes
    else LOCK_OTHER_USERS=no; fi
  else
    LOCK_OTHER_USERS=no
  fi

  # SSH gets "AllowUsers", so leaving the other accounts unlocked would still shut them
  # out of SSH without a word. Say it, and let the admin keep them in.
  if [[ -n ${SSH_EXTRA_USERS+x} ]]; then
    SSH_EXTRA_USERS=$(valid_extra_users "$SSH_EXTRA_USERS")
  elif [[ -n $OTHER_USERS && $LOCK_OTHER_USERS == no ]]; then
    warn "$(T "По SSH после настройки сможет входить только $NEW_USER (AllowUsers) — даже те аккаунты, что не блокируются, по SSH не войдут." \
              "After the setup SSH accepts only $NEW_USER (AllowUsers) — accounts that are not locked still cannot log in over SSH.")"
    if ask_yn "$(T "Оставить вход по SSH (по ключу) ещё и для: $OTHER_USERS?" "Keep SSH login (by key) for these as well: $OTHER_USERS?")" n; then
      SSH_EXTRA_USERS=$(valid_extra_users "$OTHER_USERS")
    else SSH_EXTRA_USERS=""; fi
  else
    SSH_EXTRA_USERS=""
  fi
  if [[ -n $SSH_EXTRA_USERS && $LOCK_OTHER_USERS == yes ]]; then
    warn "$(T "SSH_EXTRA_USERS пропущен: эти аккаунты блокируются" "SSH_EXTRA_USERS ignored: those accounts are being locked")"; SSH_EXTRA_USERS=""
  fi
  if env_yn INSTALL_CROWDSEC "$(T "Установить CrowdSec (коллективный IPS, дополнение к fail2ban)?" \
                                  "Install CrowdSec (crowd-sourced IPS on top of fail2ban)?")" n; then INSTALL_CROWDSEC=yes; else INSTALL_CROWDSEC=no; fi
  if env_yn RUN_LYNIS "$(T "Запустить в конце аудит Lynis?" "Run a Lynis audit at the end?")" y; then RUN_LYNIS=yes; else RUN_LYNIS=no; fi
  if env_yn TELEGRAM "$(T "Уведомления в Telegram (входы по SSH, сбои, ежедневная сводка)?" \
                          "Telegram alerts (SSH logins, failures, daily report)?")" n; then
    ask_telegram
  else TELEGRAM=no; fi
  # Off by default: it hides the server from ping sweeps, not from a port scan, and a
  # provider that monitors by ping will report the server as down
  if env_yn DISABLE_PING "$(T "Не отвечать на ping? (маскировка, не защита; мониторинг хостера по ping сочтёт сервер упавшим)" \
                              "Stop answering ping? (obscurity, not protection; a provider that monitors by ping will see the server as down)")" n; then
    DISABLE_PING=yes
  else DISABLE_PING=no; fi

  echo
  echo "${C_BOLD}$(T "Итог:" "Summary:")${C_0}"
  echo "  $(T "Пользователь:      " "User:              ") $NEW_USER (sudo)"
  echo "  $(T "SSH-ключи:         " "SSH keys:          ") $(ssh-keygen -lf "$PUBKEY_FILE" | awk '{print $NF, $2}' | paste -sd';' -)"
  echo "  $(T "SSH порт:          " "SSH port:          ") $CURRENT_SSH_PORTS -> $SSH_PORT"
  echo "  $(T "Открытые порты:    " "Open ports:        ") $SSH_PORT/tcp ${EXTRA_PORTS:+$EXTRA_PORTS}"
  echo "  $(T "Белый список IP:   " "Whitelisted IP:    ") ${ADMIN_IP:-$(T "нет" "none")}"
  echo "  $(T "Автоперезагрузка:  " "Auto reboot:       ") $AUTO_REBOOT ${REBOOT_TIME:-}"
  echo "  $(T "Блок. пароля root: " "Lock root password:") $LOCK_ROOT"
  [[ -n $OTHER_USERS ]] && echo "  $(T "Блок. аккаунтов:   " "Lock accounts:     ") $LOCK_OTHER_USERS ($OTHER_USERS)"
  echo "  $(T "Вход по SSH:       " "SSH login for:     ") $NEW_USER${SSH_EXTRA_USERS:+ $SSH_EXTRA_USERS}"
  echo "  CrowdSec:           $INSTALL_CROWDSEC"
  echo "  Telegram:           $TELEGRAM${TG_CHAT_ID:+ (chat $TG_CHAT_ID)}"
  echo "  $(T "Ответ на ping:     " "Answer ping:       ") $([[ $DISABLE_PING == yes ]] && T "нет" "no" || T "да" "yes")"
  ask_yn "$(T "Начать настройку?" "Start?")" y || die "$(T "Отменено." "Cancelled.")"
}

# normalize_pubkeys FILE — keep the lines that are public keys, drop everything else
# (comments, options, a stray private key). 1 when no key is left.
normalize_pubkeys() {
  local f=$1
  [[ -s $f ]] || return 1
  grep -E '^(ssh-ed25519|sk-ssh-ed25519@openssh.com|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh.com) ' "$f" >"$f.clean"     || { rm -f "$f.clean"; warn "$(T "Ключи не найдены" "No keys found")"; return 1; }
  mv "$f.clean" "$f"
}

# check_pubkeys FILE — are the keys usable? Changes nothing; weak RSA keys are named.
check_pubkeys() {
  local f=$1 bits type
  if ! ssh-keygen -lf "$f" >/dev/null 2>&1; then warn "$(T "Ключ повреждён" "The key is damaged")"; return 1; fi
  while read -r bits type; do
    if [[ $type == "(RSA)" ]] && (( bits < 3072 )); then
      warn "$(T "RSA-ключ $bits бит слабый. Рекомендуется ed25519: ssh-keygen -t ed25519" "A $bits-bit RSA key is weak. Prefer ed25519: ssh-keygen -t ed25519")"
    fi
  done < <(ssh-keygen -lf "$f" | awk '{print $1, $NF}')
  return 0
}

# A GitHub username goes into a URL: letters, digits and single hyphens, at most 39
valid_github_user() { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ && $1 != *--* ]]; }

