#!/usr/bin/env bash
# =============================================================================
#  harden.sh — first-boot setup and hardening for a Debian / Ubuntu server
#
#  Supported: Debian 12/13, Ubuntu 22.04/24.04/26.04
#  Run:       curl -fsSL https://raw.githubusercontent.com/N0deZ3r0/server-hardening/main/harden.sh -o harden.sh && sudo bash harden.sh
#  Interface: English / Русский (asked at start, or HARDEN_LANG=en|ru)
#
#  Order of work:
#    1. Questions: new user, SSH key, new SSH port, extra ports, options
#    2. Waits for the provider's cloud-init, upgrades, installs packages
#    3. sudo user with the key; kernel (sysctl), AppArmor, auditd, chrony,
#       journald, no core dumps, password policy, security auto-updates
#    4. UFW (deny incoming) + fail2ban (+ CrowdSec), admin IP whitelisted
#    5. SSH: new port, keys only, no root, modern crypto incl. post-quantum KEX
#       -> the admin logs in from a NEW window first; only then the old port closes
#    6. Locks pre-existing accounts and the root password, Lynis audit, report,
#       reboot (never while packages are being installed)
#
#  Environment (optional, otherwise the script asks):
#    HARDEN_LANG=en|ru, NEW_USER, SSH_PORT, SSH_PUBKEY, GITHUB_KEYS_USER,
#    EXTRA_PORTS="80,443", ADMIN_IP (empty = none), AUTO_REBOOT=yes|no,
#    REBOOT_TIME=04:00, LOCK_ROOT=yes|no, LOCK_OTHER_USERS=yes|no,
#    INSTALL_CROWDSEC=yes|no, RUN_LYNIS=yes|no, REBOOT_NOW=yes|no,
#    SERVER_STATUS=yes|no, REUSE_USER=yes|no (use an existing account),
#    TELEGRAM=yes|no, TG_TOKEN, TG_CHAT_ID, TG_REPORT_TIME=09:00,
#    SET_USER_PASSWORD=no (root is then NOT locked)
#
#  Other modes: --check (audit only), --setup-telegram, --install-status, --help
# =============================================================================
set -Eeuo pipefail

HARDEN_VERSION="2026.09"
LOG_FILE="/var/log/harden.log"
REPORT_FILE="/root/harden-report.txt"
BACKUP_DIR="/root/harden-backup-$(date +%Y%m%d-%H%M%S)"
SSHD_DROPIN="/etc/ssh/sshd_config.d/00-hardening.conf"
UI=${HARDEN_LANG:-en}

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

trap 'echo "${C_R}[✗] $(T "Ошибка в строке" "Error at line") $LINENO: $BASH_COMMAND${C_0}" >&2
      echo "$(T "Бэкап конфигов" "Config backup"): $BACKUP_DIR, $(T "лог" "log"): $LOG_FILE" >&2' ERR

# Questions are read from the terminal, so this also works as `curl ... | bash`
ask() {  # ask "question" "default" -> REPLY
  local q=$1 def=${2:-}
  if [[ -n $def ]]; then read -r -p "$q [$def]: " REPLY </dev/tty; REPLY=${REPLY:-$def}
  else read -r -p "$q: " REPLY </dev/tty; fi
}
ask_yn() {  # ask_yn "question" y|n -> 0 on yes (accepts y/yes/д/да)
  local q=$1 def=${2:-n} hint
  [[ $def == y ]] && hint="Y/n" || hint="y/N"
  read -r -p "$q [$hint]: " REPLY </dev/tty
  REPLY=${REPLY:-$def}
  [[ ${REPLY,,} == y* || ${REPLY,,} == д* ]]
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
  sudo bash harden.sh --install-status  only install the login summary (server-status)
  sudo HARDEN_LANG=ru bash harden.sh    interface in Russian / интерфейс на русском

After a full run the script is also installed as /usr/local/sbin/harden,
so later it is just: sudo harden --check

All options can be preset through environment variables — see the header of this file
or README.md.
EOF
}

# ---------- 0. language, tmux, preflight ----------
choose_language() {
  case ${HARDEN_LANG:-} in ru|en) UI=$HARDEN_LANG; export HARDEN_LANG; return 0 ;; esac
  local d=1
  [[ "${LC_ALL:-}${LANG:-}" == *ru* ]] && d=2
  if [[ -r /dev/tty ]]; then
    read -r -p "Language / Язык:  1) English  2) Русский [$d]: " REPLY </dev/tty || REPLY=$d
    case ${REPLY:-$d} in 2|ru|RU|р*|Р*) UI=ru ;; *) UI=en ;; esac
  else
    [[ $d == 2 ]] && UI=ru || UI=en
  fi
  export HARDEN_LANG=$UI
}

# A dropped SSH session (fresh VPS images often restart sshd in the first minutes)
# must not kill a half-done run, so the script moves itself into tmux.
relaunch_in_tmux() {
  [[ -n ${TMUX:-} || -n ${STY:-} || -n ${HARDEN_NO_TMUX:-} ]] && return 0
  command -v tmux >/dev/null || return 0
  [[ -f $0 && -t 0 ]] || return 0
  local script inner v
  script=$(readlink -f "$0")
  inner="env HARDEN_NO_TMUX=1"
  for v in HARDEN_LANG NEW_USER SSH_PORT SSH_PUBKEY GITHUB_KEYS_USER EXTRA_PORTS AUTO_REBOOT REBOOT_TIME \
           LOCK_ROOT LOCK_OTHER_USERS INSTALL_CROWDSEC RUN_LYNIS REBOOT_NOW SET_USER_PASSWORD ADMIN_IP \
           SERVER_STATUS REUSE_USER TELEGRAM TG_CHAT_ID TG_REPORT_TIME HARDEN_TG_API SSH_CLIENT; do
    # TG_TOKEN is deliberately not passed: it would sit in tmux's command line, readable
    # in ps; inside tmux the script asks for it again (hidden input)
    [[ -n ${!v+x} ]] && inner+=" $v=$(printf '%q' "${!v}")"
  done
  inner+=" bash $(printf '%q' "$script"); echo; read -rp $(printf '%q' "$(T 'Enter — закрыть окно tmux' 'Press Enter to close tmux')") _"
  info "$(T "Запускаю внутри tmux. Если SSH оборвётся — зайди снова и выполни: tmux attach -t harden" \
            "Running inside tmux. If SSH drops, log in again and run: tmux attach -t harden")"
  sleep 2
  exec tmux new-session -A -s harden bash -c "$inner"
}

preflight() {
  [[ -r /dev/tty ]] || die "$(T "Нужен интерактивный терминал (запускай в SSH-сессии)." "An interactive terminal is required (run it in an SSH session).")"
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "$(T "Поддерживаются только Debian и Ubuntu (обнаружено: ${PRETTY_NAME:-?})" "Only Debian and Ubuntu are supported (found: ${PRETTY_NAME:-?})")" ;;
  esac
  OS_NAME=$PRETTY_NAME
  VIRT=$(systemd-detect-virt 2>/dev/null || echo none)
  IS_CONTAINER=no
  systemd-detect-virt -cq 2>/dev/null && IS_CONTAINER=yes

  mkdir -p "$BACKUP_DIR"
  cp -a /etc/ssh "$BACKUP_DIR/ssh"
  [[ -d /etc/ufw ]] && cp -a /etc/ufw "$BACKUP_DIR/ufw"
  exec > >(tee -a "$LOG_FILE") 2>&1

  echo "${C_BOLD}Server hardening v$HARDEN_VERSION — $OS_NAME (virt: $VIRT)${C_0}"
  if [[ -z ${TMUX:-} && -z ${STY:-} ]]; then
    warn "$(T "tmux/screen не найден: обрыв SSH прервёт настройку (apt install tmux)." "tmux/screen not found: a dropped SSH session will abort the run (apt install tmux).")"
  fi

  # The provider's cloud-init may run a full apt upgrade (GRUB and kernel included) and
  # restart SSH for 5–20 minutes. Interrupting or rebooting then can leave GRUB half
  # installed and the server unbootable — seen live, so we wait for it to finish.
  if command -v cloud-init >/dev/null && cloud-init status 2>/dev/null | grep -qE 'running|not started'; then
    info "$(T "Хостер ещё делает первичную настройку (cloud-init: обновление системы, загрузчик, SSH)." \
              "The provider is still doing first-boot setup (cloud-init: upgrades, bootloader, SSH).")"
    info "$(T "Жду завершения — это не зависание. Ctrl+C и перезагрузку НЕ делай." \
              "Waiting for it to finish — this is not a hang. Do NOT press Ctrl+C or reboot.")"
    local waited=0 detail
    while cloud-init status 2>/dev/null | grep -qE 'running|not started'; do
      (( waited >= 2700 )) && die "$(T "cloud-init не завершился за 45 минут. Проверь: cloud-init status --long" "cloud-init did not finish in 45 minutes. Check: cloud-init status --long")"
      detail=$(tail -n 1 /var/log/cloud-init-output.log 2>/dev/null | tr -cd '[:print:]' | cut -c1-60)
      printf '\r    %2d:%02d  %-62s' $((waited / 60)) $((waited % 60)) "$detail"
      sleep 5; waited=$((waited + 5))
    done
    echo
    ok "$(T "Первичная настройка хостера завершена" "Provider first-boot setup finished")"
  fi

  # Current SSH ports — kept open until the new port is proven to work
  CURRENT_SSH_PORTS=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u | xargs)
  CURRENT_SSH_PORTS=${CURRENT_SSH_PORTS:-22}
}

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
    (( $(id -u "$1") >= 1000 )) || { warn "$(T "'$1' — системный пользователь, выбери другое имя" "'$1' is a system user, pick another name")"; return 1; }
  elif getent group "$1" >/dev/null; then
    # Ubuntu ships a system group called "admin" — adduser admin fails on it
    warn "$(T "Имя '$1' занято системной группой, выбери другое" "'$1' is taken by a system group, pick another name")"; return 1
  fi
}

# An existing account (the provider's "ubuntu" on AWS, say) is reused only on an explicit
# yes: it may already carry other people's keys or a NOPASSWD sudo rule from cloud-init.
confirm_existing_user() {
  id "$1" &>/dev/null || return 0
  local keys=0
  [[ -f /home/$1/.ssh/authorized_keys ]] && keys=$(grep -c . "/home/$1/.ssh/authorized_keys" || true)
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

port_busy() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }

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
    curl -fsSL "https://github.com/${GITHUB_KEYS_USER}.keys" >"$PUBKEY_FILE" || true
  fi
  while ! check_pubkeys "$PUBKEY_FILE"; do
    echo
    T "Откуда взять публичный SSH-ключ?" "Where should the public SSH key come from?"; echo
    T "  1) Вставить вручную (строка из ~/.ssh/id_ed25519.pub)" "  1) Paste it (the line from ~/.ssh/id_ed25519.pub)"; echo
    T "  2) Загрузить с GitHub (https://github.com/<ник>.keys)" "  2) Fetch from GitHub (https://github.com/<user>.keys)"; echo
    T "  3) Скопировать из /root/.ssh/authorized_keys" "  3) Copy from /root/.ssh/authorized_keys"; echo
    ask "$(T "Выбор" "Choice")" "1"
    case $REPLY in
      2) ask "$(T "Ник на GitHub" "GitHub username")"
         curl -fsSL "https://github.com/${REPLY}.keys" >"$PUBKEY_FILE" || warn "$(T "Не удалось скачать ключи" "Could not download the keys")" ;;
      3) cp /root/.ssh/authorized_keys "$PUBKEY_FILE" 2>/dev/null || warn "$(T "У root нет authorized_keys" "root has no authorized_keys")" ;;
      *) echo "$(T "Создать ключ на СВОЁМ компьютере:" "Create a key on YOUR computer:")  ssh-keygen -t ed25519 -C \"$NEW_USER@server\""
         ask "$(T "Вставь публичный ключ (ssh-ed25519 AAAA...)" "Paste the public key (ssh-ed25519 AAAA...)")"
         printf '%s\n' "$REPLY" >"$PUBKEY_FILE" ;;
    esac
  done

  local suggested
  suggested=$(shuf -i 20000-60999 -n 1)
  SSH_PORT=${SSH_PORT:-}
  until [[ $SSH_PORT =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1024 && SSH_PORT <= 65535 )) \
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
  if env_yn INSTALL_CROWDSEC "$(T "Установить CrowdSec (коллективный IPS, дополнение к fail2ban)?" \
                                  "Install CrowdSec (crowd-sourced IPS on top of fail2ban)?")" n; then INSTALL_CROWDSEC=yes; else INSTALL_CROWDSEC=no; fi
  if env_yn RUN_LYNIS "$(T "Запустить в конце аудит Lynis?" "Run a Lynis audit at the end?")" y; then RUN_LYNIS=yes; else RUN_LYNIS=no; fi
  if env_yn TELEGRAM "$(T "Уведомления в Telegram (входы по SSH, сбои, ежедневная сводка)?" \
                          "Telegram alerts (SSH logins, failures, daily report)?")" n; then
    ask_telegram
  else TELEGRAM=no; fi

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
  echo "  CrowdSec:           $INSTALL_CROWDSEC"
  echo "  Telegram:           $TELEGRAM${TG_CHAT_ID:+ (chat $TG_CHAT_ID)}"
  ask_yn "$(T "Начать настройку?" "Start?")" y || die "$(T "Отменено." "Cancelled.")"
}

check_pubkeys() {  # is the key file usable?
  local f=$1
  [[ -s $f ]] || return 1
  # keep key lines only
  grep -E '^(ssh-ed25519|sk-ssh-ed25519@openssh.com|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh.com) ' "$f" >"$f.clean" \
    || { rm -f "$f.clean"; warn "$(T "Ключи не найдены" "No keys found")"; return 1; }
  mv "$f.clean" "$f"
  if ! ssh-keygen -lf "$f" >/dev/null 2>&1; then warn "$(T "Ключ повреждён" "The key is damaged")"; return 1; fi
  while read -r bits type; do
    if [[ $type == "(RSA)" ]] && (( bits < 3072 )); then
      warn "$(T "RSA-ключ $bits бит слабый. Рекомендуется ed25519: ssh-keygen -t ed25519" "A $bits-bit RSA key is weak. Prefer ed25519: ssh-keygen -t ed25519")"
    fi
  done < <(ssh-keygen -lf "$f" | awk '{print $1, $NF}')
  return 0
}

# ---------- 2. packages ----------
install_packages() {
  step "$(T "Обновление системы и установка пакетов" "System upgrade and packages")"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  # Lock::Timeout — wait while apt is busy with auto-updates (common on a fresh VPS)
  local apt_opts=(-y -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  apt-get -o DPkg::Lock::Timeout=600 update -q
  apt-get "${apt_opts[@]}" full-upgrade
  local pkgs=(
    ufw fail2ban python3-systemd
    unattended-upgrades apt-listchanges needrestart debsums
    apparmor apparmor-utils
    chrony libpam-pwquality
    lynis curl ca-certificates gnupg sudo openssh-server
    libpam-tmpdir apt-show-versions acct sysstat
    rsyslog logrotate
  )
  [[ $IS_CONTAINER == no ]] && pkgs+=(auditd audispd-plugins)
  apt-get "${apt_opts[@]}" install "${pkgs[@]}"
  apt-get "${apt_opts[@]}" autoremove --purge
  # Leftover configs of removed packages (status rc)
  local rc_pkgs
  rc_pkgs=$(dpkg -l | awk '/^rc/{print $2}')
  # shellcheck disable=SC2086  # word splitting is intended: one argument per package
  [[ -n $rc_pkgs ]] && dpkg --purge $rc_pkgs >/dev/null
  ok "$(T "Пакеты установлены" "Packages installed")"
}

# ---------- 3. user ----------
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

  install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "/home/$NEW_USER/.ssh"
  local ak="/home/$NEW_USER/.ssh/authorized_keys"
  touch "$ak"
  while read -r line; do
    grep -qxF "$line" "$ak" || echo "$line" >>"$ak"
  done <"$PUBKEY_FILE"
  chown "$NEW_USER:$NEW_USER" "$ak"; chmod 600 "$ak"
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
    until passwd "$NEW_USER" </dev/tty >/dev/tty 2>&1; do warn "$(T "Попробуй ещё раз" "Try again")"; done
    USER_HAS_PASSWORD=yes
  fi

  # Log every sudo command, shorter credential cache
  cat >/etc/sudoers.d/99-hardening <<'EOF'
Defaults    use_pty
Defaults    logfile="/var/log/sudo.log"
Defaults    timestamp_timeout=15
Defaults    passwd_tries=3
EOF
  chmod 440 /etc/sudoers.d/99-hardening
  visudo -cq || { rm -f /etc/sudoers.d/99-hardening; die "$(T "Ошибка sudoers" "sudoers error")"; }
  ok "$(T "Пользователь готов" "User ready")"
}

lock_other_users() {
  [[ $LOCK_OTHER_USERS == yes ]] || return 0
  step "$(T "Блокировка лишних аккаунтов:" "Locking extra accounts:") $OTHER_USERS"
  local u f g
  for u in $OTHER_USERS; do
    usermod -L -s /usr/sbin/nologin "$u"
    for g in sudo adm lxd docker; do gpasswd -d "$u" "$g" &>/dev/null || true; done
    [[ -f /home/$u/.ssh/authorized_keys ]] && mv "/home/$u/.ssh/authorized_keys" "$BACKUP_DIR/authorized_keys.$u"
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

# ---------- 4. system ----------
harden_system() {
  step "$(T "Ядро и система" "Kernel and system")"

  cat >/etc/sysctl.d/99-hardening.conf <<'EOF'
# --- kernel ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.perf_event_paranoid = 3
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
# --- IPv4 ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# --- IPv6 ---
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# --- performance ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# --- misc (Lynis KRNL-6000) ---
dev.tty.ldisc_autoload = 0
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
EOF
  sysctl --system >/dev/null 2>&1 || warn "$(T "Часть sysctl не применилась (нормально для контейнеров)" "Some sysctl values were not applied (normal in containers)")"

  # No core dumps
  echo '* hard core 0' >/etc/security/limits.d/99-nocore.conf
  mkdir -p /etc/systemd/coredump.conf.d
  printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' >/etc/systemd/coredump.conf.d/99-hardening.conf

  # Persistent, size-capped journal
  mkdir -p /etc/systemd/journald.conf.d
  printf '[Journal]\nStorage=persistent\nSystemMaxUse=500M\nMaxRetentionSec=3month\n' >/etc/systemd/journald.conf.d/99-hardening.conf
  systemctl restart systemd-journald

  # Accurate time matters for logs, TLS and 2FA
  systemctl enable --now chrony >/dev/null 2>&1 || true

  if [[ $IS_CONTAINER == no ]]; then
    systemctl enable --now apparmor >/dev/null 2>&1 || warn "$(T "AppArmor не запустился" "AppArmor did not start")"
  fi

  # Legal banner (shown before login)
  cat >/etc/issue.net <<'EOF'
This is a private system. Authorized access only.
Unauthorized access is prohibited and may be prosecuted under applicable law.
All connections are monitored and logged; records may be used as evidence.
EOF
  cp /etc/issue.net /etc/issue

  # Unused filesystems and network protocols
  cat >/etc/modprobe.d/99-hardening.conf <<'EOF'
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install jffs2 /bin/false
install udf /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
install usb-storage /bin/false
EOF

  # login.defs: new files not world-readable (027), more password hashing rounds
  sed -i -E 's/^UMASK[[:space:]]+.*/UMASK\t\t027/' /etc/login.defs
  grep -q '^SHA_CRYPT_MIN_ROUNDS' /etc/login.defs || printf 'SHA_CRYPT_MIN_ROUNDS 65536\nSHA_CRYPT_MAX_ROUNDS 131072\n' >>/etc/login.defs

  # Process accounting and load history — useful when investigating an incident
  systemctl enable --now acct &>/dev/null || true
  if [[ -f /etc/default/sysstat ]]; then
    sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
    systemctl enable --now sysstat &>/dev/null || true
  fi

  # Services a server does not need
  local svc
  for svc in ModemManager udisks2; do
    systemctl list-unit-files "$svc.service" &>/dev/null && systemctl disable --now "$svc.service" &>/dev/null \
      && info "$(T "Отключена служба" "Disabled service") $svc" || true
  done

  chmod 600 /etc/crontab 2>/dev/null || true
  chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
  chmod 750 /home/"$NEW_USER"

  ok "$(T "Система усилена" "System hardened")"
}

setup_auditd() {
  [[ $IS_CONTAINER == yes ]] && { info "$(T "Контейнер — auditd пропущен" "Container — auditd skipped")"; return; }
  step "auditd"
  cat >/etc/audit/rules.d/99-hardening.rules <<'EOF'
-D
-b 8192
-f 1
# Users and privileges
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
# SSH
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k root_ssh
# Schedulers
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
# Time
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time
# Commands run as root by a logged-in user
-a always,exit -F arch=b64 -F euid=0 -F auid>=1000 -F auid!=unset -S execve -k root_cmd
EOF
  systemctl enable auditd >/dev/null 2>&1 || true
  augenrules --load >/dev/null 2>&1 || service auditd restart || warn "$(T "auditd не перезапустился" "auditd did not restart")"
  ok "$(T "auditd настроен (поиск: ausearch -k identity)" "auditd configured (search: ausearch -k identity)")"
}

setup_autoupdates() {
  step "$(T "Автоматические обновления безопасности" "Automatic security updates")"
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  cat >/etc/apt/apt.conf.d/52-hardening-unattended <<EOF
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Automatic-Reboot "$([[ $AUTO_REBOOT == yes ]] && echo true || echo false)";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME:-04:00}";
EOF
  mkdir -p /etc/needrestart/conf.d
  echo "\$nrconf{restart} = 'a';" >/etc/needrestart/conf.d/99-hardening.conf
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "$(T "Обновления безопасности ставятся автоматически" "Security updates install automatically")"
}

# ---------- 5. firewall ----------
setup_firewall() {
  step "Firewall (UFW)"
  # No reset — rules added by hand survive a re-run
  ufw default deny incoming
  ufw default allow outgoing
  ufw default deny routed
  local p
  # The new port is never added as a plain allow: UFW stops at the first match, and a plain
  # allow before the limit rule would switch rate limiting off (re-run with the same port)
  for p in $CURRENT_SSH_PORTS; do
    [[ $p == "$SSH_PORT" ]] && continue
    ufw allow "$p/tcp" comment 'SSH (temporary)' >/dev/null
  done
  # The admin is not rate-limited: this rule precedes the limit rule and UFW stops at the first match
  [[ -n $ADMIN_IP ]] && ufw allow from "$ADMIN_IP" to any port "$SSH_PORT" proto tcp comment 'SSH admin' >/dev/null
  ufw limit "$SSH_PORT/tcp" comment 'SSH' >/dev/null
  local -a extra
  IFS=, read -ra extra <<<"$EXTRA_PORTS"
  for p in "${extra[@]}"; do
    [[ -z $p ]] && continue
    if [[ $p =~ ^[0-9]+(:[0-9]+)?(/(tcp|udp))?$ ]]; then ufw allow "$p" >/dev/null
    else warn "$(T "Пропущен неверный порт:" "Invalid port skipped:") $p"; fi
  done
  ufw logging low
  ufw --force enable
  ok "$(T "UFW включён" "UFW enabled")"
}

setup_fail2ban() {
  step "fail2ban"
  cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
backend            = systemd
bantime            = 1h
bantime.increment  = true
bantime.factor     = 2
bantime.maxtime    = 4w
findtime           = 10m
maxretry           = 4
ignoreip           = 127.0.0.1/8 ::1 ${ADMIN_IP}
banaction          = ufw

[sshd]
enabled  = true
port     = $SSH_PORT
mode     = aggressive

[recidive]
enabled  = true
backend  = auto
logpath  = /var/log/fail2ban.log
bantime  = 4w
findtime = 1d
maxretry = 3
EOF
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  ok "$(T "fail2ban включён (статус: fail2ban-client status sshd)" "fail2ban enabled (status: fail2ban-client status sshd)")"
}

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
  systemctl cat "$1.service" >/dev/null 2>&1 || return 0
  local state
  state=$(systemctl is-active "$1" 2>/dev/null)
  case $state in
    active) printf " %-10s %b\n" "$1" "${GREEN}✓${NC}" ;;
    # Right after boot some services take a while (CrowdSec: ~20 s) — not a failure
    activating|reloading) printf " %-10s %b\n" "$1" "${YELLOW}… starting${NC}" ;;
    *) printf " %-10s %b\n" "$1" "${RED}✗ ${state:-unknown}${NC}" ;;
  esac
}

LOCAL_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')
OS=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")
USER_NAME=$(id -un)
if [ "$USER_NAME" = root ]; then USER_C="${RED}${USER_NAME}${NC}"; else USER_C="${GOLD}${USER_NAME}${NC}"; fi
read -r RAM_TOTAL RAM_AVAIL < <(free -m | awk '/^Mem:/{print $2, $7}')
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
kv "Uptime"   "$(uptime -p | sed 's/^up //')"
if [ "${UPDATES:-0}" -gt 0 ]; then kv "Updates" "${RED}${UPDATES}${NC}"; else kv "Updates" "${GREEN}0${NC}"; fi
[ -f /var/run/reboot-required ] && kv "Reboot" "${RED}required (sudo reboot)${NC}"
line "----------------------------------------"
kv "CPU"      "$(nproc) cores"
kv "RAM"      "${RAM_TOTAL} MB total, ${RAM_AVAIL} MB free ($(pct $(( RAM_AVAIL * 100 / RAM_TOTAL ))))"
kv "Disk /"   "${DISK_SIZE} total, ${DISK_AVAIL} free ($(pct $(( 100 - ${DISK_USED%\%} ))))"
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

  # Drop the whole stock greeting (Welcome, ESM, ads, legal) — the summary replaces it.
  # dpkg-statoverride instead of editing files: the mode survives package upgrades, and
  # edited conffiles would make unattended-upgrades skip openssh/bash security updates.
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
    [[ -d $home/.cache ]] || install -d -m 700 -o "$u" -g "$(id -gn "$u")" "$home/.cache"
    install -o "$u" -g "$(id -gn "$u")" -m 644 /dev/null "$home/.sudo_as_admin_successful"
    install -o "$u" -g "$(id -gn "$u")" -m 644 /dev/null "$home/.cache/motd.legal-displayed"
  done < <(awk -F: '$3>=1000 && $3<60000' /etc/passwd)
  ok "$(T "Сводка будет показываться при входе вместо стандартного приветствия. Вручную: server-status" \
          "The summary replaces the stock login greeting. Run it any time: server-status")"
}

# CrowdSec's apt repository is set up here rather than by piping install.crowdsec.net
# into sh, so no third-party code runs as root. What is trusted instead is one signing
# key, and only if its fingerprint matches the one pinned below — cross-checked against
# packagecloud.io, keyserver.ubuntu.com and keys.openpgp.org, and verified to sign the
# repository's InRelease. apt is then allowed to take only CrowdSec's own packages from
# that repository, so even a compromised repository cannot ship a new openssh or sudo.
CROWDSEC_REPO="https://packagecloud.io/crowdsec/crowdsec/any"
CROWDSEC_KEY_URL="https://packagecloud.io/crowdsec/crowdsec/gpgkey"
CROWDSEC_KEY_FPR="6A89E3C2303A901A889971D3376ED5326E93CD0C"
CROWDSEC_ORIGIN="packagecloud.io/crowdsec/crowdsec"

setup_crowdsec_repo() {
  local tmp fpr keyring=/etc/apt/keyrings/crowdsec.gpg
  tmp=$(mktemp -d)
  if ! curl -fsSL --proto '=https' --tlsv1.2 "$CROWDSEC_KEY_URL" -o "$tmp/key.asc"; then
    rm -rf "$tmp"
    warn "$(T "Не удалось скачать ключ CrowdSec" "Could not download the CrowdSec key")"; return 1
  fi
  # Armored or binary — either way the fingerprint check below decides
  if grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "$tmp/key.asc"; then
    gpg --batch --quiet --homedir "$tmp" --dearmor -o "$tmp/key.gpg" "$tmp/key.asc" 2>/dev/null || true
  else
    cp "$tmp/key.asc" "$tmp/key.gpg"
  fi
  fpr=$(gpg --batch --homedir "$tmp" --show-keys --with-colons "$tmp/key.gpg" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
  if [[ $fpr != "$CROWDSEC_KEY_FPR" ]]; then
    rm -rf "$tmp"
    warn "$(T "Отпечаток ключа CrowdSec не совпал (ожидался $CROWDSEC_KEY_FPR, получен ${fpr:-ничего}) — репозиторий не подключён" \
              "CrowdSec key fingerprint mismatch (expected $CROWDSEC_KEY_FPR, got ${fpr:-nothing}) — repository not added")"
    return 1
  fi
  install -d -m 755 /etc/apt/keyrings
  install -m 644 "$tmp/key.gpg" "$keyring"
  rm -rf "$tmp"
  echo "deb [signed-by=$keyring] $CROWDSEC_REPO any main" >/etc/apt/sources.list.d/crowdsec.list
  # Specific record first: whichever way apt ranks records, CrowdSec's packages get 500
  # and everything else from this origin gets -1 (never installed)
  cat >/etc/apt/preferences.d/crowdsec <<EOF
# harden.sh: only CrowdSec's own packages may come from its repository
Package: crowdsec crowdsec-firewall-bouncer-nftables
Pin: release o=$CROWDSEC_ORIGIN
Pin-Priority: 500

Package: *
Pin: release o=$CROWDSEC_ORIGIN
Pin-Priority: -1
EOF
  if ! apt-get -o DPkg::Lock::Timeout=600 update -q; then
    rm -f /etc/apt/sources.list.d/crowdsec.list /etc/apt/preferences.d/crowdsec "$keyring"
    warn "$(T "apt update с репозиторием CrowdSec не прошёл — репозиторий убран" "apt update with the CrowdSec repository failed — repository removed")"
    return 1
  fi
  ok "$(T "Репозиторий CrowdSec подключён (ключ $CROWDSEC_KEY_FPR проверен)" "CrowdSec repository added (key $CROWDSEC_KEY_FPR verified)")"
}

setup_crowdsec() {
  [[ $INSTALL_CROWDSEC == yes ]] || return 0
  step "CrowdSec"
  if ! setup_crowdsec_repo; then
    warn "$(T "CrowdSec пропущен, fail2ban защищает SSH и без него" "CrowdSec skipped; fail2ban protects SSH without it")"
    return 0
  fi
  local apt_opts=(-y -o DPkg::Lock::Timeout=600)
  # Engine first (it creates /etc/crowdsec/config.yaml), then the bouncer — installed
  # together, apt may configure the bouncer first and it fails without config.yaml
  apt-get "${apt_opts[@]}" install crowdsec
  if [[ -n $ADMIN_IP ]]; then
    mkdir -p /etc/crowdsec/parsers/s02-enrich
    cat >/etc/crowdsec/parsers/s02-enrich/99-harden-admin-whitelist.yaml <<EOF
name: harden/admin-whitelist
description: "Admin IP whitelisted by harden.sh"
whitelist:
  reason: "admin ip (harden.sh)"
  ip:
    - "$ADMIN_IP"
EOF
  fi
  cscli collections install crowdsecurity/linux crowdsecurity/sshd >/dev/null 2>&1 || true
  systemctl restart crowdsec
  apt-get "${apt_opts[@]}" install crowdsec-firewall-bouncer-nftables
  # CrowdSec's own security fixes arrive the same way as the system's
  cat >/etc/apt/apt.conf.d/53-hardening-crowdsec <<EOF
Unattended-Upgrade::Origins-Pattern { "origin=$CROWDSEC_ORIGIN"; };
EOF
  if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
    ok "$(T "CrowdSec и bouncer работают (cscli decisions list)" "CrowdSec and bouncer running (cscli decisions list)")"
  else
    warn "$(T "CrowdSec установлен, но не всё запущено: systemctl status crowdsec crowdsec-firewall-bouncer" \
              "CrowdSec installed but not everything runs: systemctl status crowdsec crowdsec-firewall-bouncer")"
  fi
}

# ---------- 6. SSH ----------
filter_algos() {  # filter_algos <ssh -Q type> algorithms... -> the supported ones, comma-separated
  local type=$1; shift
  local supported out=() a
  supported=$(ssh -Q "$type" 2>/dev/null)
  for a in "$@"; do grep -qxF "$a" <<<"$supported" && out+=("$a"); done
  (IFS=,; echo "${out[*]}")
}

ssh_service() { systemctl list-unit-files ssh.service &>/dev/null && echo ssh || echo sshd; }

write_sshd_config() {  # write_sshd_config "port1 port2 ..."
  local ports=$1 p kex ciphers macs hostkeys
  kex=$(filter_algos kex mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com \
        curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group18-sha512 diffie-hellman-group16-sha512)
  ciphers=$(filter_algos cipher chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes128-ctr)
  macs=$(filter_algos mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com)
  hostkeys=$(filter_algos key-sig ssh-ed25519 rsa-sha2-512 rsa-sha2-256)

  {
    echo "# Generated by harden.sh $(date -Is). First match wins — this file is read first."
    for p in $ports; do echo "Port $p"; done
    cat <<EOF
AddressFamily any

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# --- Authentication: keys only, no root ---
PermitRootLogin no
AllowUsers $NEW_USER
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
UsePAM yes
StrictModes yes

# --- Limits ---
MaxAuthTries 3
MaxSessions 2
TCPKeepAlive no
MaxStartups 10:30:60
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Off. SSH tunnels and VS Code Remote-SSH need: AllowTcpForwarding local ---
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
PrintMotd no
UseDNS no
Compression no
DebianBanner no

Banner /etc/issue.net
LogLevel VERBOSE

# --- Crypto (only what this OpenSSH supports, post-quantum KEX first) ---
EOF
    # An empty list (old OpenSSH without that ssh -Q type) would break sshd — skip the line
    [[ -n $kex ]]      && echo "KexAlgorithms $kex"
    [[ -n $ciphers ]]  && echo "Ciphers $ciphers"
    [[ -n $macs ]]     && echo "MACs $macs"
    [[ -n $hostkeys ]] && echo "HostKeyAlgorithms $hostkeys"
    true
  } >"$SSHD_DROPIN"
  chmod 600 "$SSHD_DROPIN"
}

restart_sshd() {
  sshd -t || return 1
  systemctl restart "$(ssh_service)"
}

rollback_ssh() {
  warn "$(T "Откат настроек SSH..." "Rolling SSH back...")"
  rm -f "$SSHD_DROPIN"
  cp -a "$BACKUP_DIR/ssh/." /etc/ssh/
  systemctl restart "$(ssh_service)" || true
}

setup_ssh() {
  step "SSH"
  mkdir -p /etc/ssh/sshd_config.d /run/sshd
  grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config \
    || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config

  # Host keys: drop DSA/ECDSA, regenerate RSA below 3072 bits
  rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key*
  [[ -f /etc/ssh/ssh_host_ed25519_key ]] || ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
  if [[ ! -f /etc/ssh/ssh_host_rsa_key ]] || (( $(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key | awk '{print $1}') < 3072 )); then
    rm -f /etc/ssh/ssh_host_rsa_key*; ssh-keygen -q -t rsa -b 4096 -N "" -f /etc/ssh/ssh_host_rsa_key
  fi
  # Weak DH groups
  if [[ -f /etc/ssh/moduli ]]; then
    awk '$5 >= 3071' /etc/ssh/moduli >/etc/ssh/moduli.safe && [[ -s /etc/ssh/moduli.safe ]] && mv /etc/ssh/moduli.safe /etc/ssh/moduli
  fi

  # Ubuntu 22.10+: ssh.socket ignores Port — switch to the plain service
  if systemctl is-enabled ssh.socket &>/dev/null; then
    info "$(T "Отключаю ssh.socket (socket activation), включаю ssh.service" "Disabling ssh.socket (socket activation), enabling ssh.service")"
    systemctl disable ssh.socket &>/dev/null || true
    systemctl enable ssh.service &>/dev/null
  fi

  # Stage 1: old and new port side by side
  local ports="$CURRENT_SSH_PORTS"
  [[ " $ports " == *" $SSH_PORT "* ]] || ports="$ports $SSH_PORT"
  write_sshd_config "$ports"
  if ! sshd -t; then rollback_ssh; die "$(T "Конфиг sshd не прошёл проверку — откатил." "sshd config failed the check — rolled back.")"; fi
  systemctl stop ssh.socket &>/dev/null || true
  restart_sshd || { rollback_ssh; die "$(T "sshd не перезапустился — откатил." "sshd did not restart — rolled back.")"; }
  ok "$(T "sshd слушает порты:" "sshd listens on ports:") $ports"

  # The admin proves the new login works before anything is closed
  local ip
  ip=$(curl -fsS4 --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
  echo
  echo "${C_BOLD}${C_Y}╔════════════════════════════════════════════════════════════╗"
  if [[ $UI == ru ]]; then
    echo "║  НЕ ЗАКРЫВАЙ ЭТО ОКНО! Открой НОВЫЙ терминал и проверь:   ║"
  else
    echo "║  DO NOT CLOSE THIS WINDOW! Open a NEW terminal and check: ║"
  fi
  echo "╚════════════════════════════════════════════════════════════╝${C_0}"
  echo
  echo "     ssh -p $SSH_PORT $NEW_USER@$ip"
  if [[ $USER_HAS_PASSWORD == yes ]]; then
    echo "     sudo -v        # $(T "проверить, что sudo работает (введи пароль)" "check that sudo works (enter the password)")"
  fi
  echo
  T "  Не пускает (timeout)? У облачных хостеров есть свой firewall в панели" \
    "  Timing out? Cloud providers have their own firewall in the control panel"; echo
  T "  (AWS Security Group, Hetzner/Oracle/GCP Firewall) — открой там TCP $SSH_PORT и проверь снова." \
    "  (AWS Security Group, Hetzner/Oracle/GCP Firewall) — open TCP $SSH_PORT there and try again."; echo
  echo
  local tries=0
  until ask_yn "$(T "Вход по ключу на порт $SSH_PORT работает?" "Does key login on port $SSH_PORT work?")" n; do
    tries=$((tries+1))
    if (( tries >= 3 )) || ! ask_yn "$(T "Попробовать ещё раз? (нет = откатить SSH)" "Try again? (no = roll SSH back)")" y; then
      rollback_ssh
      die "$(T "SSH откатан к исходному состоянию. Firewall пропускает оба порта. Проверь ключ и запусти снова." \
               "SSH rolled back to how it was. The firewall allows both ports. Check the key and run again.")"
    fi
  done

  # Stage 2: new port only
  write_sshd_config "$SSH_PORT"
  restart_sshd || { rollback_ssh; die "$(T "Ошибка при финальном перезапуске sshd — откатил." "Final sshd restart failed — rolled back.")"; }
  local p
  for p in $CURRENT_SSH_PORTS; do
    [[ $p == "$SSH_PORT" ]] && continue
    ufw delete allow "$p/tcp" >/dev/null 2>&1 || true
  done
  ufw delete allow OpenSSH >/dev/null 2>&1 || true
  ok "$(T "SSH только на порту $SSH_PORT, только по ключу, root запрещён" "SSH on port $SSH_PORT only, keys only, root denied")"
}

lock_root() {
  [[ $LOCK_ROOT == yes ]] || return 0
  step "$(T "Блокировка root" "Locking root")"
  if [[ $USER_HAS_PASSWORD != yes ]]; then
    warn "$(T "У $NEW_USER нет пароля — root НЕ блокирую, иначе sudo будет недоступен." "$NEW_USER has no password — root is NOT locked, or sudo would be unreachable.")"
    warn "$(T "Задай пароль (passwd $NEW_USER), затем: sudo passwd -l root" "Set one (passwd $NEW_USER), then: sudo passwd -l root")"
    LOCK_ROOT="no ($NEW_USER: no password)"
    return 0
  fi
  passwd -l root >/dev/null
  # root can no longer log in over SSH, so its keys are moved to the backup
  if [[ -s /root/.ssh/authorized_keys ]]; then
    mv /root/.ssh/authorized_keys "$BACKUP_DIR/root_authorized_keys"
  fi
  ok "$(T "Пароль root заблокирован. Для админки: sudo -i" "root password locked. For admin work: sudo -i")"
  warn "$(T "Консоль VPS у хостера (VNC) — входи как $NEW_USER." "Provider's VPS console (VNC) — log in as $NEW_USER.")"
}

# ---------- 7. report ----------
final_report() {
  if [[ $RUN_LYNIS == yes ]]; then
    step "$(T "Аудит Lynis (1–2 минуты)" "Lynis audit (1–2 minutes)")"
    lynis audit system --quick --no-colors >/var/log/lynis-harden.log 2>&1 || true
    HARDENING_INDEX=$(grep -oP 'Hardening index : \K[0-9]+' /var/log/lynis-harden.log || echo "?")
  fi

  {
    echo "Server hardening report — $(date)"
    echo "OS: $OS_NAME   virt: $VIRT"
    echo
    echo "$(T "Пользователь:   " "User:           ") $NEW_USER (sudo)"
    echo "$(T "Подключение:    " "Connect:        ") ssh -p $SSH_PORT $NEW_USER@<IP>"
    echo "Root:            $(T "вход по SSH запрещён; пароль заблокирован:" "SSH login denied; password locked:") $LOCK_ROOT"
    echo "Firewall:"; ufw status verbose | sed 's/^/  /'
    echo "fail2ban:        $(systemctl is-active fail2ban)"
    echo "CrowdSec:        $INSTALL_CROWDSEC"
    echo "$(T "Автообновления: " "Auto-updates:   ") $(T "да, автоперезагрузка:" "yes, auto reboot:") $AUTO_REBOOT ${REBOOT_TIME:-}"
    [[ -n ${HARDENING_INDEX:-} ]] && echo "Lynis index:     $HARDENING_INDEX/100 (/var/log/lynis-harden.log)"
    echo
    echo "$(T "Бэкап исходных конфигов:" "Original config backup:") $BACKUP_DIR"
    echo "$(T "Лог установки:          " "Setup log:              ") $LOG_FILE"
  } | tee "$REPORT_FILE"
  chmod 600 "$REPORT_FILE"

  echo
  ok "${C_BOLD}$(T "Готово!" "Done!")${C_0} $(T "Отчёт:" "Report:") $REPORT_FILE"
  echo
  T "Полезные команды:" "Useful commands:"; echo
  echo "  sudo ufw status                   — $(T "правила firewall" "firewall rules")"
  echo "  sudo ufw allow 443/tcp            — $(T "открыть порт" "open a port")"
  echo "  sudo fail2ban-client status sshd  — $(T "забаненные IP" "banned IPs")"
  echo "  sudo ausearch -k identity -i      — $(T "кто менял пользователей" "who changed accounts")"
  echo "  sudo lynis audit system           — $(T "полный аудит" "full audit")"
  echo "  server-status                     — $(T "сводка о сервере" "server summary")"
  echo "  sudo harden --check               — $(T "проверить защиту сервера" "audit the server")"
  [[ ${TELEGRAM:-no} == yes ]] || echo "  sudo harden --setup-telegram      — $(T "подключить уведомления" "add Telegram alerts")"
  warn "$(T "Docker публикует порты в обход UFW! Используй -p 127.0.0.1:PORT:PORT или ufw-docker." \
            "Docker publishes ports around UFW! Use -p 127.0.0.1:PORT:PORT or ufw-docker.")"
  if [[ -f /var/run/reboot-required ]]; then
    echo
    warn "$(T "Нужна перезагрузка: установлено новое ядро" "Reboot needed: a new kernel is installed") ($(uname -r) -> $(ls -1 /boot/vmlinuz-* | sort -V | tail -1 | sed 's|.*/vmlinuz-||'))"
    if env_yn REBOOT_NOW "$(T "Перезагрузить сейчас? (после — входи: ssh -p $SSH_PORT $NEW_USER@<IP>)" \
                              "Reboot now? (then log in: ssh -p $SSH_PORT $NEW_USER@<IP>)")" y; then
      # Never reboot in the middle of a package install (GRUB/kernel).
      # Not by process name "unattended-upgr" — its shutdown helper is always running; use dpkg locks.
      local w=0
      while pgrep -x 'apt|apt-get|dpkg' >/dev/null \
            || { command -v fuser >/dev/null && fuser -s /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock 2>/dev/null; } \
            || cloud-init status 2>/dev/null | grep -q running; do
        (( w == 0 )) && info "$(T "Жду окончания установки пакетов перед перезагрузкой..." "Waiting for package installs to finish before rebooting...")"
        (( w >= 1800 )) && { warn "$(T "Пакеты ставятся уже 30 минут — перезагрузку отменяю. Сделай позже: sudo reboot" "Packages have been installing for 30 minutes — reboot cancelled. Later: sudo reboot")"; return 0; }
        sleep 5; w=$((w + 5))
      done
      info "$(T "Перезагрузка через 5 секунд..." "Rebooting in 5 seconds...")"
      systemd-run --on-active=5 --unit=harden-reboot systemctl reboot >/dev/null
    fi
  fi
}

# ---------- Telegram alerts ----------
# tg_api TOKEN METHOD [curl args] — the token goes to curl on stdin as a config line,
# never on a command line, where any local user could read it from ps.
tg_api() {
  local token=$1 method=$2; shift 2
  printf 'url = "%s/bot%s/%s"\n' "${HARDEN_TG_API:-https://api.telegram.org}" "$token" "$method" \
    | curl -sS --max-time 15 -K - "$@" 2>/dev/null || true
}

ask_telegram() {  # sets TG_TOKEN / TG_CHAT_ID, or TELEGRAM=no if the admin gives up
  local token=${TG_TOKEN:-} chat=${TG_CHAT_ID:-} bot=""
  T "  1) В Telegram откройте @BotFather → /newbot → скопируйте токен бота" \
    "  1) In Telegram open @BotFather → /newbot → copy the bot token"; echo
  until [[ $token =~ ^[0-9]{5,}:[A-Za-z0-9_-]{30,}$ ]] && tg_api "$token" getMe | grep -q '"ok":true'; do
    [[ -n $token ]] && warn "$(T "Telegram не принял токен" "Telegram rejected the token")"
    read -r -s -p "$(T "Токен бота (ввод скрыт, пусто — пропустить): " "Bot token (hidden, empty to skip): ")" token </dev/tty; echo
    [[ -z $token ]] && { TELEGRAM=no; return 0; }
  done
  bot=$(tg_api "$token" getMe | grep -o '"username":"[^"]*"' | cut -d'"' -f4)
  if [[ ! $chat =~ ^-?[0-9]+$ ]]; then
    T "  2) Откройте https://t.me/$bot, нажмите Start (или отправьте любое сообщение) и нажмите Enter здесь" \
      "  2) Open https://t.me/$bot, press Start (or send any message), then press Enter here"; echo
    read -r _ </dev/tty
    chat=$(tg_api "$token" getUpdates | grep -o '"chat":{"id":-\{0,1\}[0-9]*' | tail -1 | grep -o -- '-\{0,1\}[0-9]*$' || true)
    until [[ $chat =~ ^-?[0-9]+$ ]]; do
      ask "$(T "Chat ID не найден автоматически — введите вручную" "Chat ID not found automatically — enter it")"; chat=$REPLY
    done
  fi
  tg_api "$token" sendMessage --data-urlencode "chat_id=$chat" \
    --data-urlencode "text=✅ $(hostname): $(T "уведомления harden.sh подключаются" "harden.sh alerts are being set up")" -o /dev/null
  if ask_yn "$(T "Тестовое сообщение пришло в Telegram?" "Did the test message arrive in Telegram?")" y; then
    TG_TOKEN=$token; TG_CHAT_ID=$chat; TELEGRAM=yes
  else
    warn "$(T "Telegram пропущен. Позже: sudo harden --setup-telegram" "Telegram skipped. Later: sudo harden --setup-telegram")"
    TELEGRAM=no
  fi
}

install_notifications() {
  [[ ${TELEGRAM:-no} == yes ]] || return 0
  step "$(T "Уведомления в Telegram" "Telegram alerts")"
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
printf 'url = "%s/bot%s/sendMessage"\n' "${api:-https://api.telegram.org}" "$token" \
  | curl -sS --max-time 15 --retry 3 --retry-delay 5 -K - -o /dev/null \
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
journalctl -f -n 0 -o cat SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session 2>/dev/null |
while IFS= read -r line; do
  case $line in
    "Accepted "*)
      # Accepted <method> for <user> from <ip> port <port> ssh2[: <type> <fingerprint>]
      read -r -a f <<<"$line"
      /usr/local/sbin/harden-notify "🔑 SSH login: ${f[3]:-?} from ${f[5]:-?} (${f[1]:-?}${f[9]:+, ${f[9]}}${f[10]:+ ${f[10]}})" &
      ;;
  esac
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
acc=$(journalctl --since "$since" -o cat SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session 2>/dev/null | grep '^Accepted ' || true)
nlog=$(printf '%s' "$acc" | grep -c . || true)
who=$(printf '%s' "$acc" | awk 'NF{print $4"@"$6}' | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s%s×%s", (NR>1?", ":""), $2, $1}')
bans=0
[ -r /var/log/fail2ban.log ] && bans=$(awk -v s="$since" '($1" "substr($2,1,8)) >= s && / Ban /' /var/log/fail2ban.log | wc -l)
banned=$(fail2ban-client status sshd 2>/dev/null | awk -F'\t' '/Currently banned/{print $2}')
failed=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | paste -sd' ' -)
disk=$(df -h --output=avail,pcent / | awk 'NR==2{print $1" free ("$2" used)"}')
ram=$(free -m | awk '/^Mem:/{print $7" MB free of "$2}')

msg="📊 Daily report
Uptime: $(uptime -p | sed 's/^up //'), load $(cut -d' ' -f1-3 /proc/loadavg)
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
    mkdir -p "/etc/systemd/system/$u.service.d"
    printf '[Unit]\nOnFailure=harden-alert@%%n.service\n' >"/etc/systemd/system/$u.service.d/harden-alert.conf"
  done
  systemctl daemon-reload
  systemctl enable --now harden-login-watch.service harden-daily-report.timer &>/dev/null \
    || warn "$(T "Не удалось запустить службы уведомлений" "Could not start the alert services")"
  systemctl enable harden-boot-alert.service &>/dev/null || true
  /usr/local/sbin/harden-notify "✅ $(T "Уведомления включены: входы по SSH, падения служб, загрузка, сводка в" "Alerts on: SSH logins, failed services, boot, daily report at") ${TG_REPORT_TIME:-09:00} $(date +%Z)"
  ok "$(T "Telegram: входы по SSH, падения служб, загрузка, ежедневная сводка" "Telegram: SSH logins, failed services, boot, daily report")"
}

# ---------- --check: audit only, nothing is changed ----------
CHK_PASS=0; CHK_WARN=0; CHK_FAIL=0
chk() {  # chk pass|warn|fail "text"
  case $1 in
    pass) CHK_PASS=$((CHK_PASS + 1)); echo "  ${C_G}✓${C_0} $2" ;;
    warn) CHK_WARN=$((CHK_WARN + 1)); echo "  ${C_Y}!${C_0} $2" ;;
    *)    CHK_FAIL=$((CHK_FAIL + 1)); echo "  ${C_R}✗${C_0} $2" ;;
  esac
}

run_check() {
  local cfg v kex weak n list u
  . /etc/os-release
  step "$(T "Проверка сервера — ничего не меняется" "Server check — nothing is changed")"
  echo "  ${PRETTY_NAME:-?}, kernel $(uname -r)"

  echo; echo "${C_BOLD}SSH${C_0}"
  cfg=$(sshd -T 2>/dev/null || true)
  sv() { awk -v k="$1" '$1==k{$1=""; sub(/^ /,""); print; exit}' <<<"$cfg"; }
  if [[ -z $cfg ]]; then
    chk fail "$(T "sshd -T не отработал — конфиг SSH не читается" "sshd -T failed — the SSH config cannot be read")"
  else
    v=$(awk '$1=="port"{print $2}' <<<"$cfg" | paste -sd' ' -)
    [[ " $v " == *" 22 "* ]] && chk warn "$(T "Порт 22 (много шума от ботов)" "Port 22 (lots of bot noise)")" || chk pass "$(T "Порт" "Port") $v"
    [[ $(sv permitrootlogin) == no ]] && chk pass "PermitRootLogin no" || chk fail "PermitRootLogin $(sv permitrootlogin)"
    [[ $(sv passwordauthentication) == no ]] && chk pass "PasswordAuthentication no" || chk fail "PasswordAuthentication $(sv passwordauthentication)"
    [[ $(sv kbdinteractiveauthentication) == no ]] && chk pass "KbdInteractiveAuthentication no" || chk fail "KbdInteractiveAuthentication $(sv kbdinteractiveauthentication)"
    [[ $(sv permitemptypasswords) == no ]] && chk pass "PermitEmptyPasswords no" || chk fail "PermitEmptyPasswords $(sv permitemptypasswords)"
    v=$(sv maxauthtries); (( ${v:-6} <= 3 )) && chk pass "MaxAuthTries $v" || chk warn "MaxAuthTries $v ($(T "лучше" "better") ≤ 3)"
    [[ $(sv x11forwarding) == no ]] && chk pass "X11Forwarding no" || chk warn "X11Forwarding $(sv x11forwarding)"
    [[ -n $(sv allowusers) ]] && chk pass "AllowUsers $(sv allowusers)" || chk warn "$(T "AllowUsers не задан — войти может любой пользователь с ключом" "AllowUsers not set — any user with a key can log in")"
    kex=$(sv kexalgorithms)
    [[ $kex =~ mlkem768|sntrup761 ]] && chk pass "$(T "Постквантовый обмен ключами" "Post-quantum key exchange")" \
      || chk warn "$(T "Нет постквантового обмена ключами (mlkem768/sntrup761)" "No post-quantum key exchange (mlkem768/sntrup761)")"
    weak=$(tr ',' '\n' <<<"$kex,$(sv ciphers),$(sv macs),$(sv hostkeyalgorithms)" \
           | grep -E 'sha1|cbc|md5|umac-64|group1-|3des|arcfour|^ssh-rsa$|ssh-dss' | paste -sd' ' - || true)
    [[ -z $weak ]] && chk pass "$(T "Нет слабых алгоритмов" "No weak algorithms")" || chk fail "$(T "Слабые алгоритмы:" "Weak algorithms:") $weak"
  fi

  echo; echo "${C_BOLD}$(T "Аккаунты" "Accounts")${C_0}"
  case $(passwd -S root 2>/dev/null | awk '{print $2}') in
    L)  chk pass "$(T "Пароль root заблокирован" "root password locked")" ;;
    NP) chk fail "$(T "У root ПУСТОЙ пароль" "root has an EMPTY password")" ;;
    *)  chk warn "$(T "У root есть пароль (вход по SSH всё равно запрещён?)" "root has a password (is SSH login for root denied?)")" ;;
  esac
  list=$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null | paste -sd' ' -)
  [[ -z $list ]] && chk pass "$(T "Нет аккаунтов с пустым паролем" "No accounts with an empty password")" || chk fail "$(T "Пустой пароль:" "Empty password:") $list"
  list=""
  for u in $(awk -F: '$3>=1000 && $3<60000 && $7!~/(nologin|false)$/{print $1}' /etc/passwd); do
    [[ $(passwd -S "$u" 2>/dev/null | awk '{print $2}') == P ]] && list+="$u "
  done
  [[ -n $list ]] && chk pass "$(T "Аккаунты с входом:" "Login accounts:") $list" || chk warn "$(T "Нет аккаунта с паролем для sudo" "No account with a password for sudo")"
  list=$(grep -hsE '^[^#%].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* | awk '{print $1}' | sort -u | paste -sd' ' - || true)
  [[ -z $list ]] && chk pass "$(T "Нет sudo без пароля" "No passwordless sudo")" || chk warn "$(T "sudo без пароля (NOPASSWD):" "Passwordless sudo (NOPASSWD):") $list"

  echo; echo "${C_BOLD}$(T "Сеть и защита" "Network and protection")${C_0}"
  if ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw status verbose 2>/dev/null | grep -q 'deny (incoming)' && chk pass "$(T "UFW включён, входящие запрещены" "UFW on, incoming denied")" \
      || chk warn "$(T "UFW включён, но входящие не запрещены по умолчанию" "UFW on, but incoming is not denied by default")"
  else
    chk fail "$(T "Firewall UFW выключен" "UFW firewall is off")"
  fi
  list=$(ss -Hltnu 2>/dev/null | awk '{print $5}' | grep -vE '^(127\.|\[::1\]|\[::ffff:127\.)' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un | paste -sd' ' - || true)
  chk pass "$(T "Порты, слушающие снаружи:" "Ports listening publicly:") ${list:-$(T "нет" "none")}"
  systemctl is-active --quiet fail2ban && fail2ban-client status sshd &>/dev/null \
    && chk pass "$(T "fail2ban защищает SSH" "fail2ban protects SSH")" || chk fail "$(T "fail2ban не защищает SSH" "fail2ban does not protect SSH")"
  if systemctl cat crowdsec.service &>/dev/null; then
    systemctl is-active --quiet crowdsec && chk pass "CrowdSec" || chk warn "$(T "CrowdSec установлен, но не работает" "CrowdSec installed but not running")"
  fi
  systemctl is-active --quiet auditd && chk pass "auditd" || chk warn "$(T "auditd не работает" "auditd not running")"
  aa-status --enabled 2>/dev/null && chk pass "AppArmor" || chk warn "$(T "AppArmor выключен" "AppArmor off")"
  [[ -s /etc/harden/telegram.conf ]] && systemctl is-active --quiet harden-login-watch \
    && chk pass "$(T "Уведомления в Telegram" "Telegram alerts")" || chk warn "$(T "Уведомлений нет (sudo harden --setup-telegram)" "No alerts (sudo harden --setup-telegram)")"

  echo; echo "${C_BOLD}$(T "Обновления и ядро" "Updates and kernel")${C_0}"
  apt-config dump 2>/dev/null | grep -q 'APT::Periodic::Unattended-Upgrade "1"' \
    && chk pass "$(T "Автообновления безопасности" "Automatic security updates")" || chk fail "$(T "Автообновления выключены" "Automatic updates off")"
  n=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst' || true)
  (( n == 0 )) && chk pass "$(T "Все обновления установлены" "All updates installed")" || chk warn "$(T "Ожидают установки:" "Pending updates:") $n"
  [[ -f /var/run/reboot-required ]] && chk warn "$(T "Нужна перезагрузка" "Reboot required")" || chk pass "$(T "Перезагрузка не нужна" "No reboot needed")"
  [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == yes ]] \
    && chk pass "$(T "Время синхронизировано" "Clock synchronised")" || chk warn "$(T "Время не синхронизировано" "Clock not synchronised")"
  list=""
  for v in kernel.kptr_restrict=2 kernel.dmesg_restrict=1 kernel.randomize_va_space=2 fs.suid_dumpable=0 \
           fs.protected_symlinks=1 fs.protected_hardlinks=1 net.ipv4.tcp_syncookies=1 \
           net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0 \
           net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.all.rp_filter=1; do
    [[ $(sysctl -n "${v%%=*}" 2>/dev/null) == "${v#*=}" ]] || list+="${v%%=*} "
  done
  [[ -z $list ]] && chk pass "$(T "Параметры ядра (sysctl)" "Kernel settings (sysctl)")" || chk warn "$(T "Отличаются от рекомендуемых:" "Differ from recommended:") $list"

  echo
  echo "${C_BOLD}$(T "Итог" "Summary"): ${C_G}✓ $CHK_PASS${C_0}  ${C_Y}! $CHK_WARN${C_0}  ${C_R}✗ $CHK_FAIL${C_0}"
  (( CHK_FAIL == 0 ))
}

main() {
  case ${1:-} in -h|--help) usage; exit 0 ;; esac
  [[ $EUID -eq 0 ]] || die "Run as root: sudo bash harden.sh / Запусти от root: sudo bash harden.sh"
  choose_language
  case ${1:-} in
    # Only the login summary, for an already hardened server
    --install-status) install_server_status; exit 0 ;;
    --check) run_check || exit 1; exit 0 ;;
    --setup-telegram)
      TELEGRAM=yes; ask_telegram; install_notifications
      [[ $TELEGRAM == yes ]] || exit 1
      exit 0 ;;
    "") ;;
    *) usage; exit 2 ;;
  esac
  relaunch_in_tmux
  preflight
  collect_answers
  install_packages
  setup_user
  harden_system
  install_server_status
  setup_auditd
  setup_autoupdates
  setup_firewall
  setup_fail2ban
  setup_crowdsec
  # Before SSH, so the admin's test login on the new port is the first alert they see
  install_notifications
  setup_ssh
  # Only once the new user's login is confirmed — on AWS/Oracle (ubuntu/opc logins)
  # locking them earlier would leave no way in if SSH had to be rolled back
  lock_other_users
  lock_root
  # Keep a copy for later: sudo harden --check / --setup-telegram
  [[ -f $0 ]] && install -m 755 "$0" /usr/local/sbin/harden
  final_report
}

# Run unless sourced (CI sources the file to test single functions on a runner)
if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then main "$@"; fi
