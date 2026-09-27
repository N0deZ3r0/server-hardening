#!/usr/bin/env bash
# =============================================================================
#  harden.sh — первичная настройка и защита сервера Debian / Ubuntu (2026)
#
#  Поддержка: Debian 12/13, Ubuntu 22.04/24.04/26.04
#  Запуск:    curl -fsSL https://raw.githubusercontent.com/N0deZ3r0/server-hardening/main/harden.sh -o harden.sh && sudo bash harden.sh
#
#  Что делает (по порядку):
#    1. Спрашивает: имя нового пользователя, SSH-ключ, новый порт SSH и т.д.
#    2. Обновляет систему, ставит пакеты защиты
#    3. Создаёт sudo-пользователя, кладёт ему SSH-ключ
#    4. Ядро (sysctl), AppArmor, auditd, chrony, journald, запрет core dump,
#       политика паролей, автообновления безопасности
#    5. Firewall UFW (deny incoming) + fail2ban (+ CrowdSec по желанию)
#    6. SSH: новый порт, только ключи, root запрещён, современная криптография
#       -> ПРОВЕРКА входа в новом окне, только потом старый порт закрывается
#    7. Блокирует пароль root и чужие аккаунты (ubuntu/debian от cloud-init),
#       запускает аудит Lynis, пишет отчёт, предлагает перезагрузку
#
#  Переменные окружения (необязательно, иначе скрипт спросит):
#    NEW_USER, SSH_PORT, SSH_PUBKEY, GITHUB_KEYS_USER, EXTRA_PORTS="80,443",
#    AUTO_REBOOT=yes|no, REBOOT_TIME=04:00, LOCK_ROOT=yes|no,
#    LOCK_OTHER_USERS=yes|no, INSTALL_CROWDSEC=yes|no, RUN_LYNIS=yes|no,
#    REBOOT_NOW=yes|no,
#    SET_USER_PASSWORD=no  — не задавать пароль пользователю сейчас
#                            (тогда root НЕ блокируется, пароль задашь позже: passwd <user>)
# =============================================================================
set -Eeuo pipefail

VERSION="2026.09"
LOG_FILE="/var/log/harden.log"
REPORT_FILE="/root/harden-report.txt"
BACKUP_DIR="/root/harden-backup-$(date +%Y%m%d-%H%M%S)"
SSHD_DROPIN="/etc/ssh/sshd_config.d/00-hardening.conf"

# ---------- вывод ----------
if [[ -t 1 ]]; then
  C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[34m'; C_BOLD=$'\e[1m'; C_0=$'\e[0m'
else
  C_R=; C_G=; C_Y=; C_B=; C_BOLD=; C_0=
fi
info()  { echo "${C_B}[i]${C_0} $*"; }
ok()    { echo "${C_G}[✓]${C_0} $*"; }
warn()  { echo "${C_Y}[!]${C_0} $*"; }
die()   { echo "${C_R}[✗]${C_0} $*" >&2; exit 1; }
step()  { echo; echo "${C_BOLD}${C_B}==> $*${C_0}"; }

trap 'echo "${C_R}[✗] Ошибка в строке $LINENO: $BASH_COMMAND${C_0}" >&2; echo "Бэкап конфигов: $BACKUP_DIR, лог: $LOG_FILE" >&2' ERR

# Все вопросы читаем из терминала — работает и при запуске через curl | bash
ask() {  # ask "Вопрос" "по умолчанию" -> REPLY
  local q=$1 def=${2:-}
  if [[ -n $def ]]; then read -r -p "$q [$def]: " REPLY </dev/tty; REPLY=${REPLY:-$def}
  else read -r -p "$q: " REPLY </dev/tty; fi
}
ask_yn() {  # ask_yn "Вопрос" y|n -> 0 если да
  local q=$1 def=${2:-n} hint
  [[ $def == y ]] && hint="Y/n" || hint="y/N"
  read -r -p "$q [$hint]: " REPLY </dev/tty
  REPLY=${REPLY:-$def}
  [[ ${REPLY,,} == y* || ${REPLY,,} == д* ]]
}
env_yn() {  # env_yn VAR "Вопрос" default -> 0 если да (берёт из env, если задано)
  local var=$1 q=$2 def=$3 val=${!1:-}
  if [[ -n $val ]]; then [[ ${val,,} == y* ]]; return; fi
  ask_yn "$q" "$def"
}

# ---------- 0. проверки ----------
preflight() {
  [[ $EUID -eq 0 ]] || die "Запусти от root: sudo bash harden.sh"
  [[ -r /dev/tty ]] || die "Нужен интерактивный терминал (запускай в SSH-сессии)."
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "Поддерживаются только Debian и Ubuntu (обнаружено: ${PRETTY_NAME:-unknown})" ;;
  esac
  OS_NAME=$PRETTY_NAME
  VIRT=$(systemd-detect-virt 2>/dev/null || echo none)
  IS_CONTAINER=no
  systemd-detect-virt -cq 2>/dev/null && IS_CONTAINER=yes

  mkdir -p "$BACKUP_DIR"
  cp -a /etc/ssh "$BACKUP_DIR/ssh"
  [[ -d /etc/ufw ]] && cp -a /etc/ufw "$BACKUP_DIR/ufw"
  exec > >(tee -a "$LOG_FILE") 2>&1

  echo "${C_BOLD}Server hardening v$VERSION — $OS_NAME (virt: $VIRT)${C_0}"
  if [[ -z ${TMUX:-} && -z ${STY:-} ]]; then
    warn "Совет: запускай внутри tmux/screen, чтобы обрыв SSH не прервал настройку."
  fi

  # На свежем VPS первые минуты работают cloud-init и автообновления
  if command -v cloud-init >/dev/null; then
    info "Жду завершения cloud-init..."
    timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
  fi

  # Текущие порты SSH (чтобы не отрезать себя до проверки)
  CURRENT_SSH_PORTS=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u | xargs)
  CURRENT_SSH_PORTS=${CURRENT_SSH_PORTS:-22}
}

# ---------- 1. вопросы ----------
valid_user() {
  [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ && $1 != root ]] || { warn "Только латиница в нижнем регистре, цифры, _ и -"; return 1; }
  if id "$1" &>/dev/null; then
    (( $(id -u "$1") >= 1000 )) || { warn "'$1' — системный пользователь, выбери другое имя"; return 1; }
  elif getent group "$1" >/dev/null; then
    # На Ubuntu есть системная группа admin — adduser с таким именем падает
    warn "Имя '$1' занято системной группой, выбери другое"; return 1
  fi
}

port_busy() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }

collect_answers() {
  step "Настройка параметров"

  # Пользователь
  NEW_USER=${NEW_USER:-}
  until [[ -n $NEW_USER ]] && valid_user "$NEW_USER"; do
    ask "Имя нового пользователя с sudo" "sysop"; NEW_USER=$REPLY
  done

  # SSH-ключ
  PUBKEY_FILE=$(mktemp)
  if [[ -n ${SSH_PUBKEY:-} ]]; then
    printf '%s\n' "$SSH_PUBKEY" >"$PUBKEY_FILE"
  elif [[ -n ${GITHUB_KEYS_USER:-} ]]; then
    curl -fsSL "https://github.com/${GITHUB_KEYS_USER}.keys" >"$PUBKEY_FILE" || true
  fi
  while ! check_pubkeys "$PUBKEY_FILE"; do
    echo
    echo "Откуда взять публичный SSH-ключ?"
    echo "  1) Вставить вручную (строка из ~/.ssh/id_ed25519.pub)"
    echo "  2) Загрузить с GitHub (https://github.com/<ник>.keys)"
    echo "  3) Скопировать из /root/.ssh/authorized_keys"
    ask "Выбор" "1"
    case $REPLY in
      2) ask "Ник на GitHub"; curl -fsSL "https://github.com/${REPLY}.keys" >"$PUBKEY_FILE" || warn "Не удалось скачать ключи" ;;
      3) cp /root/.ssh/authorized_keys "$PUBKEY_FILE" 2>/dev/null || warn "У root нет authorized_keys" ;;
      *) echo "Сгенерировать ключ на СВОЁМ компьютере:  ssh-keygen -t ed25519 -C \"$NEW_USER@server\""
         ask "Вставь публичный ключ (ssh-ed25519 AAAA...)"; printf '%s\n' "$REPLY" >"$PUBKEY_FILE" ;;
    esac
  done

  # Порт SSH
  local suggested
  suggested=$(shuf -i 20000-60999 -n 1)
  SSH_PORT=${SSH_PORT:-}
  until [[ $SSH_PORT =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1024 && SSH_PORT <= 65535 )) \
        && { [[ " $CURRENT_SSH_PORTS " == *" $SSH_PORT "* ]] || ! port_busy "$SSH_PORT"; }; do
    [[ -n $SSH_PORT ]] && warn "Порт должен быть 1024–65535 и свободен."
    ask "Новый порт SSH" "$suggested"; SSH_PORT=$REPLY
  done

  # Дополнительные порты
  if [[ -z ${EXTRA_PORTS+x} ]]; then
    ask "Какие ещё порты открыть в firewall (через запятую, напр. 80,443; пусто — никаких)" ""
    EXTRA_PORTS=$REPLY
  fi
  EXTRA_PORTS=$(tr -d ' ' <<<"$EXTRA_PORTS")

  # Автоперезагрузка после обновлений ядра
  if env_yn AUTO_REBOOT "Разрешить автоперезагрузку ночью, если обновление ядра этого требует?" y; then
    AUTO_REBOOT=yes; REBOOT_TIME=${REBOOT_TIME:-04:00}
  else AUTO_REBOOT=no; fi

  if env_yn LOCK_ROOT "Заблокировать пароль root (вход только через $NEW_USER + sudo)?" y; then LOCK_ROOT=yes; else LOCK_ROOT=no; fi

  # Другие аккаунты с входом (ubuntu, debian, admin от хостера и т.п.)
  OTHER_USERS=$(awk -F: -v me="$NEW_USER" '$3>=1000 && $3<60000 && $1!=me && $7!~/(nologin|false)$/ {print $1}' /etc/passwd | xargs)
  if [[ -n $OTHER_USERS ]]; then
    warn "Найдены другие аккаунты с доступом к shell: $OTHER_USERS"
    if env_yn LOCK_OTHER_USERS "Заблокировать их (пароль, shell, sudo; данные не удаляются)?" y; then LOCK_OTHER_USERS=yes; else LOCK_OTHER_USERS=no; fi
  else
    LOCK_OTHER_USERS=no
  fi
  if env_yn INSTALL_CROWDSEC "Установить CrowdSec (коллективный IPS, дополнение к fail2ban)?" n; then INSTALL_CROWDSEC=yes; else INSTALL_CROWDSEC=no; fi
  if env_yn RUN_LYNIS "Запустить в конце аудит Lynis?" y; then RUN_LYNIS=yes; else RUN_LYNIS=no; fi

  echo
  echo "${C_BOLD}Итог:${C_0}"
  echo "  Пользователь:       $NEW_USER (sudo)"
  echo "  SSH-ключи:          $(ssh-keygen -lf "$PUBKEY_FILE" | awk '{print $NF, $2}' | paste -sd';' -)"
  echo "  SSH порт:           $CURRENT_SSH_PORTS -> $SSH_PORT"
  echo "  Открытые порты:     $SSH_PORT/tcp ${EXTRA_PORTS:+$EXTRA_PORTS}"
  echo "  Автоперезагрузка:   $AUTO_REBOOT ${REBOOT_TIME:-}"
  echo "  Блок. пароля root:  $LOCK_ROOT"
  [[ -n $OTHER_USERS ]] && echo "  Блок. аккаунтов:    $LOCK_OTHER_USERS ($OTHER_USERS)"
  echo "  CrowdSec:           $INSTALL_CROWDSEC"
  ask_yn "Начать настройку?" y || die "Отменено."
}

check_pubkeys() {  # файл с ключами валиден?
  local f=$1
  [[ -s $f ]] || return 1
  # оставляем только строки ключей
  grep -E '^(ssh-ed25519|sk-ssh-ed25519@openssh.com|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh.com) ' "$f" >"$f.clean" || { rm -f "$f.clean"; warn "Ключи не найдены"; return 1; }
  mv "$f.clean" "$f"
  if ! ssh-keygen -lf "$f" >/dev/null 2>&1; then warn "Ключ повреждён"; return 1; fi
  while read -r bits type; do
    if [[ $type == "(RSA)" ]] && (( bits < 3072 )); then
      warn "RSA-ключ $bits бит слабый. Рекомендуется ed25519: ssh-keygen -t ed25519"
    fi
  done < <(ssh-keygen -lf "$f" | awk '{print $1, $NF}')
  return 0
}

# ---------- 2. пакеты ----------
install_packages() {
  step "Обновление системы и установка пакетов"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  # Lock::Timeout — ждать, если apt занят автообновлением (частое на свежем VPS)
  local apt_opts=(-y -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  apt-get -o DPkg::Lock::Timeout=600 update -q
  apt-get "${apt_opts[@]}" full-upgrade
  local pkgs=(
    ufw fail2ban python3-systemd
    unattended-upgrades apt-listchanges needrestart debsums
    apparmor apparmor-utils
    chrony libpam-pwquality
    lynis curl ca-certificates gnupg sudo openssh-server
    rsyslog logrotate
  )
  [[ $IS_CONTAINER == no ]] && pkgs+=(auditd audispd-plugins)
  apt-get "${apt_opts[@]}" install "${pkgs[@]}"
  apt-get "${apt_opts[@]}" autoremove --purge
  ok "Пакеты установлены"
}

# ---------- 3. пользователь ----------
setup_user() {
  step "Пользователь $NEW_USER"

  # Политика паролей (до создания пароля)
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
    info "Пользователь уже существует"
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
  ok "Ключ добавлен в $ak"

  USER_HAS_PASSWORD=no
  if passwd -S "$NEW_USER" | awk '{exit !($2=="P")}'; then
    info "Пароль уже задан"; USER_HAS_PASSWORD=yes
  elif [[ ${SET_USER_PASSWORD:-yes} == no ]]; then
    warn "Пароль для $NEW_USER не задан (SET_USER_PASSWORD=no) — sudo заработает после: passwd $NEW_USER"
  else
    echo "Задай пароль для $NEW_USER — он нужен для sudo (минимум 12 символов, 3 типа символов)."
    until passwd "$NEW_USER" </dev/tty >/dev/tty 2>&1; do warn "Попробуй ещё раз"; done
    USER_HAS_PASSWORD=yes
  fi

  # Логи всех sudo-команд + таймаут
  cat >/etc/sudoers.d/99-hardening <<'EOF'
Defaults    use_pty
Defaults    logfile="/var/log/sudo.log"
Defaults    timestamp_timeout=15
Defaults    passwd_tries=3
EOF
  chmod 440 /etc/sudoers.d/99-hardening
  visudo -cq || { rm -f /etc/sudoers.d/99-hardening; die "Ошибка sudoers"; }
  ok "Пользователь готов"
}

lock_other_users() {
  [[ $LOCK_OTHER_USERS == yes ]] || return 0
  step "Блокировка лишних аккаунтов: $OTHER_USERS"
  local u f g
  for u in $OTHER_USERS; do
    usermod -L -s /usr/sbin/nologin "$u"
    for g in sudo adm lxd docker; do gpasswd -d "$u" "$g" &>/dev/null || true; done
    [[ -f /home/$u/.ssh/authorized_keys ]] && mv "/home/$u/.ssh/authorized_keys" "$BACKUP_DIR/authorized_keys.$u"
    # cloud-init выдаёт ubuntu/debian "NOPASSWD:ALL" — отключаем
    for f in /etc/sudoers.d/*; do
      [[ -f $f ]] && grep -qE "^${u}[[:space:]]" "$f" || continue
      cp -a "$f" "$BACKUP_DIR/"
      sed -i -E "s/^(${u}[[:space:]].*)/# disabled by harden.sh: \1/" "$f"
    done
    ok "$u заблокирован (вернуть: usermod -U -s /bin/bash $u)"
  done
  visudo -cq || die "Ошибка sudoers после блокировки пользователей — см. $BACKUP_DIR"
}

# ---------- 4. система ----------
harden_system() {
  step "Ядро и система"

  cat >/etc/sysctl.d/99-hardening.conf <<'EOF'
# --- ядро ---
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
# --- сеть IPv4 ---
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
# --- сеть IPv6 ---
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# --- производительность ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  sysctl --system >/dev/null 2>&1 || warn "Часть sysctl не применилась (нормально для контейнеров)"

  # Запрет core dump
  echo '* hard core 0' >/etc/security/limits.d/99-nocore.conf
  mkdir -p /etc/systemd/coredump.conf.d
  printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' >/etc/systemd/coredump.conf.d/99-hardening.conf

  # Постоянный журнал с ограничением размера
  mkdir -p /etc/systemd/journald.conf.d
  printf '[Journal]\nStorage=persistent\nSystemMaxUse=500M\nMaxRetentionSec=3month\n' >/etc/systemd/journald.conf.d/99-hardening.conf
  systemctl restart systemd-journald

  # Время (важно для логов, TLS, 2FA)
  systemctl enable --now chrony >/dev/null 2>&1 || true

  # AppArmor
  if [[ $IS_CONTAINER == no ]]; then
    systemctl enable --now apparmor >/dev/null 2>&1 || warn "AppArmor не запустился"
  fi

  # Предупреждающий баннер
  cat >/etc/issue.net <<'EOF'
Authorized access only. All activity is logged and monitored.
EOF
  cp /etc/issue.net /etc/issue

  # Отключить ненужные модули файловых систем и протоколов
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
install usb-storage /bin/false
EOF

  # Службы, которые не нужны на сервере
  local svc
  for svc in ModemManager udisks2; do
    systemctl list-unit-files "$svc.service" &>/dev/null && systemctl disable --now "$svc.service" &>/dev/null && info "Отключена служба $svc" || true
  done

  # Права на важные файлы
  chmod 600 /etc/crontab 2>/dev/null || true
  chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
  chmod 750 /home/"$NEW_USER"

  ok "Система усилена"
}

setup_auditd() {
  [[ $IS_CONTAINER == yes ]] && { info "Контейнер — auditd пропущен"; return; }
  step "auditd"
  cat >/etc/audit/rules.d/99-hardening.rules <<'EOF'
-D
-b 8192
-f 1
# Изменения пользователей и прав
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
# Планировщики
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
# Модули ядра
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
# Время
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time
# Команды от root
-a always,exit -F arch=b64 -F euid=0 -F auid>=1000 -F auid!=unset -S execve -k root_cmd
EOF
  systemctl enable auditd >/dev/null 2>&1 || true
  augenrules --load >/dev/null 2>&1 || service auditd restart || warn "auditd не перезапустился"
  ok "auditd настроен (поиск: ausearch -k identity)"
}

setup_autoupdates() {
  step "Автоматические обновления безопасности"
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
  ok "Обновления безопасности ставятся автоматически"
}

# ---------- 5. firewall ----------
setup_firewall() {
  step "Firewall (UFW)"
  # Без reset — при повторном запуске уже добавленные правила сохраняются
  ufw default deny incoming
  ufw default allow outgoing
  ufw default deny routed
  local p
  for p in $CURRENT_SSH_PORTS; do ufw allow "$p/tcp" comment 'SSH (temporary)' >/dev/null; done
  ufw limit "$SSH_PORT/tcp" comment 'SSH' >/dev/null
  IFS=',' read -ra ports <<<"$EXTRA_PORTS"
  for p in "${ports[@]}"; do
    [[ -z $p ]] && continue
    if [[ $p =~ ^[0-9]+(:[0-9]+)?(/(tcp|udp))?$ ]]; then ufw allow "$p" >/dev/null; else warn "Пропущен неверный порт: $p"; fi
  done
  ufw logging low
  ufw --force enable
  ok "UFW включён"
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
ignoreip           = 127.0.0.1/8 ::1
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
  ok "fail2ban включён (статус: fail2ban-client status sshd)"
}

setup_crowdsec() {
  [[ $INSTALL_CROWDSEC == yes ]] || return 0
  step "CrowdSec"
  if curl -fsSL https://install.crowdsec.net | sh; then
    apt-get install -y crowdsec crowdsec-firewall-bouncer-nftables
    cscli collections install crowdsecurity/linux crowdsecurity/sshd >/dev/null 2>&1 || true
    systemctl restart crowdsec
    ok "CrowdSec установлен (cscli decisions list)"
  else
    warn "Не удалось подключить репозиторий CrowdSec — пропускаю"
  fi
}

# ---------- 6. SSH ----------
filter_algos() {  # filter_algos <тип ssh -Q> алгоритмы... -> только поддерживаемые, через запятую
  local type=$1; shift
  local supported out=() a
  supported=$(ssh -Q "$type" 2>/dev/null)
  for a in "$@"; do grep -qxF "$a" <<<"$supported" && out+=("$a"); done
  (IFS=,; echo "${out[*]}")
}

ssh_service() { systemctl list-unit-files ssh.service &>/dev/null && echo ssh || echo sshd; }

write_sshd_config() {  # write_sshd_config "порт1 порт2 ..."
  local ports=$1 p kex ciphers macs hostkeys
  kex=$(filter_algos kex mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com \
        curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group18-sha512 diffie-hellman-group16-sha512)
  ciphers=$(filter_algos cipher chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes128-ctr)
  macs=$(filter_algos mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com)
  hostkeys=$(filter_algos key-sig ssh-ed25519 rsa-sha2-512 rsa-sha2-256)

  {
    echo "# Сгенерировано harden.sh $(date -Is). Первое совпадение побеждает — этот файл читается первым."
    for p in $ports; do echo "Port $p"; done
    cat <<EOF
AddressFamily any

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# --- Аутентификация: только ключи, root запрещён ---
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

# --- Ограничения ---
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Отключить лишнее (AllowTcpForwarding local — если нужны SSH-туннели к БД) ---
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

# --- Криптография (только поддерживаемые этой версией OpenSSH, вкл. пост-квантовые KEX) ---
KexAlgorithms $kex
Ciphers $ciphers
MACs $macs
HostKeyAlgorithms $hostkeys
EOF
  } >"$SSHD_DROPIN"
  chmod 600 "$SSHD_DROPIN"
}

restart_sshd() {
  sshd -t || return 1
  systemctl restart "$(ssh_service)"
}

rollback_ssh() {
  warn "Откат настроек SSH..."
  rm -f "$SSHD_DROPIN"
  cp -a "$BACKUP_DIR/ssh/." /etc/ssh/
  systemctl restart "$(ssh_service)" || true
}

setup_ssh() {
  step "SSH"
  mkdir -p /etc/ssh/sshd_config.d /run/sshd
  grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config \
    || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config

  # Хост-ключи: убрать DSA/ECDSA, пересоздать RSA если < 3072 бит
  rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key*
  [[ -f /etc/ssh/ssh_host_ed25519_key ]] || ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
  if [[ ! -f /etc/ssh/ssh_host_rsa_key ]] || (( $(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key | awk '{print $1}') < 3072 )); then
    rm -f /etc/ssh/ssh_host_rsa_key*; ssh-keygen -q -t rsa -b 4096 -N "" -f /etc/ssh/ssh_host_rsa_key
  fi
  # Слабые DH-группы
  if [[ -f /etc/ssh/moduli ]]; then
    awk '$5 >= 3071' /etc/ssh/moduli >/etc/ssh/moduli.safe && [[ -s /etc/ssh/moduli.safe ]] && mv /etc/ssh/moduli.safe /etc/ssh/moduli
  fi

  # Ubuntu 22.10+: ssh.socket игнорирует Port — переводим на обычный сервис
  if systemctl is-enabled ssh.socket &>/dev/null; then
    info "Отключаю ssh.socket (socket activation), включаю ssh.service"
    mkdir -p /etc/systemd/system
    systemctl disable ssh.socket &>/dev/null || true
    systemctl enable ssh.service &>/dev/null
  fi

  # Этап 1: старый + новый порт одновременно
  local ports="$CURRENT_SSH_PORTS"
  [[ " $ports " == *" $SSH_PORT "* ]] || ports="$ports $SSH_PORT"
  write_sshd_config "$ports"
  if ! sshd -t; then rollback_ssh; die "Конфиг sshd не прошёл проверку — откатил."; fi
  systemctl stop ssh.socket &>/dev/null || true
  restart_sshd || { rollback_ssh; die "sshd не перезапустился — откатил."; }
  ok "sshd слушает порты: $ports"

  # Проверка входа
  local ip
  ip=$(curl -fsS4 --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
  echo
  echo "${C_BOLD}${C_Y}╔════════════════════════════════════════════════════════════╗"
  echo "║  НЕ ЗАКРЫВАЙ ЭТО ОКНО! Открой НОВЫЙ терминал и проверь:   ║"
  echo "╚════════════════════════════════════════════════════════════╝${C_0}"
  echo
  echo "     ssh -p $SSH_PORT $NEW_USER@$ip"
  if [[ $USER_HAS_PASSWORD == yes ]]; then
    echo "     sudo -v        # проверить, что sudo работает (введи пароль)"
  fi
  echo
  local tries=0
  until ask_yn "Вход по ключу на порт $SSH_PORT работает?" n; do
    tries=$((tries+1))
    if (( tries >= 3 )) || ! ask_yn "Попробовать ещё раз? (нет = откатить SSH)" y; then
      rollback_ssh
      die "SSH откатан к исходному состоянию. Firewall пропускает оба порта. Проверь ключ и запусти снова."
    fi
  done

  # Этап 2: оставляем только новый порт
  write_sshd_config "$SSH_PORT"
  restart_sshd || { rollback_ssh; die "Ошибка при финальном перезапуске sshd — откатил."; }
  local p
  for p in $CURRENT_SSH_PORTS; do
    [[ $p == "$SSH_PORT" ]] && continue
    ufw delete allow "$p/tcp" >/dev/null 2>&1 || true
  done
  ufw delete allow OpenSSH >/dev/null 2>&1 || true
  ok "SSH только на порту $SSH_PORT, только по ключу, root запрещён"
}

lock_root() {
  [[ $LOCK_ROOT == yes ]] || return 0
  step "Блокировка root"
  if [[ $USER_HAS_PASSWORD != yes ]]; then
    warn "У $NEW_USER нет пароля — root НЕ блокирую, иначе sudo будет недоступен."
    warn "Задай пароль (passwd $NEW_USER), затем: sudo passwd -l root"
    LOCK_ROOT="no (у $NEW_USER нет пароля)"
    return 0
  fi
  passwd -l root >/dev/null
  # Ключи root больше не нужны (вход root по SSH запрещён) — сохраняем копию
  if [[ -s /root/.ssh/authorized_keys ]]; then
    mv /root/.ssh/authorized_keys "$BACKUP_DIR/root_authorized_keys"
  fi
  ok "Пароль root заблокирован. Для админки: sudo -i"
  warn "Консоль VPS у хостера (VNC) — входи как $NEW_USER."
}

# ---------- 7. отчёт ----------
final_report() {
  if [[ $RUN_LYNIS == yes ]]; then
    step "Аудит Lynis (1–2 минуты)"
    lynis audit system --quick --no-colors >/var/log/lynis-harden.log 2>&1 || true
    HARDENING_INDEX=$(grep -oP 'Hardening index : \K[0-9]+' /var/log/lynis-harden.log || echo "?")
  fi

  {
    echo "Server hardening report — $(date)"
    echo "OS: $OS_NAME   virt: $VIRT"
    echo
    echo "Пользователь:   $NEW_USER (sudo)"
    echo "Подключение:    ssh -p $SSH_PORT $NEW_USER@<IP>"
    echo "Root:           вход по SSH запрещён; пароль заблокирован: $LOCK_ROOT"
    echo "Firewall:"; ufw status verbose | sed 's/^/  /'
    echo "fail2ban:       $(systemctl is-active fail2ban)"
    echo "CrowdSec:       $INSTALL_CROWDSEC"
    echo "Автообновления: да, автоперезагрузка: $AUTO_REBOOT ${REBOOT_TIME:-}"
    [[ -n ${HARDENING_INDEX:-} ]] && echo "Lynis index:    $HARDENING_INDEX/100 (подробно: /var/log/lynis-harden.log)"
    echo
    echo "Бэкап исходных конфигов: $BACKUP_DIR"
    echo "Лог установки:           $LOG_FILE"
  } | tee "$REPORT_FILE"
  chmod 600 "$REPORT_FILE"

  echo
  ok "${C_BOLD}Готово!${C_0} Отчёт: $REPORT_FILE"
  echo
  echo "Полезные команды:"
  echo "  sudo ufw status                 — правила firewall"
  echo "  sudo ufw allow 443/tcp          — открыть порт"
  echo "  sudo fail2ban-client status sshd — забаненные IP"
  echo "  sudo ausearch -k identity -i    — кто менял пользователей"
  echo "  sudo lynis audit system         — полный аудит"
  warn "Docker публикует порты в обход UFW! Используй -p 127.0.0.1:PORT:PORT или ufw-docker."
  if [[ -f /var/run/reboot-required ]]; then
    echo
    warn "Нужна перезагрузка: установлено новое ядро ($(uname -r) -> $(ls -1 /boot/vmlinuz-* | sort -V | tail -1 | sed 's|.*/vmlinuz-||'))"
    if env_yn REBOOT_NOW "Перезагрузить сейчас? (после — входи: ssh -p $SSH_PORT $NEW_USER@<IP>)" y; then
      info "Перезагрузка через 5 секунд..."
      rm -f "$PUBKEY_FILE"
      systemd-run --on-active=5 --unit=harden-reboot systemctl reboot >/dev/null
    fi
  fi
}

main() {
  preflight
  collect_answers
  install_packages
  setup_user
  lock_other_users
  harden_system
  setup_auditd
  setup_autoupdates
  setup_firewall
  setup_fail2ban
  setup_crowdsec
  setup_ssh
  lock_root
  final_report
  rm -f "$PUBKEY_FILE"
}

main "$@"
