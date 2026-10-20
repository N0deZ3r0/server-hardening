# ---------- --check: audit only, nothing is changed ----------
CHK_PASS=0; CHK_WARN=0; CHK_FAIL=0
chk() {  # chk pass|warn|fail|info "text" — info is shown and not counted: a fact, not a verdict
  case $1 in
    pass) CHK_PASS=$((CHK_PASS + 1)); echo "  ${C_G}✓${C_0} $2" ;;
    warn) CHK_WARN=$((CHK_WARN + 1)); echo "  ${C_Y}!${C_0} $2" ;;
    info) echo "  ${C_B}·${C_0} $2" ;;
    *)    CHK_FAIL=$((CHK_FAIL + 1)); echo "  ${C_R}✗${C_0} $2" ;;
  esac
}

run_check() {
  local cfg k v kex weak n list u out nons=no other
  . /etc/os-release
  step "$(T "Проверка сервера — ничего не меняется" "Server check — nothing is changed")"
  echo "  ${PRETTY_NAME:-?}, kernel $(uname -r)"

  echo; echo "${C_BOLD}SSH${C_0}"
  # sshd -T refuses to run without its runtime directory, which is missing whenever sshd
  # is socket-activated and idle (Ubuntu 24.04). The check changes nothing, so it does not
  # create it: sshd -T then runs in a mount namespace of its own, where a throwaway /run
  # exists for that one command and is seen by nothing else.
  if [[ -d /run/sshd ]]; then
    cfg=$(sshd -T 2>&1) || { v=$(head -1 <<<"$cfg"); cfg=""; }
  elif unshare --mount sh -c 'mount -t tmpfs tmpfs /run && mkdir /run/sshd' 2>/dev/null; then
    cfg=$(unshare --mount sh -c 'mount -t tmpfs tmpfs /run && mkdir /run/sshd && exec sshd -T' 2>&1) \
      || { v=$(head -1 <<<"$cfg"); cfg=""; }
  else
    # Containers often refuse a new mount namespace. Not being able to look is not the
    # same as a broken config, so it is reported as such and not counted as a failure.
    cfg=""; nons=yes
  fi
  sv() { awk -v k="$1" '$1==k{$1=""; sub(/^ /,""); print; exit}' <<<"$cfg"; }
  if [[ $nons == yes ]]; then
    chk warn "$(T "Конфигурацию SSH не прочитать, ничего не создавая: нет /run/sshd, а отдельное пространство монтирования здесь запрещено. Запусти sshd или выполни: mkdir /run/sshd" \
                  "The SSH config cannot be read without creating something: /run/sshd is missing and a private mount namespace is not allowed here. Start sshd, or run: mkdir /run/sshd")"
  elif [[ -z $cfg ]]; then
    chk fail "$(T "sshd -T не отработал — конфиг SSH не читается" "sshd -T failed — the SSH config cannot be read"): ${v:-?}"
  else
    v=$(awk '$1=="port"{print $2}' <<<"$cfg" | paste -sd' ' -)
    [[ " $v " == *" 22 "* ]] && chk warn "$(T "Порт 22 (много шума от ботов)" "Port 22 (lots of bot noise)")" || chk pass "$(T "Порт" "Port") $v"
    # An sshd bound to a port its config does not name is a daemon left over from before
    # a change, still running the old settings (found live after a port switch)
    list=""
    for u in $(ss -Hltnp 2>/dev/null | grep '"sshd"' | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' \
               | sed -E 's/.*:([0-9]+)$/\1/' | sort -un || true); do
      [[ " $v " == *" $u "* ]] || list+="$u "
    done
    [[ -z $list ]] && chk pass "$(T "sshd слушает только порты из конфигурации" "sshd listens only on configured ports")" \
      || chk fail "$(T "sshd слушает порт вне конфигурации: ${list}— остался старый процесс (sudo systemctl restart ssh или перезагрузка)" \
                      "sshd also listens outside its config: ${list}— a leftover daemon (sudo systemctl restart ssh, or reboot)")"
    for u in "${SSH_AUTH_POLICY[@]}"; do   # the list the setup writes; sshd -T prints keys in lowercase
      k=${u%% *}; v=$(sv "${k,,}")
      [[ $v == "${u#* }" ]] && chk pass "$u" || chk fail "$k $v"
    done
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
  # Group rules count as well: "%sudo ALL=(ALL) NOPASSWD: ALL" used to be skipped
  list=$(grep -hsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* | awk '{print $1}' | sort -u | paste -sd' ' - || true)
  [[ -z $list ]] && chk pass "$(T "Нет sudo без пароля" "No passwordless sudo")" || chk warn "$(T "sudo без пароля (NOPASSWD):" "Passwordless sudo (NOPASSWD):") $list"

  echo; echo "${C_BOLD}$(T "Сеть и защита" "Network and protection")${C_0}"
  # Output is captured first and searched afterwards. `cmd | grep -q` under pipefail is a
  # trap: grep -q exits at the first match, the writer dies of SIGPIPE, and the pipeline
  # reports failure for a check that passed — seen live on the auto-updates line below.
  out=$(ufw status verbose 2>/dev/null || true)
  if grep -q '^Status: active' <<<"$out"; then
    grep -q 'deny (incoming)' <<<"$out" && chk pass "$(T "UFW включён, входящие запрещены" "UFW on, incoming denied")" \
      || chk warn "$(T "UFW включён, но входящие не запрещены по умолчанию" "UFW on, but incoming is not denied by default")"
  else
    # UFW is not the only firewall. The check does not read other rule sets, but it must
    # not call a server unprotected when something else is dropping incoming traffic.
    other=""
    if systemctl is-active --quiet firewalld 2>/dev/null; then other=firewalld; fi
    if [[ -z $other ]]; then
      out=$(nft list ruleset 2>/dev/null || true)
      if grep -qE 'hook input .*policy drop' <<<"$out"; then other=nftables; fi
    fi
    if [[ -z $other ]]; then
      out=$(iptables -S INPUT 2>/dev/null || true)
      if grep -qx -- '-P INPUT DROP' <<<"$out"; then other=iptables; fi
    fi
    if [[ -n $other ]]; then
      chk warn "$(T "UFW выключен, входящие фильтрует $other — его правила здесь не проверяются" "UFW is off; incoming traffic is filtered by $other — its rules are not checked here")"
    else
      chk fail "$(T "Firewall UFW выключен" "UFW firewall is off")"
    fi
  fi
  # Everything bound beyond loopback; UDP 68 is the DHCP client, not a service
  list=$(ss -Hltnu 2>/dev/null | awk '{print $1, $5}' | grep -vE ' (127\.|\[::1\]|\[::ffff:127\.)' \
         | grep -vE '^udp .*:68$' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un | paste -sd' ' - || true)
  # Whether a port should be open is the admin's call — the check cannot know, so it
  # lists them without a mark of approval
  chk info "$(T "Порты, слушающие снаружи:" "Ports listening publicly:") ${list:-$(T "нет" "none")}"
  # Informational either way: answering ping is not a weakness
  [[ $(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null) == 1 ]] \
    && chk info "$(T "Ping: сервер не отвечает" "Ping: not answered")" || chk info "$(T "Ping: сервер отвечает (отключить: sudo harden --ping off)" "Ping: answered (to stop: sudo harden --ping off)")"
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
  out=$(apt-config dump 2>/dev/null || true)
  grep -q 'APT::Periodic::Unattended-Upgrade "1"' <<<"$out" \
    && chk pass "$(T "Автообновления безопасности" "Automatic security updates")" || chk fail "$(T "Автообновления выключены" "Automatic updates off")"
  # Updates keep a locally edited config and save the packaged one beside it. Each such
  # file is a config whose new defaults nobody has looked at yet.
  # The files are named (the first three): a bare count sent the first person who saw it
  # off to run find.
  out=$(find /etc -xdev \( -name '*.dpkg-dist' -o -name '*.dpkg-new' -o -name '*.ucf-dist' \) 2>/dev/null | sort || true)
  n=$(grep -c . <<<"$out" || true)
  list=$(head -3 <<<"$out" | paste -sd' ' - || true)
  (( n > 3 )) && list+=" …"
  (( n == 0 )) && chk pass "$(T "Нет непросмотренных новых конфигов от пакетов" "No new package configs waiting for review")" \
    || chk warn "$(T "Новые конфиги от пакетов не просмотрены ($n): $list — сравни с действующим файлом (diff) и удали" \
                    "New package configs not reviewed ($n): $list — compare with the file in use (diff), then delete")"
  n=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst' || true)
  (( n == 0 )) && chk pass "$(T "Все обновления установлены" "All updates installed")" || chk warn "$(T "Ожидают установки:" "Pending updates:") $n"
  [[ -f /var/run/reboot-required ]] && chk warn "$(T "Нужна перезагрузка" "Reboot required")" || chk pass "$(T "Перезагрузка не нужна" "No reboot needed")"
  [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == yes ]] \
    && chk pass "$(T "Время синхронизировано" "Clock synchronised")" || chk warn "$(T "Время не синхронизировано" "Clock not synchronised")"
  list=$(sysctl_overridden)
  [[ -z $list ]] && chk pass "$(T "Параметры ядра (sysctl)" "Kernel settings (sysctl)")" || chk warn "$(T "Отличаются от рекомендуемых:" "Differ from recommended:") $list"

  echo
  echo "${C_BOLD}$(T "Итог" "Summary"): ${C_G}✓ $CHK_PASS${C_0}  ${C_Y}! $CHK_WARN${C_0}  ${C_R}✗ $CHK_FAIL${C_0}"
  (( CHK_FAIL == 0 ))
}

