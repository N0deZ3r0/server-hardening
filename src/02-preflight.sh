# ---------- 0. language, tmux, preflight ----------
# The language picked at setup is remembered, so later `sudo harden --check` does not ask
# again. Order: HARDEN_LANG from the environment, then the saved choice, then the question.
LANG_FILE=/etc/harden/lang

choose_language() {
  case ${HARDEN_LANG:-} in ru|en) UI=$HARDEN_LANG; export HARDEN_LANG; return 0 ;; esac
  if [[ -r $LANG_FILE ]]; then
    case $(head -c 2 "$LANG_FILE" 2>/dev/null) in
      ru) UI=ru; export HARDEN_LANG=ru; return 0 ;;
      en) UI=en; export HARDEN_LANG=en; return 0 ;;
    esac
  fi
  local d=1
  [[ "${LC_ALL:-}${LANG:-}" == *ru* ]] && d=2
  if have_tty; then
    read -r -p "Language / Язык:  1) English  2) Русский [$d]: " REPLY </dev/tty || REPLY=$d
    case ${REPLY:-$d} in 2|ru|RU|р*|Р*) UI=ru ;; *) UI=en ;; esac
  else
    [[ $d == 2 ]] && UI=ru || UI=en
  fi
  export HARDEN_LANG=$UI
}

# Called only by modes that change the system anyway. --check promises to change nothing,
# so it reads the saved language but never writes it.
save_language() {
  install -d -m 700 /etc/harden
  echo "$UI" >"$LANG_FILE"
}

# A dropped SSH session (fresh VPS images often restart sshd in the first minutes)
# must not kill a half-done run, so the script moves itself into tmux.
relaunch_in_tmux() {
  [[ -n ${TMUX:-} || -n ${STY:-} || -n ${HARDEN_NO_TMUX:-} ]] && return 0
  command -v tmux >/dev/null || return 0
  [[ -f $0 && -t 0 ]] || return 0
  # Not on a terminal that cannot draw one (TERM=dumb: an editor's shell, a session started
  # by a program): tmux ends there with "terminal does not support clear", and the setup
  # would end with it. It runs in place instead, and preflight says what that costs.
  case ${TERM:-dumb} in dumb|unknown) return 0 ;; esac
  local script inner v done_flag=/run/harden-tmux.done
  script=$(readlink -f "$0")
  # A session whose run is still going has to be attached to (that is what -A is for: the
  # connection dropped, the admin starts the command again). A session whose run has ended
  # and is only waiting for Enter would show the old output instead of starting anew, so
  # the run leaves a mark when it ends.
  if [[ -e $done_flag ]]; then tmux kill-session -t harden 2>/dev/null || true; fi
  rm -f "$done_flag"
  inner="env HARDEN_NO_TMUX=1"
  for v in HARDEN_LANG NEW_USER SSH_PORT SSH_PUBKEY GITHUB_KEYS_USER EXTRA_PORTS AUTO_REBOOT REBOOT_TIME \
           LOCK_ROOT LOCK_OTHER_USERS INSTALL_CROWDSEC RUN_LYNIS REBOOT_NOW SET_USER_PASSWORD ADMIN_IP \
           SERVER_STATUS REUSE_USER TELEGRAM TG_CHAT_ID TG_REPORT_TIME HARDEN_TG_API DISABLE_PING \
           SSH_EXTRA_USERS SSH_CLIENT; do
    # TG_TOKEN is deliberately not passed: it would sit in tmux's command line, readable
    # in ps; inside tmux the script asks for it again (hidden input)
    [[ -n ${!v+x} ]] && inner+=" $v=$(printf '%q' "${!v}")"
  done
  # ...and before the last line waits for Enter, what was typed during the run is thrown
  # away: an Enter pressed once too often closed the window with the final report in it
  inner+=" bash $(printf '%q' "$script"); touch $done_flag; echo; while read -rs -t 0.1 -n 1000 _; do :; done"
  inner+="; read -rp $(printf '%q' "$(T 'Enter — закрыть окно tmux' 'Press Enter to close tmux')") _"
  info "$(T "Запускаю внутри tmux. Если SSH оборвётся — зайди снова и выполни: tmux attach -t harden" \
            "Running inside tmux. If SSH drops, log in again and run: tmux attach -t harden")"
  sleep 2
  # tmux refuses to start on a terminal type this server has no description of ("missing
  # or unsuitable terminal") — kitty, ghostty and others on a fresh image — and the setup
  # ended right there, with that line for an explanation. They all speak xterm's language,
  # so tmux is told that instead.
  if command -v infocmp >/dev/null && ! infocmp "$TERM" &>/dev/null; then
    export TERM=xterm-256color
  fi
  exec tmux new-session -A -s harden bash -c "$inner"
}

# cloud-init says "not started" both before it has begun and on a machine where it is
# installed but never runs, so "not started" counts only while the machine is still booting.
cloud_init_busy() {
  command -v cloud-init >/dev/null || return 1
  local st
  st=$(cloud-init status 2>/dev/null || true)
  grep -q 'running' <<<"$st" && return 0
  grep -q 'not started' <<<"$st" || return 1
  [[ $(systemctl is-system-running 2>/dev/null || true) =~ ^(initializing|starting)$ ]]
}

# The ports sshd is configured for now. sshd -T needs /run/sshd, which is missing while
# sshd is socket-activated and has not been started yet (Ubuntu 24.04 from the provider's
# console). A failing sshd -T must not end the run under pipefail: 22 is assumed then.
current_ssh_ports() {
  local ports
  [[ -d /run/sshd ]] || mkdir -p /run/sshd 2>/dev/null || true
  ports=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u | xargs || true)
  echo "${ports:-22}"
}

# Every file this script replaces or edits in place is copied first, so that "the
# originals are in the backup" holds for each of them (jail.local and hosts are copied
# where they are handled). --undo restores from the oldest of these directories.
backup_originals() {
  local bf
  mkdir -p "$BACKUP_DIR"
  if [[ -d /etc/ssh ]]; then cp -a /etc/ssh "$BACKUP_DIR/ssh"; fi
  for bf in /etc/login.defs /etc/issue /etc/issue.net /etc/motd /etc/apt/apt.conf.d/20auto-upgrades \
            /etc/default/apport /etc/default/sysstat /etc/default/motd-news; do
    # mkdir + cp, not `cp --parents`: that fails with "No such file or directory" in
    # coreutils 9.1, which is what Debian 12 has
    if [[ -e $bf ]]; then mkdir -p "$BACKUP_DIR${bf%/*}"; cp -a "$bf" "$BACKUP_DIR$bf"; fi
  done
  if [[ -d /etc/ufw ]]; then cp -a /etc/ufw "$BACKUP_DIR/ufw"; fi
}

preflight() {
  have_tty || die "$(T "Нужен интерактивный терминал (запускай в SSH-сессии)." "An interactive terminal is required (run it in an SSH session).")"
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "$(T "Поддерживаются только Debian и Ubuntu (обнаружено: ${PRETTY_NAME:-?})" "Only Debian and Ubuntu are supported (found: ${PRETTY_NAME:-?})")" ;;
  esac
  OS_NAME=$PRETTY_NAME
  VIRT=$(systemd-detect-virt 2>/dev/null || echo none)
  IS_CONTAINER=no
  systemd-detect-virt -cq 2>/dev/null && IS_CONTAINER=yes

  backup_originals
  # The log names the user, the SSH port and the whitelisted address: root only
  touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE") 2>&1

  echo "${C_BOLD}Server hardening v$HARDEN_VERSION — $OS_NAME (virt: $VIRT)${C_0}"
  if [[ -z ${TMUX:-} && -z ${STY:-} ]]; then
    # Said as what it is: this is reached with tmux installed too (HARDEN_NO_TMUX, or the
    # script fed through a pipe), and "not found" was not true then
    warn "$(T "Настройка идёт не в tmux/screen: обрыв SSH её прервёт." "Not inside tmux/screen: a dropped SSH session will abort the run.")$(command -v tmux >/dev/null || T " Поставить: apt install tmux" " To get it: apt install tmux")"
  fi

  # The provider's cloud-init may run a full apt upgrade (GRUB and kernel included) and
  # restart SSH for 5–20 minutes. Interrupting or rebooting then can leave GRUB half
  # installed and the server unbootable, so we wait for it to finish.
  if cloud_init_busy; then
    info "$(T "Хостер ещё делает первичную настройку (cloud-init: обновление системы, загрузчик, SSH)." \
              "The provider is still doing first-boot setup (cloud-init: upgrades, bootloader, SSH).")"
    info "$(T "Жду завершения — это не зависание. Ctrl+C и перезагрузку НЕ делай." \
              "Waiting for it to finish — this is not a hang. Do NOT press Ctrl+C or reboot.")"
    local waited=0 detail
    while cloud_init_busy; do
      (( waited >= 2700 )) && die "$(T "cloud-init не завершился за 45 минут. Проверь: cloud-init status --long" "cloud-init did not finish in 45 minutes. Check: cloud-init status --long")"
      detail=$(tail -n 1 /var/log/cloud-init-output.log 2>/dev/null | tr -cd '[:print:]' | cut -c1-60 || true)
      printf '\r    %2d:%02d  %-62s' $((waited / 60)) $((waited % 60)) "$detail"
      sleep 5; waited=$((waited + 5))
    done
    echo
    ok "$(T "Первичная настройка хостера завершена" "Provider first-boot setup finished")"
  fi

  # Current SSH ports — kept open until the new port is proven to work
  CURRENT_SSH_PORTS=$(current_ssh_ports)
}

