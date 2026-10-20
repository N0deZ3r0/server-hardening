# ---------- 7. report ----------
final_report() {
  if [[ $RUN_LYNIS == yes ]]; then
    step "$(T "Аудит Lynis (1–2 минуты)" "Lynis audit (1–2 minutes)")"
    lynis audit system --quick --no-colors >/var/log/lynis-harden.log 2>&1 || true
    chmod 600 /var/log/lynis-harden.log 2>/dev/null || true
    HARDENING_INDEX=$(grep -oP 'Hardening index : \K[0-9]+' /var/log/lynis-harden.log || echo "?")
  fi

  install -m 600 /dev/null "$REPORT_FILE"   # root only from the first byte, not after the fact
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
  echo "  sudo harden --refresh             — $(T "применить настройки новой версии скрипта, без вопросов" "apply a newer version's settings, no questions")"
  echo "  sudo harden --undo                — $(T "откатить настройку из резервной копии" "take the setup back from the backup")"
  echo
  T "Чтобы настроить сервер так же ещё раз (после переустановки, например), сохрани у себя эту команду:" \
    "To set a server up the same way again (after a reinstall, say), keep this command:"; echo
  echo "  $(print_answers)"
  echo
  warn "$(T "Docker публикует порты в обход UFW! Используй -p 127.0.0.1:PORT:PORT или ufw-docker." \
            "Docker publishes ports around UFW! Use -p 127.0.0.1:PORT:PORT or ufw-docker.")"
  # On a VPS nobody misses USB storage; on a physical server a backup disk may depend on it
  if [[ $VIRT == none ]]; then
    warn "$(T "Физический сервер: USB-накопители отключены (usb-storage). Вернуть: убери эту строку из /etc/modprobe.d/99-hardening.conf" \
              "Bare metal: USB storage is disabled (usb-storage). To undo, remove that line from /etc/modprobe.d/99-hardening.conf")"
  fi
  if [[ -f /var/run/reboot-required ]]; then
    echo
    # reboot-required is also left by libc, systemd and others; "a new kernel" with the
    # same version on both sides of the arrow explained nothing
    local newest
    newest=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1 | sed 's|.*/vmlinuz-||' || true)
    if [[ -n $newest && $newest != "$(uname -r)" ]]; then
      warn "$(T "Нужна перезагрузка: установлено новое ядро" "Reboot needed: a new kernel is installed") ($(uname -r) -> $newest)"
    else
      warn "$(T "Нужна перезагрузка: обновлены системные компоненты" "Reboot needed: system components were updated")"
    fi
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

