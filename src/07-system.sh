# ---------- 4. system ----------
SYSCTL_CONF=/etc/sysctl.d/99-hardening.conf
PROTECT_LINKS_CONF=/etc/sysctl.d/99-protect-links.conf

# The kernel settings, in one list: written by write_sysctl_conf, and compared with the
# live values by sysctl_overridden — after the setup, and by --check on any server.
SYSCTL_SETTINGS=(
  # kernel
  kernel.kptr_restrict=2 kernel.dmesg_restrict=1 kernel.unprivileged_bpf_disabled=1
  net.core.bpf_jit_harden=2 kernel.yama.ptrace_scope=1 kernel.sysrq=0
  kernel.randomize_va_space=2 kernel.perf_event_paranoid=3 fs.suid_dumpable=0
  fs.protected_hardlinks=1 fs.protected_symlinks=1 fs.protected_fifos=2 fs.protected_regular=2
  # IPv4
  net.ipv4.tcp_syncookies=1 net.ipv4.tcp_rfc1337=1
  net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1
  net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0
  net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0
  net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0
  net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0
  net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1
  net.ipv4.icmp_echo_ignore_broadcasts=1 net.ipv4.icmp_ignore_bogus_error_responses=1
  # IPv6
  net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0
  net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0
  # misc (Lynis KRNL-6000)
  dev.tty.ldisc_autoload=0 kernel.core_uses_pid=1 kernel.ctrl-alt-del=0
)
# Speed, not security: written, but a different value is not reported
SYSCTL_PERFORMANCE=(net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr)

write_sysctl_conf() {
  local kv
  {
    echo "# Written by harden.sh $HARDEN_VERSION. Undo: sudo harden --undo"
    for kv in "${SYSCTL_SETTINGS[@]}" "${SYSCTL_PERFORMANCE[@]}"; do echo "${kv%%=*} = ${kv#*=}"; done
  } >"$SYSCTL_CONF"
  # Debian and Ubuntu ship /usr/lib/sysctl.d/99-protect-links.conf. It sorts after our
  # file ("h" < "p") and puts fs.protected_fifos back to 1. A file of the same name in
  # /etc replaces the packaged one.
  {
    echo "# Written by harden.sh. Replaces /usr/lib/sysctl.d/99-protect-links.conf, which loads"
    echo "# after 99-hardening.conf and would lower fs.protected_fifos to 1."
    for kv in "${SYSCTL_SETTINGS[@]}"; do
      [[ $kv == fs.protected_* ]] && echo "${kv%%=*} = ${kv#*=}"
    done
  } >"$PROTECT_LINKS_CONF"
}

# Settings whose live value is not the one in the list: something that loads later has
# set them again (it has happened with UFW, apport and procps), or the setup never ran.
# A key this kernel does not have is skipped.
sysctl_overridden() {
  local kv cur out=""
  for kv in "${SYSCTL_SETTINGS[@]}"; do
    cur=$(sysctl -n "${kv%%=*}" 2>/dev/null) || continue
    [[ $cur == "${kv#*=}" ]] || out+="${kv%%=*} "
  done
  printf '%s' "$out"
}

# Some images leave the machine's own name out of /etc/hosts; sudo and mail tools look it
# up there. 127.0.1.1 is the Debian convention for a host without a fixed address.
add_hostname_to_hosts() {
  local hn
  hn=$(hostname 2>/dev/null || true)
  [[ -n $hn && -f /etc/hosts ]] || return 0
  grep -qwF -- "$hn" /etc/hosts && return 0
  cp -a /etc/hosts "$BACKUP_DIR/hosts" 2>/dev/null || true
  [[ -z $(tail -c1 /etc/hosts) ]] || echo >>/etc/hosts
  printf '127.0.1.1 %s\n' "$hn" >>/etc/hosts
}

harden_system() {
  step "$(T "Ядро и система" "Kernel and system")"

  write_sysctl_conf
  disable_apport
  sysctl --system >/dev/null 2>&1 || warn "$(T "Часть sysctl не применилась (нормально для контейнеров)" "Some sysctl values were not applied (normal in containers)")"
  local over
  over=$(sysctl_overridden)
  [[ -z $over || $IS_CONTAINER == yes ]] \
    || warn "$(T "Эти параметры ядра задаёт что-то ещё, они не применились:" "Something else sets these kernel values, they are not in effect:") $over"
  add_hostname_to_hosts

  if [[ $DISABLE_PING == yes ]]; then
    set_ping off
  elif [[ -e $PING_SYSCTL ]]; then
    set_ping on    # answered "no" on a re-run after an earlier "yes"
  fi

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
    # Only what is on now — said once, not at every refresh
    note_if_enabled "$svc.service" || systemctl is-active --quiet "$svc.service" 2>/dev/null || continue
    systemctl disable --now "$svc.service" &>/dev/null \
      && info "$(T "Отключена служба" "Disabled service") $svc" || true
  done
  # Name lookups for a local network (LLMNR, mDNS) are of no use to a server. On Debian 13
  # systemd-resolved answers LLMNR on every address — port 5355, which --check then lists as
  # listening publicly next to SSH (found on a provider's Debian 13 image). DNS is untouched.
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nLLMNR=no\nMulticastDNS=no\n' >/etc/systemd/resolved.conf.d/99-hardening.conf
    systemctl try-restart systemd-resolved &>/dev/null || true
  fi

  chmod 600 /etc/crontab 2>/dev/null || true
  chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
  chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
  local home
  home=$(home_of "$NEW_USER")
  if [[ -d $home && $home != / ]]; then chmod 750 "$home"; fi

  ok "$(T "Система усилена" "System hardened")"
}

setup_auditd() {
  [[ $IS_CONTAINER == yes ]] && { info "$(T "Контейнер — auditd пропущен" "Container — auditd skipped")"; return; }
  step "auditd"
  # -D looks like "delete every rule", and for rules typed in with auditctl and saved
  # nowhere it is. Rule files already in rules.d are not lost: augenrules merges every
  # file there and moves -D to the top of the result, so the admin's rules load as before
  # and ours are added. CI checks exactly that.
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
// This script edits a few package config files (login.defs, UFW's sysctl.conf, motd-news).
// Without these options unattended-upgrades holds back any package whose new version
// changes such a file, security fixes included. With them the local file is kept and the
// upgrade goes through.
Dpkg::Options { "--force-confdef"; "--force-confold"; };
EOF
  mkdir -p /etc/needrestart/conf.d
  echo "\$nrconf{restart} = 'a';" >/etc/needrestart/conf.d/99-hardening.conf
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "$(T "Обновления безопасности ставятся автоматически" "Security updates install automatically")"
}

