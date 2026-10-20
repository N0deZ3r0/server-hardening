# ---------- 2. packages ----------
# Everything the setup installs. CI asks apt on each supported release whether these exist
# there, so a renamed package is found by a test and not half-way through a setup.
setup_packages() {
  echo ufw fail2ban python3-systemd \
       unattended-upgrades apt-listchanges needrestart debsums \
       apparmor apparmor-utils chrony libpam-pwquality \
       lynis curl ca-certificates gnupg sudo openssh-server \
       libpam-tmpdir apt-show-versions acct sysstat rsyslog logrotate
  [[ ${IS_CONTAINER:-no} == yes ]] || echo auditd audispd-plugins
}

install_packages() {
  step "$(T "Обновление системы и установка пакетов" "System upgrade and packages")"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  # Lock::Timeout — wait while apt is busy with auto-updates (common on a fresh VPS)
  # Acquire::Retries — a mirror that drops one download must not end the setup at its
  # second step; apt's own default is not to try again at all
  local apt_opts=(-y -o DPkg::Lock::Timeout=600 -o Acquire::Retries=3 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=3 update -q
  apt-get "${apt_opts[@]}" full-upgrade
  local -a pkgs
  read -ra pkgs <<<"$(setup_packages | xargs)"
  apt-get "${apt_opts[@]}" install "${pkgs[@]}"
  apt-get "${apt_opts[@]}" autoremove --purge
  # Packages that were removed earlier but left their configs behind (status rc) are only
  # counted. Purging them here deleted configuration — for some packages, data too — that
  # the admin of an existing server may have kept on purpose.
  local rc_n
  rc_n=$(dpkg -l | awk '/^rc/{n++} END{print n+0}')
  (( rc_n == 0 )) || info "$(T "От удалённых пакетов остались конфиги: $rc_n (список: dpkg -l | grep ^rc; убрать: sudo apt purge <имя>)" \
                               "Configs left by removed packages: $rc_n (list: dpkg -l | grep ^rc; remove: sudo apt purge <name>)")"
  ok "$(T "Пакеты установлены" "Packages installed")"
}

