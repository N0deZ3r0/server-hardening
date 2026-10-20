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
  # Captured, then parsed: awk exiting on the first fpr line must not SIGPIPE gpg (pipefail)
  fpr=$(gpg --batch --homedir "$tmp" --show-keys --with-colons "$tmp/key.gpg" 2>/dev/null || true)
  fpr=$(awk -F: '/^fpr/{print $10; exit}' <<<"$fpr")
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
  # An optional part: if it does not install, the setup goes on without it rather than
  # stopping half-way with SSH still to be done
  if ! apt-get "${apt_opts[@]}" install crowdsec; then
    warn "$(T "CrowdSec не установился — пропущен, fail2ban защищает SSH и без него" "CrowdSec did not install — skipped; fail2ban protects SSH without it")"
    return 0
  fi
  # the whitelist follows the answer: an address given at an earlier run is not kept for good
  rm -f /etc/crowdsec/parsers/s02-enrich/99-harden-admin-whitelist.yaml
  if [[ -n $ADMIN_IP ]]; then
    mkdir -p /etc/crowdsec/parsers/s02-enrich
    # A network (203.0.113.0/24) goes under "cidr": under "ip" it is read as one address,
    # does not parse, and whitelists nothing
    cat >/etc/crowdsec/parsers/s02-enrich/99-harden-admin-whitelist.yaml <<EOF
name: harden/admin-whitelist
description: "Admin IP whitelisted by harden.sh"
whitelist:
  reason: "admin ip (harden.sh)"
  $([[ $ADMIN_IP == */* ]] && echo cidr || echo ip):
    - "$ADMIN_IP"
EOF
  fi
  cscli collections install crowdsecurity/linux crowdsecurity/sshd >/dev/null 2>&1 || true
  systemctl restart crowdsec || true
  apt-get "${apt_opts[@]}" install crowdsec-firewall-bouncer-nftables \
    || warn "$(T "Bouncer CrowdSec не установился" "The CrowdSec bouncer did not install")"
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

