#!/usr/bin/env bash
# =============================================================================
#  harden.sh — first-boot setup and hardening for a Debian / Ubuntu server
#
#  Supported: Debian 12/13, Ubuntu 22.04/24.04/26.04
#  Run:       see README.md — the release command verifies the checksum before running
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
#    REBOOT_TIME=04:00, LOCK_ROOT=yes|no, LOCK_OTHER_USERS=yes|no, SSH_EXTRA_USERS="a b",
#    INSTALL_CROWDSEC=yes|no, RUN_LYNIS=yes|no, REBOOT_NOW=yes|no,
#    SERVER_STATUS=yes|no, REUSE_USER=yes|no (use an existing account),
#    TELEGRAM=yes|no, TG_TOKEN, TG_CHAT_ID, TG_REPORT_TIME=09:00,
#    DISABLE_PING=yes|no (do not answer ICMP echo; default no),
#    SET_USER_PASSWORD=no (root is then NOT locked)
#
#  Other modes: --check (audit only), --setup-telegram, --ping off|on, --lang en|ru,
#               --install-status, --refresh, --answers, --undo, --help.
#               The language and the answers of the setup are remembered in /etc/harden.
# =============================================================================
set -Eeuo pipefail
# Files this script writes get ordinary modes whatever umask the caller has: the setup
# sets UMASK 027, and `sudo harden …` from such a session would pass it on to root and
# write drop-ins normal users cannot read. Anything private is restricted explicitly
# where it is written. (Lessons from live runs: docs/decisions/0004-lessons-from-live-runs.md)
umask 022

HARDEN_VERSION="2026.10.28"
LOG_FILE="/var/log/harden.log"
REPORT_FILE="/root/harden-report.txt"
BACKUP_DIR="/root/harden-backup-$(date +%Y%m%d-%H%M%S)"
SSHD_DROPIN="/etc/ssh/sshd_config.d/00-hardening.conf"
UI=${HARDEN_LANG:-en}

