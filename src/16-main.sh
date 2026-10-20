# Keep a copy for later (sudo harden --check / --setup-telegram). Run as `sudo harden`
# the script is that copy already, and `install` onto itself would fail under set -e.
install_self() {
  local src=${1:-$0} dst=/usr/local/sbin/harden
  [[ -f $src ]] || return 0
  [[ $src -ef $dst ]] && return 0
  install -m 755 "$src" "$dst"
}

main() {
  case ${1:-} in
    -h|--help) usage; exit 0 ;;
    -V|--version) echo "harden.sh $HARDEN_VERSION"; exit 0 ;;
  esac
  [[ $EUID -eq 0 ]] || die "Run as root: sudo bash harden.sh / Запусти от root: sudo bash harden.sh"
  if [[ ${1:-} == --lang ]]; then
    case ${2:-} in
      ru|en) UI=$2; save_language; ok "$(T "Язык интерфейса: русский" "Interface language: English")"; exit 0 ;;
      *) die "Usage: sudo harden --lang en|ru / Использование: sudo harden --lang en|ru" ;;
    esac
  fi
  choose_language
  case ${1:-} in
    # Only the login summary, for an already hardened server
    --install-status) save_language; SERVER_STATUS=yes; install_server_status; set_saved_answer SERVER_STATUS yes; exit 0 ;;
    --check) run_check || exit 1; exit 0 ;;
    --setup-telegram)
      save_language
      TELEGRAM=yes; ask_telegram; install_notifications
      [[ $TELEGRAM == yes ]] || exit 1
      set_saved_answer TELEGRAM yes
      exit 0 ;;
    --ping)
      save_language; set_ping "${2:-}"
      if [[ ${2:-} == off ]]; then set_saved_answer DISABLE_PING yes; else set_saved_answer DISABLE_PING no; fi
      exit 0 ;;
    --refresh) save_language; run_refresh; exit 0 ;;
    --answers) load_answers; print_answers; exit 0 ;;
    --undo) run_undo; exit 0 ;;
    "") ;;
    *) usage; exit 2 ;;
  esac
  relaunch_in_tmux
  preflight
  save_language
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
  install_self "$0"
  SSH_PUBKEY=$(cat "$PUBKEY_FILE")
  LOCK_ROOT=${LOCK_ROOT%% *}
  save_answers
  final_report
}

# Run unless sourced (CI sources the file to test single functions on a runner)
if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then main "$@"; fi
