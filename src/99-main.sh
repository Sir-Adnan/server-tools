# shellcheck shell=bash
# ============================================================================
# 99-main.sh — CLI argument parsing and the program entrypoint.
# This file MUST be last in the build order (see build.sh SOURCES).
# ============================================================================

usage() {
  cat <<EOF
${ST_NAME} v${ST_VERSION} — Linux server optimization toolkit
${ST_REPO_URL}

Usage: server-tools.sh [OPTIONS]   (installed: st [OPTIONS])

Actions (no action starts the interactive menu):
  --status              Print the full system status report and exit
  --auto                Non-interactive optimize: base layer + detected profile
  --dry-run             Show the plan and exact sysctl diff, apply NOTHING
  --verify              Check whether everything applied is still in effect
  --report              Print + save a plain-text support report
  --rollback            Revert the latest recorded run and exit
  --rollback-original   Restore the state from before ServerTools ever ran
  --install             Install as the 'st' command (/usr/local/bin/st)
  --update              Self-update from the latest GitHub release

Options for --auto and --dry-run:
  --profile NAME        general | vpn-node | wireguard | panel | full
  --tier T              Capacity tier: S | M | L | XL (default: by RAM)
  --users N             Expected concurrent users — sizes conntrack from the
                        real user count instead of RAM (with a RAM warning)
  --dns VALUE           Provider (cloudflare|google|quad9|opendns|shecan|
                        electro|begzar) or custom "primary,secondary"
  --no-swap             Skip the swap step
  --no-limits           Skip the nofile limits step
  --no-extras           Skip the journald/NTP step
  --no-perf             Skip the CPU/NIC performance step (RPS, governor, THP)

General options:
  --json                Machine-readable output (--verify)
  --no-color            Disable colored output (NO_COLOR env also honoured)
  --debug               Verbose logging to console and log file
  -v, --version         Print version and exit
  -h, --help            Show this help

Exit codes:
  0  everything succeeded    1  at least one step failed
  2  usage error             3  applied, but with warnings / drift found

Example (fleet provisioning):
  st --auto --profile vpn-node --users 10000 --dns cloudflare
  st --verify --json    # nightly drift check from your own automation
EOF
}

_need_value() { # _need_value OPTION VALUE
  if [[ -z ${2:-} ]]; then
    printf 'Missing value for %s\n' "$1" >&2
    exit 2
  fi
}

main() {
  local action="menu" tuning_opts=''
  while (($# > 0)); do
    case "$1" in
      -v | --version)
        printf '%s %s\n' "$ST_NAME" "$ST_VERSION"
        return 0
        ;;
      -h | --help)
        usage
        return 0
        ;;
      --status) action="status" ;;
      --rollback) action="rollback" ;;
      --rollback-original) action="rollback_original" ;;
      --auto) action="auto" ;;
      --dry-run) action="dryrun" ;;
      --verify | --doctor) action="verify" ;;
      --report) action="report" ;;
      --install) action="install" ;;
      --update) action="update" ;;
      --profile)
        _need_value "$1" "${2:-}"
        shift
        ST_AUTO_PROFILE="$1"
        tuning_opts='yes'
        ;;
      --tier)
        _need_value "$1" "${2:-}"
        shift
        ST_AUTO_TIER="${1^^}"
        tuning_opts='yes'
        ;;
      --users)
        _need_value "$1" "${2:-}"
        shift
        ST_AUTO_USERS="$1"
        tuning_opts='yes'
        ;;
      --dns)
        _need_value "$1" "${2:-}"
        shift
        ST_AUTO_DNS="$1"
        tuning_opts='yes'
        ;;
      --no-swap)
        ST_AUTO_SWAP=0
        tuning_opts='yes'
        ;;
      --no-limits)
        ST_AUTO_LIMITS=0
        tuning_opts='yes'
        ;;
      --no-extras)
        ST_AUTO_EXTRAS=0
        tuning_opts='yes'
        ;;
      --no-perf)
        ST_AUTO_PERF=0
        tuning_opts='yes'
        ;;
      --json) ST_OPT_JSON=1 ;;
      --no-color) ST_OPT_NO_COLOR=1 ;;
      --debug) ST_OPT_DEBUG=1 ;;
      *)
        printf 'Unknown option: %s\n\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done

  # Tuning options only mean something for a non-interactive run; silently
  # ignoring them would hide a typo in a provisioning script.
  if [[ -n $tuning_opts && $action != auto && $action != dryrun ]]; then
    printf 'Options like --profile/--tier/--users/--dns require --auto or --dry-run.\n' >&2
    exit 2
  fi

  ui_detect_terminal
  require_root
  log_init
  state_init
  config_load
  log_info "${ST_NAME} v${ST_VERSION} started (run ${ST_RUN_ID}, action=${action})"

  case "$action" in
    status)
      ST_OPT_BATCH=1
      detect_stack
      show_status
      ;;
    rollback)
      ST_OPT_BATCH=1
      rollback_latest
      ;;
    rollback_original)
      ST_OPT_BATCH=1
      rollback_original
      ;;
    auto)
      ST_OPT_BATCH=1
      auto_optimize
      ;;
    dryrun)
      ST_OPT_BATCH=1
      ST_DRY_RUN=1
      dry_run_optimize
      ;;
    verify)
      ST_OPT_BATCH=1
      detect_stack
      doctor_run || st_escalate_exit $?
      ;;
    report)
      ST_OPT_BATCH=1
      detect_stack
      tools_report
      ;;
    install)
      ST_OPT_BATCH=1
      st_self_install || st_escalate_exit 1
      ;;
    update)
      ST_OPT_BATCH=1
      st_self_update || st_escalate_exit 1
      ;;
    menu)
      main_menu
      ;;
  esac

  log_info "${ST_NAME} finished (run ${ST_RUN_ID}, exit=${ST_EXIT_CODE})"
  return "$ST_EXIT_CODE"
}

main "$@"
