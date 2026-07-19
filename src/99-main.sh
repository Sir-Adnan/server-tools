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
  --rollback            Revert the latest recorded run and exit
  --install             Install as the 'st' command (/usr/local/bin/st)
  --update              Self-update from the latest GitHub release

Options for --auto:
  --profile NAME        general | vpn-node | wireguard | panel | full
  --tier T              Capacity tier: S | M | L | XL (default: by RAM)
  --dns VALUE           Provider (cloudflare|google|quad9|opendns|shecan)
                        or custom "primary,secondary" (skipped when omitted)
  --no-swap             Skip the swap step
  --no-limits           Skip the nofile limits step
  --no-extras           Skip the journald/NTP step

General options:
  --no-color            Disable colored output (NO_COLOR env also honoured)
  --debug               Verbose logging to console and log file
  -v, --version         Print version and exit
  -h, --help            Show this help

Example (fleet provisioning):
  st --auto --profile vpn-node --tier L --dns cloudflare
EOF
}

_need_value() { # _need_value OPTION VALUE
  if [[ -z ${2:-} ]]; then
    printf 'Missing value for %s\n' "$1" >&2
    exit 2
  fi
}

main() {
  local action="menu"
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
      --auto) action="auto" ;;
      --install) action="install" ;;
      --update) action="update" ;;
      --profile)
        _need_value "$1" "${2:-}"
        shift
        ST_AUTO_PROFILE="$1"
        ;;
      --tier)
        _need_value "$1" "${2:-}"
        shift
        ST_AUTO_TIER="${1^^}"
        ;;
      --dns)
        _need_value "$1" "${2:-}"
        shift
        ST_AUTO_DNS="$1"
        ;;
      --no-swap) ST_AUTO_SWAP=0 ;;
      --no-limits) ST_AUTO_LIMITS=0 ;;
      --no-extras) ST_AUTO_EXTRAS=0 ;;
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
    auto)
      ST_OPT_BATCH=1
      auto_optimize
      ;;
    install)
      ST_OPT_BATCH=1
      st_self_install
      ;;
    update)
      ST_OPT_BATCH=1
      st_self_update
      ;;
    menu)
      main_menu
      ;;
  esac

  log_info "${ST_NAME} finished (run ${ST_RUN_ID})"
}

main "$@"
