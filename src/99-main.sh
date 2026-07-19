# shellcheck shell=bash
# ============================================================================
# 99-main.sh — CLI argument parsing and the program entrypoint.
# This file MUST be last in the build order (see build.sh SOURCES).
# ============================================================================

usage() {
  cat <<EOF
${ST_NAME} v${ST_VERSION} — Linux server optimization toolkit
${ST_REPO_URL}

Usage: server-tools.sh [OPTIONS]

Actions (no action starts the interactive menu):
  --status        Print the full system status report and exit
  --rollback      Revert the latest recorded run and exit

Options:
  --no-color      Disable colored output (NO_COLOR env is also honoured)
  --debug         Verbose logging to console and log file
  -v, --version   Print version and exit
  -h, --help      Show this help
EOF
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
    menu)
      main_menu
      ;;
  esac

  log_info "${ST_NAME} finished (run ${ST_RUN_ID})"
}

main "$@"
