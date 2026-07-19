# shellcheck shell=bash
# ============================================================================
# core/colors.sh — terminal capability detection and the UI palette.
#
# Rules:
#   - Color labels/titles only, never values (readable on light AND dark
#     terminals — no assumption about the user's background color).
#   - Honour NO_COLOR (https://no-color.org), non-tty output, and TERM=dumb.
#   - Unicode (box drawing) only when the locale advertises UTF-8.
# ============================================================================

ST_TTY=0
ST_UTF8=0

C_RESET='' C_BOLD='' C_DIM=''
C_TITLE='' C_KEY='' C_ACCENT='' C_LINE='' C_MUTED=''
C_OK='' C_WARN='' C_ERR=''

ui_detect_terminal() {
  [[ -t 1 ]] && ST_TTY=1

  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) ST_UTF8=1 ;;
  esac

  local want_color=$ST_TTY
  [[ -n ${NO_COLOR:-} ]] && want_color=0
  [[ ${TERM:-dumb} == dumb ]] && want_color=0
  ((ST_OPT_NO_COLOR)) && want_color=0
  ((want_color)) || return 0

  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'

  # Classic (non-bright) ANSI colors — stable across terminal themes.
  C_TITLE=$'\033[1;36m' # bold cyan   — screen titles, banner
  C_KEY=$'\033[1;34m'   # bold blue   — menu keys, kv labels
  C_ACCENT=$'\033[1;35m' # bold magenta — highlights
  C_LINE=$'\033[0;34m'  # blue        — separators
  C_MUTED=$'\033[2m'    # dim         — hints, secondary text
  C_OK=$'\033[1;32m'
  C_WARN=$'\033[1;33m'
  C_ERR=$'\033[1;31m'
  return 0
}
