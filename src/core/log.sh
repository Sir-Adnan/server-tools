# shellcheck shell=bash
# ============================================================================
# core/log.sh — leveled logging with size-based rotation.
# Primary target /var/log/server-tools.log, falling back to the state dir.
# ============================================================================

ST_LOG_FILE="/var/log/server-tools.log"
readonly ST_LOG_MAX_BYTES=$((2 * 1024 * 1024))

log_init() {
  if ! touch "$ST_LOG_FILE" 2>/dev/null; then
    mkdir -p "$ST_LIB_DIR"
    ST_LOG_FILE="${ST_LIB_DIR}/server-tools.log"
    touch "$ST_LOG_FILE"
  fi
}

_log_rotate_if_needed() {
  [[ -f $ST_LOG_FILE ]] || return 0
  local size
  size="$(wc -c <"$ST_LOG_FILE" 2>/dev/null)" || size=0
  if ((size > ST_LOG_MAX_BYTES)); then
    mv -f "$ST_LOG_FILE" "${ST_LOG_FILE}.1"
    : >"$ST_LOG_FILE"
  fi
}

# _log LEVEL MESSAGE... — appends to the log file when it is writable
# (before log_init, or as non-root, messages go to the console only).
_log() {
  local level="$1"
  shift
  [[ -w $ST_LOG_FILE ]] || return 0
  _log_rotate_if_needed
  printf '[%s] [%-5s] %s\n' "$(date '+%F %T')" "$level" "$*" >>"$ST_LOG_FILE"
}

log_debug() {
  ((ST_OPT_DEBUG)) || return 0
  _log DEBUG "$@"
  printf '%bDEBUG%b %s\n' "$C_MUTED" "$C_RESET" "$*" >&2
}

log_info() { _log INFO "$@"; }

# While a step is running its status line is still open ("... "), so console
# warnings are buffered and flushed by st_run_step right after the verdict.
# The log file always receives them immediately.
ST_LOG_BUFFERING=0
ST_LOG_BUFFER=()

log_warn() {
  _log WARN "$@"
  if ((ST_LOG_BUFFERING)); then
    ST_LOG_BUFFER+=("$*")
    return 0
  fi
  printf '%bWARN%b  %s\n' "$C_WARN" "$C_RESET" "$*" >&2
}

log_error() {
  _log ERROR "$@"
  printf '%bERROR%b %s\n' "$C_ERR" "$C_RESET" "$*" >&2
}

# die MESSAGE — log the error and exit with failure.
die() {
  log_error "$@"
  exit 1
}
