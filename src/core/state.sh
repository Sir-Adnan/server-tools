# shellcheck shell=bash
# ============================================================================
# core/state.sh — persistent user config (key=value) and the change manifest.
#
# The manifest is the source of truth for rollback: every file the tool
# creates or modifies gets one TSV row (see docs/ROLLBACK.md).
# ============================================================================

declare -A ST_CONFIG=()

state_init() {
  mkdir -p "$ST_ETC_DIR" "$ST_LIB_DIR" "$ST_BACKUP_DIR"
  if [[ ! -f $ST_MANIFEST_FILE ]]; then
    printf '# timestamp\trun_id\taction\ttarget\n' >"$ST_MANIFEST_FILE"
  fi
}

config_load() {
  ST_CONFIG=()
  [[ -f $ST_CONFIG_FILE ]] || return 0
  local key value
  while IFS='=' read -r key value; do
    [[ -z $key || $key == \#* ]] && continue
    ST_CONFIG[$key]="$value"
  done <"$ST_CONFIG_FILE"
}

config_get() { # config_get KEY [DEFAULT]
  printf '%s' "${ST_CONFIG[$1]:-${2:-}}"
}

config_set() { # config_set KEY VALUE — updates memory and persists.
  ST_CONFIG[$1]="$2"
  config_save
}

config_save() {
  mkdir -p "$ST_ETC_DIR"
  local tmp="${ST_CONFIG_FILE}.tmp" key
  {
    printf '# %s configuration — generated; editing by hand is fine.\n' "$ST_NAME"
    for key in "${!ST_CONFIG[@]}"; do
      printf '%s=%s\n' "$key" "${ST_CONFIG[$key]}"
    done | sort
  } >"$tmp"
  mv -f "$tmp" "$ST_CONFIG_FILE"
}

# manifest_add ACTION TARGET — ACTION is "created" or "modified".
manifest_add() {
  printf '%s\t%s\t%s\t%s\n' "$(date '+%F %T')" "$ST_RUN_ID" "$1" "$2" >>"$ST_MANIFEST_FILE"
}

manifest_entry_count() {
  [[ -f $ST_MANIFEST_FILE ]] || {
    printf '0'
    return 0
  }
  awk 'NR > 1' "$ST_MANIFEST_FILE" | wc -l | tr -d '[:space:]'
}

# manifest_latest_run — most recent run id that recorded changes (empty if none).
manifest_latest_run() {
  [[ -f $ST_MANIFEST_FILE ]] || return 0
  awk -F'\t' 'NR > 1 {print $2}' "$ST_MANIFEST_FILE" | sort -u | tail -n1
}
