# shellcheck shell=bash
# ============================================================================
# core/backup.sh — track-before-touch backups and manifest-driven rollback.
#
# Contract (see CLAUDE.md rule 3): call `st_track_file PATH` BEFORE creating
# or modifying PATH. This yields:
#   - a pristine copy under original/ the first time the tool ever touches
#     the file (never overwritten afterwards),
#   - a per-run copy under runs/<run-id>/ (mirror of the absolute path),
#   - a manifest row ("modified" or "created") for rollback.
# ============================================================================

st_track_file() {
  local path="$1"
  mkdir -p "$ST_RUN_BACKUP_DIR"
  if [[ -e $path || -L $path ]]; then
    if [[ ! -e ${ST_ORIGINAL_DIR}${path} && ! -L ${ST_ORIGINAL_DIR}${path} ]]; then
      mkdir -p "${ST_ORIGINAL_DIR}$(dirname "$path")"
      cp -a "$path" "${ST_ORIGINAL_DIR}${path}"
    fi
    mkdir -p "${ST_RUN_BACKUP_DIR}$(dirname "$path")"
    cp -a "$path" "${ST_RUN_BACKUP_DIR}${path}"
    manifest_add modified "$path"
    log_debug "tracked (modified): $path"
  else
    manifest_add created "$path"
    log_debug "tracked (created): $path"
  fi
}

# rollback_latest — revert everything recorded by the most recent run,
# newest change first. Files "created" by that run are removed; "modified"
# files are restored from the run backup.
rollback_latest() {
  local run
  run="$(manifest_latest_run)"
  if [[ -z $run ]]; then
    log_warn "No recorded changes — nothing to roll back."
    return 0
  fi

  local src="${ST_BACKUP_DIR}/runs/${run}"
  local action target restored=0 removed=0 missing=0
  while IFS=$'\t' read -r action target; do
    case "$action" in
      modified)
        if [[ -e ${src}${target} || -L ${src}${target} ]]; then
          cp -a "${src}${target}" "$target"
          restored=$((restored + 1))
        else
          log_warn "Backup missing for ${target} — skipped."
          missing=$((missing + 1))
        fi
        ;;
      created)
        rm -f "$target"
        removed=$((removed + 1))
        ;;
    esac
  done < <(awk -F'\t' -v run="$run" 'NR > 1 && $2 == run {print $3 "\t" $4}' "$ST_MANIFEST_FILE" | tac)

  log_info "Rollback of run ${run}: ${restored} restored, ${removed} removed, ${missing} missing."
  printf '%sRollback of run %s:%s %d file(s) restored, %d removed' \
    "$C_OK" "$run" "$C_RESET" "$restored" "$removed"
  ((missing > 0)) && printf ', %s%d backup(s) missing%s' "$C_WARN" "$missing" "$C_RESET"
  printf '\n'
  printf '%sNote:%s runtime state (loaded sysctl values, running services) is not\n' "$C_MUTED" "$C_RESET"
  printf '%sreverted automatically — a reboot guarantees a clean slate.%s\n' "$C_MUTED" "$C_RESET"
  return 0
}
