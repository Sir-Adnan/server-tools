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

# Paths already captured in this run. Tracking the same file twice would
# overwrite its run backup with our own edit and silently break rollback.
declare -A ST_TRACKED=()

st_track_file() {
  local path="$1"
  [[ -n ${ST_TRACKED[$path]:-} ]] && return 0
  ST_TRACKED[$path]=1

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

# backup_prune [KEEP] — keep the newest KEEP run directories (default 10).
# The pristine original/ tree is never touched: it is the only way back to
# the state the server was in before ServerTools ever ran.
backup_prune() {
  local keep="${1:-10}" runs="${ST_BACKUP_DIR}/runs" dir
  [[ -d $runs ]] || return 0
  while IFS= read -r dir; do
    [[ -n $dir ]] || continue
    rm -rf "${runs:?}/${dir}" ||
      log_warn "Could not prune the old backup ${dir}."
    log_debug "pruned old run backup: ${dir}"
  done < <(find "$runs" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null |
    sort -r | awk -v k="$keep" 'NR > k')
}

# rollback_original — restore every file to the state it had the first time
# ServerTools touched it, across all runs, and remove everything it created.
rollback_original() {
  if [[ ! -d $ST_ORIGINAL_DIR ]]; then
    log_warn "No pristine backups recorded — nothing to restore."
    return 0
  fi

  local file target restored=0 removed=0
  # Restore first, then remove created files: a file can appear as created in
  # one run and modified in a later one, and the original must win.
  while IFS= read -r file; do
    target="${file#"$ST_ORIGINAL_DIR"}"
    [[ -n $target ]] || continue
    mkdir -p "$(dirname "$target")"
    cp -a "$file" "$target" && restored=$((restored + 1))
  done < <(find "$ST_ORIGINAL_DIR" -type f -o -type l 2>/dev/null)

  while IFS= read -r target; do
    [[ -n $target ]] || continue
    # Only remove what was created and never existed before this tool ran.
    [[ -e ${ST_ORIGINAL_DIR}${target} ]] && continue
    if [[ -r /proc/swaps ]] && grep -q "^${target}[[:space:]]" /proc/swaps 2>/dev/null; then
      swapoff "$target" 2>>"$ST_LOG_FILE" || {
        log_warn "Cannot swapoff ${target} — left in place."
        continue
      }
    fi
    rm -f "$target" && removed=$((removed + 1))
  done < <(awk -F'\t' 'NR > 1 && $3 == "created" {print $4}' "$ST_MANIFEST_FILE" 2>/dev/null | sort -u)

  local unit
  while IFS= read -r unit; do
    [[ -n $unit ]] || continue
    has_cmd systemctl || break
    systemctl disable --now "$unit" >/dev/null 2>>"$ST_LOG_FILE" ||
      log_warn "Could not disable unit ${unit}."
  done < <(awk -F'\t' 'NR > 1 && $3 == "unit" {print $4}' "$ST_MANIFEST_FILE" 2>/dev/null | sort -u)

  has_cmd systemctl && { systemctl daemon-reload 2>>"$ST_LOG_FILE" || log_warn "daemon-reload failed."; }
  has_cmd sysctl && { sysctl --system >/dev/null 2>>"$ST_LOG_FILE" || log_warn "sysctl reload reported errors."; }

  log_info "Factory restore: ${restored} restored, ${removed} removed."
  printf '%sRestored to the state before ServerTools ever ran:%s %d file(s) restored, %d removed.\n' \
    "$C_OK" "$C_RESET" "$restored" "$removed"
  printf '%sA reboot guarantees every runtime setting is back as well.%s\n' "$C_MUTED" "$C_RESET"
  return 0
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
  local action target restored=0 removed=0 missing=0 sysctl_touched=0 units_touched=0
  while IFS=$'\t' read -r action target; do
    case "$action" in
      unit)
        # A systemd unit this run enabled: disable it (stop included) so no
        # dangling .wants symlink survives after its file is removed below.
        if has_cmd systemctl; then
          systemctl disable --now "$target" >/dev/null 2>>"$ST_LOG_FILE" ||
            log_warn "Could not disable unit ${target}."
          units_touched=1
        fi
        ;;
      modified)
        if [[ -e ${src}${target} || -L ${src}${target} ]]; then
          cp -a "${src}${target}" "$target"
          restored=$((restored + 1))
          [[ $target == /etc/sysctl.d/* || $target == /etc/sysctl.conf ]] && sysctl_touched=1
        else
          log_warn "Backup missing for ${target} — skipped."
          missing=$((missing + 1))
        fi
        ;;
      created)
        # Never delete an active swap file out from under the kernel.
        if [[ -r /proc/swaps ]] && grep -q "^${target}[[:space:]]" /proc/swaps 2>/dev/null; then
          if ! swapoff "$target" 2>>"$ST_LOG_FILE"; then
            log_warn "Cannot swapoff ${target} — left in place."
            missing=$((missing + 1))
            continue
          fi
        fi
        rm -f "$target"
        removed=$((removed + 1))
        [[ $target == /etc/sysctl.d/* ]] && sysctl_touched=1
        ;;
    esac
  done < <(awk -F'\t' -v run="$run" 'NR > 1 && $2 == run {print $3 "\t" $4}' "$ST_MANIFEST_FILE" | tac)

  if ((units_touched)) && has_cmd systemctl; then
    systemctl daemon-reload 2>>"$ST_LOG_FILE" ||
      log_warn "daemon-reload after rollback failed."
  fi
  if ((sysctl_touched)) && has_cmd sysctl; then
    sysctl --system >/dev/null 2>>"$ST_LOG_FILE" ||
      log_warn "sysctl reload after rollback reported errors (see log)."
  fi

  log_info "Rollback of run ${run}: ${restored} restored, ${removed} removed, ${missing} missing."
  printf '%sRollback of run %s:%s %d file(s) restored, %d removed' \
    "$C_OK" "$run" "$C_RESET" "$restored" "$removed"
  ((missing > 0)) && printf ', %s%d backup(s) missing%s' "$C_WARN" "$missing" "$C_RESET"
  printf '\n'
  printf '%sNote:%s runtime state (loaded sysctl values, running services) is not\n' "$C_MUTED" "$C_RESET"
  printf '%sreverted automatically — a reboot guarantees a clean slate.%s\n' "$C_MUTED" "$C_RESET"
  return 0
}
