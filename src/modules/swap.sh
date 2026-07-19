# shellcheck shell=bash
# ============================================================================
# modules/swap.sh — create a swap file only when no swap exists at all.
#
# Fixes two legacy v1 flaws: the fstab entry is written only AFTER swapon
# verifiably succeeds, and btrfs gets explicit CoW handling (fallocate'd
# files are not usable as swap there).
# ============================================================================

swap_is_active() {
  [[ -r /proc/swaps ]] && awk 'NR > 1 {found = 1} END {exit !found}' /proc/swaps
}

swap_apply() {
  if swap_is_active; then
    log_info "Swap already active — skipped."
    return 2
  fi

  local swapfile='/swapfile'
  local size_mb
  size_mb="$(config_get swap_size_mb 2048)"
  [[ $size_mb =~ ^[0-9]+$ ]] || size_mb=2048

  # Refuse when disk headroom is too small (swap size + 1 GB safety margin).
  local avail_mb
  avail_mb="$(df -Pm / 2>/dev/null | awk 'NR == 2 {print $4}')" || avail_mb=0
  [[ $avail_mb =~ ^[0-9]+$ ]] || avail_mb=0
  if ((avail_mb < size_mb + 1024)); then
    log_error "Not enough free disk for a ${size_mb} MB swap file (available: ${avail_mb} MB)."
    return 1
  fi

  st_track_file /etc/fstab
  st_track_file "$swapfile" # recorded as "created" so rollback removes it

  local fstype
  fstype="$(stat -f -c %T / 2>/dev/null)" || fstype=''
  if [[ $fstype == btrfs ]]; then
    # CoW must be disabled on the empty file before any data is written.
    touch "$swapfile"
    if has_cmd chattr; then
      chattr +C "$swapfile" 2>/dev/null || true
    fi
    dd if=/dev/zero of="$swapfile" bs=1M count="$size_mb" status=none 2>>"$ST_LOG_FILE" || return 1
  else
    if ! fallocate -l "${size_mb}M" "$swapfile" 2>/dev/null; then
      dd if=/dev/zero of="$swapfile" bs=1M count="$size_mb" status=none 2>>"$ST_LOG_FILE" || return 1
    fi
  fi

  chmod 600 "$swapfile"
  mkswap "$swapfile" >/dev/null 2>>"$ST_LOG_FILE" || return 1
  if ! swapon "$swapfile" 2>>"$ST_LOG_FILE"; then
    log_error "swapon failed (filesystem: ${fstype:-unknown}) — swap file removed, fstab untouched."
    rm -f "$swapfile"
    return 1
  fi

  if ! grep -qE '^[[:space:]]*/swapfile[[:space:]]' /etc/fstab 2>/dev/null; then
    printf '/swapfile none swap sw 0 0\n' >>/etc/fstab
  fi

  log_info "Swap enabled: ${size_mb} MB at ${swapfile} (fs: ${fstype:-unknown})."
  return 0
}
