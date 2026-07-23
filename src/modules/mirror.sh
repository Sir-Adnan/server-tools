# shellcheck shell=bash
# ============================================================================
# modules/mirror.sh — APT mirror switching, mainly for Iran-hosted servers
# where the default archives are slow or blocked.
#
# Handles both source formats: the classic one-line sources.list and the
# deb822 .sources files Ubuntu 24.04+ ships. Every file is tracked, the
# result is verified with a real `apt-get update`, and a failure restores
# the previous configuration instead of leaving apt broken.
# ============================================================================

# Format: label|Ubuntu URI|Debian URI  ("-" = not offered for that distro)
readonly -a ST_MIRRORS=(
  'ArvanCloud (Iran)|https://mirror.arvancloud.ir/ubuntu|https://mirror.arvancloud.ir/debian'
  'Ubuntu/Debian official Iran|http://ir.archive.ubuntu.com/ubuntu|https://ftp.iranrepo.ir/debian'
  'Official worldwide (revert)|http://archive.ubuntu.com/ubuntu|http://deb.debian.org/debian'
)

_mirror_distro_id() {
  local id=''
  [[ -r /etc/os-release ]] && id="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")"
  printf '%s' "${id:-unknown}"
}

# _mirror_files — every apt source file that mentions a distribution archive.
_mirror_files() {
  local f
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
    [[ -f $f ]] || continue
    grep -qE '(archive|deb|security)\.(ubuntu|debian)\.org|ubuntu\.com/ubuntu|arvancloud|iranrepo' "$f" 2>/dev/null &&
      printf '%s\n' "$f"
  done
}

mirror_apply() {
  ui_section "APT mirror"
  if ! has_cmd apt-get; then
    printf 'This server does not use APT — nothing to switch.\n'
    return 2
  fi

  local distro
  distro="$(_mirror_distro_id)"
  case "$distro" in
    ubuntu | debian) : ;;
    *)
      printf 'Only Ubuntu and Debian mirrors are supported (found: %s).\n' "$distro"
      return 2
      ;;
  esac

  printf 'Current sources:\n'
  local f
  while IFS= read -r f; do printf '  %s\n' "$f"; done < <(_mirror_files)
  printf '\n'

  local i=1 entry label ubuntu_uri debian_uri
  for entry in "${ST_MIRRORS[@]}"; do
    IFS='|' read -r label ubuntu_uri debian_uri <<<"$entry"
    ui_menu_item "$i" "$label" "$([[ $distro == ubuntu ]] && printf '%s' "$ubuntu_uri" || printf '%s' "$debian_uri")"
    i=$((i + 1))
  done
  ui_menu_item 0 "Cancel"

  local choice
  read -rp "Select [0]: " choice || return 2
  [[ $choice =~ ^[1-3]$ ]] || return 2
  IFS='|' read -r label ubuntu_uri debian_uri <<<"${ST_MIRRORS[$((choice - 1))]}"
  local new_uri="$ubuntu_uri"
  [[ $distro == debian ]] && new_uri="$debian_uri"
  [[ $new_uri == '-' ]] && {
    printf 'That mirror is not available for %s.\n' "$distro"
    return 2
  }

  ui_confirm "Switch APT sources to ${label}?" || return 2

  local changed=0
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    st_track_file "$f"
    # Rewrite only the archive host, never the suite/component fields, and
    # leave third-party repositories alone.
    sed -i -E "s#https?://[^ ]*(archive\.ubuntu\.com/ubuntu|deb\.debian\.org/debian|ir\.archive\.ubuntu\.com/ubuntu|mirror\.arvancloud\.ir/(ubuntu|debian)|ftp\.iranrepo\.ir/debian)#${new_uri}#g" "$f" &&
      changed=1
  done < <(_mirror_files)

  if ((changed == 0)); then
    log_warn "No APT source file matched a known archive host — nothing changed."
    return 2
  fi

  printf 'Refreshing the package index...\n'
  if apt-get update -qq >>"$ST_LOG_FILE" 2>&1; then
    printf '%sMirror switched to %s.%s\n' "$C_OK" "$label" "$C_RESET"
    log_info "APT mirror switched to ${label} (${new_uri})."
    return 0
  fi

  log_error "apt-get update failed with the new mirror — restoring the previous sources."
  while IFS= read -r f; do
    [[ -e ${ST_RUN_BACKUP_DIR}${f} ]] && cp -a "${ST_RUN_BACKUP_DIR}${f}" "$f"
  done < <(_mirror_files)
  apt-get update -qq >>"$ST_LOG_FILE" 2>&1 ||
    log_warn "The restored sources also failed to refresh — check ${ST_LOG_FILE}."
  return 1
}
