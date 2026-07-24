# shellcheck shell=bash
# ============================================================================
# modules/installer.sh — node helpers: back up node configuration, and hand
# over to the OFFICIAL upstream installers.
#
# ServerTools deliberately does not reimplement those installers: they change
# with every panel release and a stale copy is worse than none. What it does
# add is the part everyone forgets — a backup of the node's configuration and
# certificates before anything is installed or upgraded.
# ============================================================================

readonly ST_NODE_BACKUP_DIR="${ST_LIB_DIR}/backups/nodes"

# Format: label|paths (space separated)|official install command
# The command substitutions inside these strings are intentionally NOT
# expanded here — they are shown to the user first and only evaluated on
# explicit consent in node_install.
# shellcheck disable=SC2016
readonly -a ST_NODE_TARGETS=(
  'Marzban node|/opt/marzban-node /var/lib/marzban-node|bash -c "$(curl -sL https://github.com/Gozargah/Marzban-scripts/raw/master/marzban-node.sh)" @ install'
  'Pasarguard node (pg-node)|/opt/pg-node /var/lib/pg-node /opt/pasarguard|bash -c "$(curl -sL https://raw.githubusercontent.com/PasarGuard/scripts/master/node.sh)" @ install'
  '3x-ui panel|/etc/x-ui /usr/local/x-ui|bash -c "$(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)"'
  'WireGuard + WGDashboard|/etc/wireguard|apt-get install -y wireguard'
)

# node_backup — archive whatever node configuration exists on this host.
node_backup() {
  ui_section "Back up node configuration"
  local entry label paths _cmd found=() path
  for entry in "${ST_NODE_TARGETS[@]}"; do
    IFS='|' read -r label paths _cmd <<<"$entry"
    for path in $paths; do
      [[ -e $path ]] && found+=("$path")
    done
  done

  if ((${#found[@]} == 0)); then
    printf 'No known node configuration found on this server.\n'
    return 2
  fi

  printf 'Found:\n'
  printf '  %s\n' "${found[@]}"
  if ! has_cmd tar; then
    log_error "tar is not available — cannot create the archive."
    return 1
  fi

  mkdir -p "$ST_NODE_BACKUP_DIR"
  local archive="${ST_NODE_BACKUP_DIR}/node-config-${ST_RUN_ID}.tar.gz"
  if ! tar -czf "$archive" "${found[@]}" 2>>"$ST_LOG_FILE"; then
    log_error "Creating ${archive} failed — see the log."
    return 1
  fi
  chmod 600 "$archive"
  printf '%sSaved:%s %s (%s)\n' "$C_OK" "$C_RESET" "$archive" \
    "$(du -h "$archive" 2>/dev/null | awk '{print $1}')"
  printf '%sIt contains certificates and keys — keep it private.%s\n' "$C_WARN" "$C_RESET"
  log_info "Node configuration archived to ${archive}."
  return 0
}

# node_install — run an official upstream installer after showing it in full.
node_install() {
  ui_section "Install a node (official upstream installers)"
  printf '%sServerTools does not ship its own installer.%s The exact command is\n' "$C_MUTED" "$C_RESET"
  printf 'printed before it runs — it is third-party code, executed as root.\n\n'

  local i=1 entry label _paths cmd
  for entry in "${ST_NODE_TARGETS[@]}"; do
    IFS='|' read -r label _paths cmd <<<"$entry"
    ui_menu_item "$i" "$label" ''
    i=$((i + 1))
  done
  ui_menu_item 0 "Back"

  local choice
  read -rp "Select [0]: " choice || return 2
  [[ $choice =~ ^[1-4]$ ]] || return 2
  IFS='|' read -r label _paths cmd <<<"${ST_NODE_TARGETS[$((choice - 1))]}"

  printf '\n%sCommand to be executed:%s\n  %s\n\n' "$C_KEY" "$C_RESET" "$cmd"
  printf 'Existing configuration should be backed up first (menu option: backup).\n'
  ui_confirm "Run this third-party installer as root now?" || return 2

  if eval "$cmd"; then
    printf '%s%s installer finished.%s Re-run Quick Optimize so the profile matches.\n' \
      "$C_OK" "$label" "$C_RESET"
    log_info "Ran official installer for ${label}."
    return 0
  fi
  log_error "The ${label} installer exited with an error — see its output above."
  return 1
}

node_menu() {
  local choice
  while true; do
    ui_logo
    ui_title "Node & Docker helpers"
    ui_kv "Detected" "$(detect_summary)"
    ui_menu_item 1 "Back up node config" "archive certificates and settings"
    ui_menu_item 2 "Install a node" "runs the official upstream installer"
    ui_menu_item 3 "Docker file limits" "raise nofile for all containers"
    ui_menu_item 0 "Back"
    read -rp "$(_ui_prompt)" choice || return 0
    case "${choice:-}" in
      1)
        node_backup || true # outcome already reported
        ui_pause
        ;;
      2)
        node_install || true
        ui_pause
        ;;
      3)
        limits_docker_ulimits || true
        ui_pause
        ;;
      0) return 0 ;;
      *)
        printf '%sInvalid choice.%s\n' "$C_ERR" "$C_RESET"
        sleep 1
        ;;
    esac
  done
}
