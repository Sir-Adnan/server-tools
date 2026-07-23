# shellcheck shell=bash
# ============================================================================
# menu.sh — interactive main menu and sub-screens.
# The dashboard must render instantly: everything network-bound is cached
# (public IP is fetched at most once per process, in utils.sh).
# ============================================================================

menu_dashboard() {
  ui_logo
  ui_kv "OS" "$(os_pretty_name)"
  ui_kv "Kernel" "$(kernel_release)"
  ui_kv "RAM" "$(mem_total_mb) MB · $(cpu_cores) core(s)"
  ui_kv "Public IPv4" "$(net_public_ip4)"
  ui_kv "TCP" "cc=$(sysctl_get net.ipv4.tcp_congestion_control) · qdisc=$(sysctl_get net.core.default_qdisc)"
  ui_kv "Detected" "$(detect_summary)"
  ui_hr
}

menu_rollback() {
  ui_logo
  ui_title "Rollback"
  local run choice
  run="$(manifest_latest_run)"
  if [[ -z $run ]]; then
    printf 'No recorded changes yet — nothing to roll back.\n'
    ui_pause
    return 0
  fi
  printf 'Latest recorded run: %s%s%s · %s change(s) recorded in total\n' \
    "$C_ACCENT" "$run" "$C_RESET" "$(manifest_entry_count)"
  ui_hr
  ui_menu_item 1 "Undo the last run" "restore files that run changed, remove what it created"
  ui_menu_item 2 "Restore original state" "everything back to before ServerTools ever ran"
  ui_menu_item 0 "Back"
  ui_hr
  read -rp "Select: " choice || return 0
  case "${choice:-}" in
    1) ui_confirm "Revert all changes from run ${run}?" && rollback_latest ;;
    2)
      printf '%sThis undoes every ServerTools change on this host.%s\n' "$C_WARN" "$C_RESET"
      ui_confirm "Restore the original (factory) state?" && rollback_original
      ;;
    *) return 0 ;;
  esac
  ui_pause
}

menu_settings() {
  local choice
  while true; do
    ui_logo
    ui_title "Settings & Maintenance"
    ui_kv "Version" "$ST_VERSION"
    ui_kv "Config file" "$ST_CONFIG_FILE"
    ui_kv "Log file" "$ST_LOG_FILE"
    ui_kv "Backups" "$ST_BACKUP_DIR"
    ui_kv "Recorded changes" "$(manifest_entry_count)"
    ui_kv "Saved profile" "$(config_get last_profile 'none yet') / tier $(config_get last_tier '-')"
    ui_hr
    ui_menu_item 1 "Install 'st' command" "run 'st' instead of the long one-liner"
    ui_menu_item 2 "Check for updates" "self-update from the latest release"
    ui_menu_item 0 "Back"
    ui_hr
    read -rp "Select: " choice || return 0
    case "${choice:-}" in
      1)
        st_self_install || log_warn "Install did not complete."
        ui_pause
        ;;
      2)
        st_self_update || log_warn "Update did not complete."
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

main_menu() {
  detect_stack
  local choice
  while true; do
    menu_dashboard
    ui_menu_item 1 "Quick Optimize" "full base layer + auto-detected profile (recommended)"
    ui_menu_item 2 "Custom Optimize" "pick profile and modules manually"
    ui_menu_item 3 "System Status" "full report"
    ui_menu_item 4 "Doctor" "is everything still in effect? (drift check)"
    ui_menu_item 5 "Rollback" "undo changes"
    ui_menu_item 6 "Security" "UFW / fail2ban / SSH / anti-abuse (optional)"
    ui_menu_item 7 "Network & VPN tools" "ping, speed, live view, MSS, mirror"
    ui_menu_item 8 "Node & Docker" "config backup, installers, container limits"
    ui_menu_item 9 "Settings" "paths, config, install/update"
    ui_menu_item 0 "Exit"
    ui_hr
    # EOF (e.g. closed stdin) simply exits the menu.
    read -rp "Select: " choice || {
      printf '\n'
      return 0
    }
    case "${choice:-}" in
      1) quick_optimize ;;
      2) custom_optimize ;;
      3) show_status ;;
      4)
        doctor_run || true # drift is reported on screen, not an error here
        ui_pause
        ;;
      5) menu_rollback ;;
      6) security_menu ;;
      7) tools_menu ;;
      8) node_menu ;;
      9) menu_settings ;;
      0) return 0 ;;
      *)
        printf '%sInvalid choice.%s\n' "$C_ERR" "$C_RESET"
        sleep 1
        ;;
    esac
  done
}
