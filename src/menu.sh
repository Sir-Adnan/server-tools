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
  local run
  run="$(manifest_latest_run)"
  if [[ -z $run ]]; then
    printf 'No recorded changes yet — nothing to roll back.\n'
    ui_pause
    return 0
  fi
  printf 'Latest recorded run: %s%s%s\n' "$C_ACCENT" "$run" "$C_RESET"
  printf 'This restores every file that run modified and removes files it created.\n'
  ui_hr
  if ui_confirm "Revert all changes from this run?"; then
    rollback_latest
  fi
  ui_pause
}

menu_settings() {
  ui_logo
  ui_title "Settings & Paths"
  ui_kv "Version" "$ST_VERSION"
  ui_kv "Config file" "$ST_CONFIG_FILE"
  ui_kv "Log file" "$ST_LOG_FILE"
  ui_kv "Backups" "$ST_BACKUP_DIR"
  ui_kv "Manifest" "$ST_MANIFEST_FILE"
  ui_kv "Recorded changes" "$(manifest_entry_count)"
  ui_hr
  printf 'Preference options (DNS provider, capacity tier, profile) arrive together\n'
  printf 'with the optimization modules in the next milestone.\n'
  ui_pause
}

main_menu() {
  detect_stack
  local choice
  while true; do
    menu_dashboard
    ui_menu_item 1 "Quick Optimize" "full base layer + auto-detected profile (recommended)"
    ui_menu_item 2 "Custom Optimize" "pick profile and modules manually"
    ui_menu_item 3 "System Status" "full report"
    ui_menu_item 4 "Rollback" "undo the latest recorded run"
    ui_menu_item 5 "Security" "UFW / fail2ban / SSH hardening (optional)"
    ui_menu_item 6 "Network & VPN tools" "ping matrix, MSS clamp, audits"
    ui_menu_item 7 "Settings" "paths, config, manifest"
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
      4) menu_rollback ;;
      5) security_menu ;;
      6) tools_menu ;;
      7) menu_settings ;;
      0) return 0 ;;
      *)
        printf '%sInvalid choice.%s\n' "$C_ERR" "$C_RESET"
        sleep 1
        ;;
    esac
  done
}
