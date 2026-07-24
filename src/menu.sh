# shellcheck shell=bash
# ============================================================================
# menu.sh — interactive main menu and sub-screens.
# The dashboard must render instantly: everything network-bound is cached
# (public IP is fetched at most once per process, in utils.sh).
# ============================================================================

# _dash_row LABEL VALUE — one compact dashboard line (tight, no colon).
_dash_row() {
  printf '  %s%-9s%s %s\n' "$C_KEY" "$1" "$C_RESET" "$2"
}

menu_dashboard() {
  ui_logo

  # Optimized state is a first-class signal: a returning user sees at a glance
  # whether this host is tuned, without opening a report.
  local prof status
  prof="$(config_get last_profile '')"
  if [[ -n $prof ]]; then
    status="$(ui_badge ok) optimized ${C_MUTED}· ${prof} · tier $(config_get last_tier '-')${C_RESET}"
  else
    status="$(ui_badge idle) not optimized yet ${C_MUTED}· run Quick Optimize${C_RESET}"
  fi

  _dash_row "Host" "$(hostname 2>/dev/null || printf 'unknown') · $(os_pretty_name) · $(kernel_release)"
  _dash_row "Machine" "$(cpu_cores) vCPU · $(mem_total_mb) MB RAM · up $(uptime_pretty)"
  _dash_row "Network" "$(net_public_ip4) · cc=$(sysctl_get net.ipv4.tcp_congestion_control) · $(sysctl_get net.core.default_qdisc)"
  _dash_row "Workload" "$(detect_summary) · ${status}"
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
  ui_menu_item 1 "Undo the last run" "restore changed files, remove created ones"
  ui_menu_item 2 "Restore original state" "back to before ServerTools ever ran"
  ui_menu_item 0 "Back"
  read -rp "$(_ui_prompt)" choice || return 0
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
    ui_menu_item 1 "Install 'st' command" "run 'st' instead of the one-liner"
    ui_menu_item 2 "Check for updates" "self-update from the latest release"
    ui_menu_item 0 "Back"
    read -rp "$(_ui_prompt)" choice || return 0
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
    ui_hr
    ui_menu_group "Optimize"
    ui_menu_item 1 "Quick Optimize" "auto-tune everything · recommended"
    ui_menu_item 2 "Custom Optimize" "choose profile and modules"
    ui_menu_group "Inspect"
    ui_menu_item 3 "System Status" "full live report"
    ui_menu_item 4 "Doctor" "drift check — still in effect?"
    ui_menu_group "Manage"
    ui_menu_item 5 "Rollback" "undo changes safely"
    ui_menu_item 6 "Security" "UFW · fail2ban · SSH"
    ui_menu_item 7 "Network & VPN Tools" "ping · speed · MSS · NOTRACK"
    ui_menu_item 8 "Node & Docker" "backups · installers · limits"
    ui_menu_group "System"
    ui_menu_item 9 "Settings" "install · update · paths"
    ui_menu_item 0 "Exit"
    printf '\n'
    ui_hint "New here? Press 1 — it detects your workload and tunes it safely."
    # EOF (e.g. closed stdin) simply exits the menu.
    read -rp "$(_ui_prompt)" choice || {
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
