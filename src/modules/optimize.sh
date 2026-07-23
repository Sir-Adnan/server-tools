# shellcheck shell=bash
# ============================================================================
# modules/optimize.sh — Quick/Custom Optimize flows:
# plan → confirm → apply steps with honest per-step outcomes → summary.
#
# NOTE: step functions run via `"$fn" || rc=$?`, which suppresses errexit for
# their whole body (bash semantics). Steps therefore signal outcomes with
# explicit return codes: 0=ok, 1=failed, 2=skipped, 3=applied with warnings.
# ============================================================================

ST_STEP_RESULTS=()
ST_STEP_IDX=0
ST_STEP_TOTAL=0

# --auto flags, filled by the CLI parser in 99-main.sh.
ST_AUTO_PROFILE=''
ST_AUTO_TIER=''
ST_AUTO_USERS=''
ST_AUTO_DNS=''
ST_AUTO_SWAP=1
ST_AUTO_LIMITS=1
ST_AUTO_EXTRAS=1

st_run_step() { # st_run_step TITLE FN
  local title="$1" fn="$2" rc=0 note
  ST_STEP_IDX=$((ST_STEP_IDX + 1))
  printf '%s[%d/%d]%s %s ... ' "$C_KEY" "$ST_STEP_IDX" "$ST_STEP_TOTAL" "$C_RESET" "$title"

  # Keep the status line intact: warnings are collected and printed below it.
  ST_LOG_BUFFER=()
  ST_LOG_BUFFERING=1
  "$fn" || rc=$?
  ST_LOG_BUFFERING=0
  case "$rc" in
    0)
      printf '%sOK%s\n' "$C_OK" "$C_RESET"
      ST_STEP_RESULTS+=("ok|${title}")
      ;;
    2)
      printf '%sSKIPPED%s\n' "$C_MUTED" "$C_RESET"
      ST_STEP_RESULTS+=("skip|${title}")
      ;;
    3)
      printf '%sWARN%s\n' "$C_WARN" "$C_RESET"
      ST_STEP_RESULTS+=("warn|${title}")
      st_escalate_exit 3
      ;;
    *)
      printf '%sFAILED%s\n' "$C_ERR" "$C_RESET"
      ST_STEP_RESULTS+=("fail|${title}")
      st_escalate_exit 1
      ;;
  esac

  for note in "${ST_LOG_BUFFER[@]-}"; do
    [[ -n $note ]] && printf '      %s%s%s\n' "$C_MUTED" "$note" "$C_RESET"
  done
  ST_LOG_BUFFER=()
  return 0
}

# --- Before/after snapshot -------------------------------------------------
# Kernel counters captured before the first change, so the effect of the
# tuning can be shown later instead of merely claimed.

readonly ST_SNAPSHOT_FILE="${ST_LIB_DIR}/snapshot.tsv"

_snapshot_counters() {
  local retrans='0' insegs='0' outsegs='0' drops='0' ct='0'
  if [[ -r /proc/net/snmp ]]; then
    # The Tcp: header line names the columns; the next Tcp: line holds values.
    read -r retrans insegs outsegs < <(awk '
      /^Tcp:/ { if (!h) { for (i = 1; i <= NF; i++) idx[$i] = i; h = 1; next }
                print $idx["RetransSegs"], $idx["InSegs"], $idx["OutSegs"]; exit }' /proc/net/snmp)
  fi
  if [[ -r /proc/net/dev ]]; then
    drops="$(awk 'NR > 2 {rx += $5; tx += $12} END {print rx + tx + 0}' /proc/net/dev)"
  fi
  ct="$(sysctl_get net.netfilter.nf_conntrack_count)"
  [[ $ct =~ ^[0-9]+$ ]] || ct=0
  printf '%s\t%s\t%s\t%s\t%s' "${retrans:-0}" "${insegs:-0}" "${outsegs:-0}" "${drops:-0}" "$ct"
}

snapshot_save() {
  local now
  now="$(_snapshot_counters)" || return 0
  printf 'taken_at\t%s\n' "$(date '+%F %T')" >"$ST_SNAPSHOT_FILE"
  printf 'counters\t%s\n' "$now" >>"$ST_SNAPSHOT_FILE"
  log_debug "baseline snapshot stored"
}

# snapshot_report — deltas since the baseline; silent when none was taken.
snapshot_report() {
  [[ -f $ST_SNAPSHOT_FILE ]] || return 2
  local taken old new
  taken="$(awk -F'\t' '$1 == "taken_at" {print $2; exit}' "$ST_SNAPSHOT_FILE")"
  old="$(awk -F'\t' '$1 == "counters" {print $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6; exit}' "$ST_SNAPSHOT_FILE")"
  new="$(_snapshot_counters)"

  local o_re o_in o_out o_drop _o_ct n_re n_in n_out n_drop n_ct
  IFS=$'\t' read -r o_re o_in o_out o_drop _o_ct <<<"$old"
  IFS=$'\t' read -r n_re n_in n_out n_drop n_ct <<<"$new"

  local d_re=$((n_re - o_re)) d_seg=$((n_in - o_in + n_out - o_out)) d_drop=$((n_drop - o_drop))
  ui_kv "Baseline taken" "$taken"
  if ((d_seg > 0)); then
    # Retransmit rate in per-mille keeps integer math honest on small samples.
    ui_kv "TCP retransmits" "${d_re} of ${d_seg} segments ($((d_re * 1000 / d_seg))‰ since baseline)"
  else
    ui_kv "TCP retransmits" "${d_re} since baseline"
  fi
  ui_kv "Interface drops" "${d_drop} since baseline"
  ui_kv "Conntrack now" "$n_ct"
  return 0
}

st_report_summary() {
  local entry status _title ok=0 warn=0 fail=0 skip=0
  for entry in "${ST_STEP_RESULTS[@]-}"; do
    [[ -n $entry ]] || continue # empty array expands to one empty element
    IFS='|' read -r status _title <<<"$entry"
    case "$status" in
      ok) ok=$((ok + 1)) ;;
      warn) warn=$((warn + 1)) ;;
      skip) skip=$((skip + 1)) ;;
      fail) fail=$((fail + 1)) ;;
    esac
  done

  ui_hr
  if ((fail > 0)); then
    printf '%sCompleted with failures:%s %d ok, %d warned, %d skipped, %d failed — see the log.\n' \
      "$C_ERR" "$C_RESET" "$ok" "$warn" "$skip" "$fail"
  elif ((warn > 0)); then
    printf '%sCompleted with warnings:%s %d ok, %d warned, %d skipped — details in the log.\n' \
      "$C_WARN" "$C_RESET" "$ok" "$warn" "$skip"
  else
    printf '%sAll steps completed:%s %d applied, %d skipped.\n' "$C_OK" "$C_RESET" "$ok" "$skip"
  fi
  ui_kv "Backups" "$ST_RUN_BACKUP_DIR"
  ui_kv "Log" "$ST_LOG_FILE"
  ui_kv "Rollback" "menu option [4], or: --rollback"
  printf '%sNo daemons or cron jobs were installed — nothing stays running.%s\n' "$C_MUTED" "$C_RESET"
}

_optimize_show_plan() {
  ui_kv "Profile" "${ST_PROFILE} (${ST_PROFILE_SOURCE})"
  if ((ST_EXPECTED_USERS > 0)); then
    ui_kv "Capacity" "${ST_EXPECTED_USERS} expected users (conntrack sized from users; buffers from RAM tier ${ST_TIER})"
  else
    ui_kv "Capacity tier" "${ST_TIER} — up to ${ST_TIER_USERS} concurrent users"
  fi
  if profile_wants_forwarding; then
    ui_kv "Conntrack" "${ST_CONNTRACK} entries (~$(tier_conntrack_ram_mb) MB kernel RAM worst case)"
  fi
  ui_kv "Socket buffers" "up to ${ST_BUF_MB} MB per socket"
  ui_kv "Congestion" "BBR when the kernel supports it, else cubic"

  local warn
  warn="$(capacity_warning)"
  if [[ -n $warn ]]; then
    printf '  %sCapacity warning:%s %s\n' "$C_WARN" "$C_RESET" "$warn"
    log_info "capacity warning: ${warn}"
  fi
}

# _optimize_run WITH_DNS WITH_SWAP WITH_LIMITS WITH_EXTRAS  (each 0/1)
_optimize_run() {
  local with_dns="$1" with_swap="$2" with_limits="$3" with_extras="$4"
  ST_STEP_RESULTS=()
  ST_STEP_IDX=0
  ST_STEP_TOTAL=$((1 + with_dns + with_swap + with_limits + with_extras))
  # Baseline first: counters must be read before anything is changed.
  snapshot_save
  ui_hr
  # Swap runs BEFORE sysctl on purpose: vm.swappiness depends on whether the
  # host ends up on compressed RAM (zram) or a disk swap file.
  ((with_swap)) && st_run_step "Swap" swap_apply
  st_run_step "Kernel network tuning (sysctl, tier ${ST_TIER})" sysctl_apply
  ((with_limits)) && st_run_step "File-descriptor limits (nofile)" limits_apply
  ((with_extras)) && st_run_step "Journald cap & NTP" extras_apply
  ((with_dns)) && st_run_step "DNS (${ST_DNS1} / ${ST_DNS2})" dns_apply
  st_report_summary
  # Show what actually answers queries — a written config proves nothing.
  ((with_dns)) && ui_kv "DNS in effect" "$(dns_effective_servers)"
  _offer_service_restart
  config_set last_profile "$ST_PROFILE"
  config_set last_tier "$ST_TIER"
  backup_prune 10
  return 0
}

# _offer_service_restart — running services keep their old nofile limit
# until restarted; offer to restart detected VPN workloads (interactive),
# or just say so honestly (batch).
_offer_service_restart() {
  ((ST_LIMITS_CHANGED)) || return 0

  # Match on name AND image: a pg-node container is often just called "node"
  # while only its image identifies it (same source as detect_stack).
  # grep exit 1 (no match) is a normal outcome here, not an error.
  local containers='' engine
  for engine in docker podman; do
    has_cmd "$engine" || continue
    containers+="$("$engine" ps --format '{{.Names}} {{.Image}}' 2>/dev/null |
      grep -iE 'marzban|pg[-_]?node|pasarguard|gozargah|x-?ui|xray|hiddify|sing-?box|hysteria|wireguard|wg-' |
      awk -v e="$engine" '{print e "\t" $1}' || true)"
  done

  if [[ -n $containers ]]; then
    printf '%sNote:%s containers inherit their file limit from the container engine,\n' "$C_MUTED" "$C_RESET"
    printf 'not from /etc/security/limits.d — set "default-ulimits" in\n'
    printf '/etc/docker/daemon.json if a node still reports a low nofile.\n'
    printf '%sA restart briefly disconnects the users served by that node.%s\n' "$C_WARN" "$C_RESET"
  fi

  if ((ST_OPT_BATCH)); then
    if [[ -n $containers ]]; then
      printf '%sNote:%s restart these containers so they pick up the new limits:\n  %s\n' \
        "$C_WARN" "$C_RESET" "$(awk '{printf "%s ", $2}' <<<"$containers")"
    fi
    return 0
  fi

  # The list is read through FD 3 on purpose: with the list on stdin, the
  # `read` inside ui_confirm would consume it instead of the user's answer —
  # and bash hides the prompt entirely when stdin is not a terminal.
  local engine_name name
  while IFS=$'\t' read -r engine_name name <&3; do
    [[ -n $name ]] || continue
    if ui_confirm "Restart ${engine_name} container '${name}' now so it picks up the new limits?"; then
      if "$engine_name" restart "$name" >/dev/null 2>>"$ST_LOG_FILE"; then
        printf '%sRestarted:%s %s\n' "$C_OK" "$C_RESET" "$name"
      else
        log_warn "Could not restart ${name}."
      fi
    fi
  done 3<<<"$containers"

  local svc
  for svc in xray x-ui sing-box hysteria-server; do
    if has_cmd systemctl && systemctl is-active --quiet "$svc" 2>/dev/null; then
      if ui_confirm "Restart service '${svc}' now so it picks up the new limits?"; then
        if systemctl restart "$svc" 2>>"$ST_LOG_FILE"; then
          printf '%sRestarted:%s %s\n' "$C_OK" "$C_RESET" "$svc"
        else
          log_warn "Could not restart ${svc}."
        fi
      fi
    fi
  done
  return 0
}

quick_optimize() {
  ui_logo
  ui_title "Quick Optimize"
  detect_stack
  profile_resolve_auto
  tier_compute

  printf 'The base layer always optimizes the whole server; the detected profile\n'
  printf 'only adds specialised tuning on top of it.\n'
  ui_hr
  _optimize_show_plan
  ui_hr

  local with_dns=0
  if dns_select_menu; then
    with_dns=1
  fi

  printf '\n'
  if ! ui_confirm "Apply the plan above?"; then
    ui_pause
    return 0
  fi
  _optimize_run "$with_dns" 1 1 1
  ui_pause
}

# _apply_cli_profile_tier — resolve profile/tier honouring --profile/--tier
# overrides; invalid values die with a clear message. Shared by auto+dry-run.
_apply_cli_profile_tier() {
  if [[ -n $ST_AUTO_PROFILE ]]; then
    case "$ST_AUTO_PROFILE" in
      general | vpn-node | wireguard | panel | full)
        ST_PROFILE="$ST_AUTO_PROFILE"
        ST_PROFILE_SOURCE='cli'
        ;;
      *) die "Invalid --profile '${ST_AUTO_PROFILE}' (general|vpn-node|wireguard|panel|full)." ;;
    esac
  else
    profile_resolve_auto
  fi

  if [[ -n $ST_AUTO_USERS && ! $ST_AUTO_USERS =~ ^[0-9]+$ ]]; then
    die "Invalid --users '${ST_AUTO_USERS}' (expected a number)."
  fi

  tier_compute
  if [[ -n $ST_AUTO_TIER ]]; then
    case "$ST_AUTO_TIER" in
      S | M | L | XL)
        tier_set "$ST_AUTO_TIER"
        capacity_apply_users # a manual tier must not silently drop the users model
        ;;
      *) die "Invalid --tier '${ST_AUTO_TIER}' (S|M|L|XL)." ;;
    esac
  fi
}

# auto_optimize — the non-interactive flow behind --auto. No prompts: DNS is
# only touched when --dns was given.
auto_optimize() {
  detect_stack
  _apply_cli_profile_tier

  local with_dns=0
  if [[ -n $ST_AUTO_DNS ]]; then
    dns_resolve_cli "$ST_AUTO_DNS" ||
      die "Invalid --dns '${ST_AUTO_DNS}' (provider name or ip1,ip2)."
    with_dns=1
  fi

  ui_title "Auto Optimize (non-interactive)"
  _optimize_show_plan
  _optimize_run "$with_dns" "$ST_AUTO_SWAP" "$ST_AUTO_LIMITS" "$ST_AUTO_EXTRAS"
}

# dry_run_optimize — --dry-run: show the plan and the exact sysctl diff,
# apply absolutely nothing.
dry_run_optimize() {
  detect_stack
  _apply_cli_profile_tier
  ui_title "Dry Run — nothing will be applied"
  _optimize_show_plan
  ui_hr
  sysctl_dry_run
  printf '\nA real run would also cover: nofile limits, journald cap & NTP, swap%s.\n' \
    "$([[ -n $ST_AUTO_DNS ]] && printf ', DNS')"
}

custom_optimize() {
  ui_logo
  ui_title "Custom Optimize"
  detect_stack
  profile_resolve_auto
  local suggested="$ST_PROFILE"

  printf '%s[Workload profile]%s suggested: %s (%s)\n' \
    "$C_TITLE" "$C_RESET" "$suggested" "$ST_PROFILE_SOURCE"
  ui_menu_item 1 "general" "complete general-purpose tuning"
  ui_menu_item 2 "vpn-node" "Xray node (marzban-node / pg-node / x-ui)"
  ui_menu_item 3 "wireguard" "WireGuard host"
  ui_menu_item 4 "panel" "Marzban/Pasarguard panel host"
  ui_menu_item 5 "full" "everything with best-practice defaults"
  local choice
  read -rp "Select [Enter=suggested]: " choice || return 0
  case "${choice:-}" in
    1) ST_PROFILE='general' ;;
    2) ST_PROFILE='vpn-node' ;;
    3) ST_PROFILE='wireguard' ;;
    4) ST_PROFILE='panel' ;;
    5) ST_PROFILE='full' ;;
    *) ST_PROFILE="$suggested" ;;
  esac
  ST_PROFILE_SOURCE='manual'

  tier_compute
  local tier_choice
  read -rp "Capacity tier — auto picked ${ST_TIER} (up to ${ST_TIER_USERS} users). Override [S/M/L/XL, Enter=keep]: " tier_choice || tier_choice=''
  case "${tier_choice^^}" in
    S | M | L | XL)
      tier_set "${tier_choice^^}"
      config_set capacity_tier "${tier_choice^^}"
      ;;
  esac

  local users_in
  read -rp "Expected concurrent users [Enter=size by RAM, 0=reset saved value]: " users_in || users_in=''
  if [[ $users_in =~ ^[0-9]+$ ]]; then
    config_set expected_users "$users_in"
  fi
  capacity_apply_users

  ui_hr
  _optimize_show_plan
  ui_hr

  if ! ui_confirm_yes "Apply sysctl kernel tuning? (the core step)"; then
    printf 'Nothing to do without the sysctl step.\n'
    ui_pause
    return 0
  fi
  local with_swap=0 with_limits=0 with_extras=0 with_dns=0
  ui_confirm_yes "Raise file-descriptor limits?" && with_limits=1
  ui_confirm_yes "Cap journald disk usage and enable NTP?" && with_extras=1
  ui_confirm_yes "Create a swap file if none exists?" && with_swap=1
  if dns_select_menu; then
    with_dns=1
  fi

  printf '\n'
  if ! ui_confirm "Apply now?"; then
    ui_pause
    return 0
  fi
  _optimize_run "$with_dns" "$with_swap" "$with_limits" "$with_extras"
  ui_pause
}
