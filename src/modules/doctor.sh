# shellcheck shell=bash
# ============================================================================
# modules/doctor.sh — health check and drift detection (`--verify`).
#
# The verify contract every module follows:
#   0  applied and in effect
#   2  not configured by ServerTools (nothing to check)
#   3  configured but the live system disagrees — drift
#
# A kernel upgrade, a panel installer or a hand edit can undo tuning without
# telling anyone; this is where that becomes visible.
# ============================================================================

# Registry: "label|verify function|repair hint"
readonly -a ST_DOCTOR_CHECKS=(
  'Kernel tuning (sysctl)|sysctl_verify|re-run Quick Optimize'
  'CPU/NIC performance|perf_verify|re-run Quick Optimize'
  'DNS servers|dns_verify|Quick Optimize, then pick the provider again'
  'File limits (nofile)|limits_verify|re-run Quick Optimize'
  'Swap|swap_verify|Custom Optimize, enable the swap step'
  'SSH hardening|ssh_verify|Security menu, option 3'
  'MSS clamping|mss_verify|Network tools, option 5'
  'Conntrack NOTRACK|notrack_verify|Network tools, option n'
  'IPv6 disabled|ipv6_verify|Network tools, IPv6 control — disable again'
)

ST_DOCTOR_DRIFT=0
ST_DOCTOR_OK=0
ST_DOCTOR_NA=0

# _doctor_run_check LABEL FN HINT — one row of the report.
_doctor_run_check() {
  local label="$1" fn="$2" hint="$3" rc=0
  declare -F "$fn" >/dev/null 2>&1 || return 0
  "$fn" || rc=$?
  case "$rc" in
    0)
      ST_DOCTOR_OK=$((ST_DOCTOR_OK + 1))
      printf '  %s%-26s%s %sOK%s\n' "$C_KEY" "$label" "$C_RESET" "$C_OK" "$C_RESET"
      ;;
    2)
      ST_DOCTOR_NA=$((ST_DOCTOR_NA + 1))
      printf '  %s%-26s%s %snot configured%s\n' "$C_KEY" "$label" "$C_RESET" "$C_MUTED" "$C_RESET"
      ;;
    *)
      ST_DOCTOR_DRIFT=$((ST_DOCTOR_DRIFT + 1))
      printf '  %s%-26s%s %sDRIFT%s — %s\n' "$C_KEY" "$label" "$C_RESET" "$C_WARN" "$C_RESET" "$hint"
      ;;
  esac
}

# _doctor_json — machine-readable result for fleet automation.
_doctor_json() {
  local entry label fn hint rc first=1
  printf '{"version":"%s","host":"%s","checks":[' \
    "$ST_VERSION" "$(hostname 2>/dev/null || printf 'unknown')"
  for entry in "${ST_DOCTOR_CHECKS[@]}"; do
    IFS='|' read -r label fn hint <<<"$entry"
    declare -F "$fn" >/dev/null 2>&1 || continue
    rc=0
    "$fn" || rc=$?
    ((first)) || printf ','
    first=0
    case "$rc" in
      0) printf '{"check":"%s","status":"ok"}' "$label" ;;
      2) printf '{"check":"%s","status":"not_configured"}' "$label" ;;
      *) printf '{"check":"%s","status":"drift","hint":"%s"}' "$label" "$hint" ;;
    esac
    case "$rc" in
      0 | 2) : ;;
      *) ST_DOCTOR_DRIFT=$((ST_DOCTOR_DRIFT + 1)) ;;
    esac
  done
  printf '],"drift":%d,"profile":"%s","tier":"%s"}\n' \
    "$ST_DOCTOR_DRIFT" "$(config_get last_profile none)" "$(config_get last_tier -)"
}

# doctor_run — the whole report. Returns 0 when healthy, 3 on drift.
doctor_run() {
  ST_DOCTOR_DRIFT=0
  ST_DOCTOR_OK=0
  ST_DOCTOR_NA=0

  if ((ST_OPT_JSON)); then
    _doctor_json
    ((ST_DOCTOR_DRIFT > 0)) && return 3
    return 0
  fi

  ui_logo
  ui_title "Doctor — is everything still in effect?"
  ui_section "Checks"
  local entry label fn hint
  for entry in "${ST_DOCTOR_CHECKS[@]}"; do
    IFS='|' read -r label fn hint <<<"$entry"
    _doctor_run_check "$label" "$fn" "$hint"
  done
  ui_hr

  # Listening ports that appeared after the last apply are a silent hazard:
  # an outgoing connection can steal a port a node still needs.
  local unreserved
  unreserved="$(_doctor_unreserved_ports)"
  if [[ -n $unreserved ]]; then
    ST_DOCTOR_DRIFT=$((ST_DOCTOR_DRIFT + 1))
    printf '  %s%-26s%s %sDRIFT%s — %s not reserved; re-run Quick Optimize\n' \
      "$C_KEY" "Reserved service ports" "$C_RESET" "$C_WARN" "$C_RESET" "$unreserved"
    ui_hr
  fi

  ui_section "Effect since the last baseline"
  snapshot_report || printf '  (no baseline yet — it is taken on the next optimize run)\n'
  ui_hr

  if ((ST_DOCTOR_DRIFT > 0)); then
    printf '%s%d check(s) drifted%s · %d OK · %d not configured\n' \
      "$C_WARN" "$ST_DOCTOR_DRIFT" "$C_RESET" "$ST_DOCTOR_OK" "$ST_DOCTOR_NA"
    printf 'Run "st --dry-run" to see exactly which kernel keys differ.\n'
    return 3
  fi
  printf '%sEverything ServerTools configured is still in effect.%s (%d OK, %d not configured)\n' \
    "$C_OK" "$C_RESET" "$ST_DOCTOR_OK" "$ST_DOCTOR_NA"
  return 0
}

# _doctor_unreserved_ports — listening ports inside the ephemeral range that
# the current sysctl file does not reserve (typically inbounds added later).
_doctor_unreserved_ports() {
  [[ -f $ST_SYSCTL_FILE ]] || return 0
  local reserved port missing=''
  reserved="$(awk -F'= *' '/ip_local_reserved_ports/ {print $2; exit}' "$ST_SYSCTL_FILE")" || reserved=''
  [[ -n $reserved ]] || return 0

  # Same source as the apply step, so a service that started later shows up
  # while transient proxy sockets do not raise a false alarm.
  while IFS= read -r port; do
    [[ $port =~ ^[0-9]+$ ]] || continue
    _port_in_reserved_list "$port" "$reserved" || missing+="${port} "
  done < <(listening_service_ports)

  printf '%s' "${missing% }"
}

# _port_in_reserved_list PORT LIST — LIST holds numbers and "a-b" ranges.
_port_in_reserved_list() {
  local port="$1" item low high
  while IFS= read -r item; do
    if [[ $item == *-* ]]; then
      low="${item%%-*}"
      high="${item##*-}"
      [[ $low =~ ^[0-9]+$ && $high =~ ^[0-9]+$ ]] || continue
      if ((port >= low && port <= high)); then return 0; fi
    elif [[ $item == "$port" ]]; then
      return 0
    fi
  done < <(ports_split "$2")
  return 1
}
