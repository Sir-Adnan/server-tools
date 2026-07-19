# shellcheck shell=bash
# ============================================================================
# modules/profile.sh — layered profile resolution and capacity tiers.
# Implements docs/PROFILES.md: the base layer ALWAYS covers the whole server;
# the workload profile only decides the specialised extras on top.
# ============================================================================

ST_PROFILE='general'
ST_PROFILE_SOURCE='default'

ST_TIER=''
ST_TIER_USERS=''
ST_SOMAXCONN=0
ST_NETDEV_BACKLOG=0
ST_BUF_MB=0
ST_CONNTRACK=0

profile_resolve_auto() {
  local detected=" ${ST_DETECTED[*]-} "
  ST_PROFILE_SOURCE='auto-detected'
  if [[ $detected == *'marzban-node'* || $detected == *'pg-node'* ||
    $detected == *'xray'* || $detected == *'x-ui'* || $detected == *'hiddify'* ||
    $detected == *'sing-box'* || $detected == *'hysteria'* || $detected == *'openvpn'* ]]; then
    ST_PROFILE='vpn-node'
  elif [[ $detected == *'wireguard'* || $detected == *'wg-dashboard'* ]]; then
    ST_PROFILE='wireguard'
  elif [[ $detected == *'marzban-panel'* ]]; then
    ST_PROFILE='panel'
  else
    ST_PROFILE='general'
    ST_PROFILE_SOURCE='nothing detected'
  fi
}

# profile_wants_forwarding — vpn workloads route user traffic.
profile_wants_forwarding() {
  [[ $ST_PROFILE == vpn-node || $ST_PROFILE == wireguard || $ST_PROFILE == full ]]
}

tier_set() {
  ST_TIER="$1"
  case "$1" in
    S) ST_TIER_USERS='~1k' ST_SOMAXCONN=8192 ST_NETDEV_BACKLOG=16384 ST_BUF_MB=8 ST_CONNTRACK=65536 ;;
    M) ST_TIER_USERS='~10k' ST_SOMAXCONN=16384 ST_NETDEV_BACKLOG=32768 ST_BUF_MB=16 ST_CONNTRACK=262144 ;;
    L) ST_TIER_USERS='~100k' ST_SOMAXCONN=32768 ST_NETDEV_BACKLOG=65536 ST_BUF_MB=32 ST_CONNTRACK=1048576 ;;
    XL) ST_TIER_USERS='100k+' ST_SOMAXCONN=65535 ST_NETDEV_BACKLOG=65536 ST_BUF_MB=64 ST_CONNTRACK=2097152 ;;
    *) tier_set S ;;
  esac
}

# tier_compute — pick from RAM; the capacity_tier config key overrides.
tier_compute() {
  local override ram_mb
  override="$(config_get capacity_tier auto)"
  case "$override" in
    S | M | L | XL)
      tier_set "$override"
      return 0
      ;;
  esac

  ram_mb="$(mem_total_mb)"
  if ((ram_mb <= 1536)); then
    tier_set S
  elif ((ram_mb <= 6144)); then
    tier_set M
  elif ((ram_mb <= 24576)); then
    tier_set L
  else
    tier_set XL
  fi

  # A panel host never needs an L/XL conntrack table (docs/PROFILES.md) —
  # its RAM is better left to the database.
  if [[ $ST_PROFILE == panel && ($ST_TIER == L || $ST_TIER == XL) ]]; then
    tier_set M
  fi

  capacity_apply_users
  return 0
}

tier_conntrack_ram_mb() {
  # ~300 bytes per conntrack entry, worst case (table full).
  printf '%d' $((ST_CONNTRACK * 300 / 1048576))
}

# --- User-based capacity model -------------------------------------------
# Conntrack demand follows the ACTIVE USER COUNT, not RAM: ~24 flows per
# online user × 1.5 headroom. RAM still sizes the buffers, and the honest
# feasibility check below warns when the combination cannot fit.

ST_EXPECTED_USERS=0

# capacity_apply_users — override ST_CONNTRACK from expected users (config
# key expected_users; the --users CLI flag wins when given). No-op when 0.
capacity_apply_users() {
  local users ct
  users="$(config_get expected_users 0)"
  if [[ ${ST_AUTO_USERS:-} =~ ^[0-9]+$ ]] && ((${ST_AUTO_USERS:-0} > 0)); then
    users="$ST_AUTO_USERS"
  fi
  [[ $users =~ ^[0-9]+$ ]] || users=0
  ST_EXPECTED_USERS="$users"
  ((users > 0)) || return 0

  ct=$((users * 24 * 3 / 2))
  ((ct < 65536)) && ct=65536
  ((ct > 4194304)) && ct=4194304
  ST_CONNTRACK="$ct"
  return 0
}

# capacity_warning — prints an honest RAM-math warning when the estimated
# need (conntrack + ~0.5 MB proxy userspace per online user) crowds >75% of
# RAM; prints nothing when the sizing fits.
capacity_warning() {
  ((ST_EXPECTED_USERS > 0)) || return 0
  local ram_mb ct_mb proxy_mb need_mb
  ram_mb="$(mem_total_mb)"
  ct_mb=$((ST_CONNTRACK * 300 / 1048576))
  proxy_mb=$((ST_EXPECTED_USERS / 2))
  need_mb=$((ct_mb + proxy_mb))
  if ((ram_mb > 0 && need_mb > ram_mb * 3 / 4)); then
    printf 'estimated need ~%d MB (conntrack %d + proxy ~%d) vs %d MB RAM — OOM risk at peak. Split users across nodes or add RAM (rule of thumb: ~8 GB per 10k users).' \
      "$need_mb" "$ct_mb" "$proxy_mb" "$ram_mb"
  fi
  return 0
}
