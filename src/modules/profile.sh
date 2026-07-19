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
    $detected == *'xray'* || $detected == *'x-ui'* ]]; then
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
  return 0
}

tier_conntrack_ram_mb() {
  # ~300 bytes per conntrack entry, worst case (table full).
  printf '%d' $((ST_CONNTRACK * 300 / 1048576))
}
