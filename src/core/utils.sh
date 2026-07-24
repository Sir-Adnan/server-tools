# shellcheck shell=bash
# ============================================================================
# core/utils.sh — small dependency-free helpers: command/root checks,
# OS facts (from /proc and /etc/os-release), network facts, cached public IP.
# ============================================================================

has_cmd() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  ((EUID == 0)) || die "This tool must be run as root (try: sudo -i)."
}

os_pretty_name() {
  local name=''
  if [[ -r /etc/os-release ]]; then
    name="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}")" || name=''
  fi
  printf '%s' "${name:-unknown}"
}

kernel_release() { uname -r 2>/dev/null || printf 'unknown'; }

kernel_base() {
  local rel
  rel="$(kernel_release)"
  printf '%s' "${rel%%-*}"
}

detect_virt() {
  local virt=''
  if has_cmd systemd-detect-virt; then
    # Exit code 1 simply means "not virtualised"; the answer is on stdout.
    virt="$(systemd-detect-virt 2>/dev/null)" || true
  fi
  printf '%s' "${virt:-unknown}"
}

mem_total_mb() {
  awk '/^MemTotal:/ {print int($2 / 1024); exit}' /proc/meminfo 2>/dev/null || printf '0'
}

cpu_cores() {
  if has_cmd nproc; then
    nproc
  else
    grep -c '^processor' /proc/cpuinfo 2>/dev/null || printf '1'
  fi
}

cpu_model() {
  local model
  model="$(awk -F': *' '/^(model name|Model)/ {print $2; exit}' /proc/cpuinfo 2>/dev/null)" || model=''
  printf '%s' "${model:-unknown}"
}

uptime_pretty() {
  local secs
  secs="$(cut -d. -f1 /proc/uptime 2>/dev/null)" || secs=''
  [[ $secs =~ ^[0-9]+$ ]] || {
    printf 'unknown'
    return 0
  }
  printf '%dd %dh %dm' $((secs / 86400)) $((secs % 86400 / 3600)) $((secs % 3600 / 60))
}

load_avg() {
  cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || printf 'unknown'
}

# ver_ge A B — true when dotted version A >= B.
ver_ge() {
  [[ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]
}

is_valid_ipv4() {
  local ip="$1" octet
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.'
  for octet in $ip; do
    ((octet <= 255)) || return 1
  done
  return 0
}

# is_valid_ipv6 — hex groups separated by colons, at most one "::"
# compression, 2..8 groups. Rejects the "anything with a colon" trap.
is_valid_ipv6() {
  local ip="$1"
  [[ $ip == *:* && $ip != *:::* ]] || return 1
  # At most one "::" compression marker.
  local rest="${ip//::/}"
  ((${#ip} - ${#rest} <= 2)) || return 1
  [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]] || return 1
  # Without compression every one of the 8 groups must be present.
  if [[ $ip != *::* ]]; then
    local IFS=':' groups
    read -ra groups <<<"$ip"
    ((${#groups[@]} == 8)) || return 1
  fi
  return 0
}

# qdisc_supported NAME — real probe: attach the qdisc to loopback and remove
# it again (loopback traffic is unaffected, the default is restored at once).
# Dry-run must not touch anything, so it falls back to module inspection.
qdisc_supported() {
  local name="$1"
  has_cmd tc || return 1
  if ((ST_DRY_RUN)); then
    # fq/fq_codel are built into every supported kernel; others ship as
    # modules, which modinfo can check without loading them.
    case "$name" in
      fq | fq_codel) return 0 ;;
      *) has_cmd modinfo && modinfo -n "sch_${name}" >/dev/null 2>&1 ;;
    esac
    return
  fi
  tc qdisc add dev lo root "$name" 2>/dev/null || return 1
  tc qdisc del dev lo root 2>/dev/null ||
    log_warn "Could not detach the probe qdisc from loopback."
  return 0
}

# _ss_ports_in_range SS_OUTPUT — local ports inside the ephemeral range.
# The "+ 0" is not decoration: sub() turns the field into a string, and a
# string comparison would rank "22" above "10240" and let it through.
_ss_ports_in_range() {
  awk 'NR > 1 {
        p = $4
        sub(/.*:/, "", p)
        if (p ~ /^[0-9]+$/ && p + 0 >= 10240 && p + 0 <= 65535) print p
      }' <<<"$1" | sort -un
}

# _ports_intersect SET  / _ports_subtract SET — read candidate ports (one per
# line) from stdin; print those that ARE (intersect) / are NOT (subtract) in
# SET, a newline-separated list passed as the argument. These replace `comm`,
# which needs its inputs in *byte* order while our ports are in *numeric* order
# ("8443" sorts before "51820" numerically but after it bytewise) — feeding
# comm numeric-sorted input yields wrong results. An empty SET is handled
# correctly (intersect → nothing, subtract → everything).
_ports_intersect() {
  awk -v set="$1" '
    BEGIN { n = split(set, a, "\n"); for (i = 1; i <= n; i++) if (a[i] != "") m[a[i]] = 1 }
    ($1 in m)'
}

_ports_subtract() {
  awk -v set="$1" '
    BEGIN { n = split(set, a, "\n"); for (i = 1; i <= n; i++) if (a[i] != "") m[a[i]] = 1 }
    !($1 in m)'
}

# listening_service_ports — ports of REAL services inside the ephemeral
# range (10240-65535), one per line.
#
# TCP listeners are stable by definition. UDP is sampled twice a second
# apart and intersected: a proxy's short-lived outbound sockets also appear
# as UNCONN, and reserving those would fill the list with noise that changes
# every second — pushing genuine ports (a node API port, WireGuard) out.
listening_service_ports() {
  has_cmd ss || return 0
  local tcp udp1 udp2
  tcp="$(ss -tln 2>/dev/null)" || tcp=''
  udp1="$(ss -uln 2>/dev/null)" || udp1=''
  sleep 1
  udp2="$(ss -uln 2>/dev/null)" || udp2=''
  {
    _ss_ports_in_range "$tcp"
    # UDP ports present in BOTH samples — stable services, not a proxy's
    # transient outbound sockets that show up for only one of the two probes.
    _ss_ports_in_range "$udp2" | _ports_intersect "$(_ss_ports_in_range "$udp1")"
  } | sort -un
}

# net_dns_capable_links — links worth carrying a DNS override: everything
# that is up, minus loopback and container/virtual bridges.
net_dns_capable_links() {
  has_cmd ip || return 0
  ip -o link show up 2>/dev/null |
    awk -F': ' '{print $2}' |
    sed 's/@.*//' |
    grep -vE '^(lo|docker[0-9]*|br-|veth|cni|virbr|kube)' || true
}

# net_default_iface / net_default_gw — read from the default route.
# The route is captured first, then parsed from a here-string: piping into an
# awk that exits on the first match would SIGPIPE `ip`, and under pipefail the
# function would return 141 even on success — which the callers' `|| x=''`
# guards would then mistake for failure and blank a perfectly good value.
net_default_iface() {
  has_cmd ip || return 0
  local route
  route="$(ip route show default 2>/dev/null)" || return 0
  awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}' <<<"$route"
}

net_default_gw() {
  has_cmd ip || return 0
  local route
  route="$(ip route show default 2>/dev/null)" || return 0
  awk '{for (i = 1; i < NF; i++) if ($i == "via") {print $(i + 1); exit}}' <<<"$route"
}

# pkg_install PACKAGE — caller must already have the user's consent
# (CLAUDE.md rule 1: nothing is installed silently). Output goes to the log.
ST_PKG_INDEX_UPDATED=0

pkg_install() {
  local pkg="$1"
  if has_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    if ((ST_PKG_INDEX_UPDATED == 0)); then
      apt-get update -qq >>"$ST_LOG_FILE" 2>&1 ||
        log_warn "apt index update failed — trying the install anyway."
      ST_PKG_INDEX_UPDATED=1
    fi
    apt-get install -y -qq "$pkg" >>"$ST_LOG_FILE" 2>&1
  elif has_cmd dnf; then
    dnf install -y "$pkg" >>"$ST_LOG_FILE" 2>&1
  elif has_cmd yum; then
    yum install -y "$pkg" >>"$ST_LOG_FILE" 2>&1
  elif has_cmd pacman; then
    pacman -Sy --noconfirm "$pkg" >>"$ST_LOG_FILE" 2>&1
  else
    log_error "No supported package manager found to install ${pkg}."
    return 1
  fi
}

# sysctl_get KEY — current value or "?" when unavailable.
sysctl_get() {
  local value
  if has_cmd sysctl; then
    value="$(sysctl -n "$1" 2>/dev/null)" || value=''
  fi
  printf '%s' "${value:-?}"
}

# --- Public IP (fetched once per process, then cached — the menu redraws
# --- must never block on network calls).
ST_CACHE_IP4=''
ST_CACHE_IP6=''

_net_fetch() { # _net_fetch 4|6 URL
  has_cmd curl || return 1
  # Short timeout: this runs during the first dashboard render and must
  # never make the menu feel stuck on servers with broken connectivity.
  curl "-$1" -fsS --max-time 2 "$2" 2>/dev/null | tr -d '[:space:]'
}

net_public_ip4() {
  if [[ -z $ST_CACHE_IP4 ]]; then
    local ip='' url
    for url in 'https://api.ipify.org' 'https://ifconfig.me/ip'; do
      ip="$(_net_fetch 4 "$url")" || ip=''
      is_valid_ipv4 "$ip" && break
      ip=''
    done
    if [[ -z $ip ]] && has_cmd ip; then
      ip="$(ip -4 addr show scope global 2>/dev/null |
        awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')" || ip=''
    fi
    ST_CACHE_IP4="${ip:-N/A}"
  fi
  printf '%s' "$ST_CACHE_IP4"
}

net_public_ip6() {
  if [[ -z $ST_CACHE_IP6 ]]; then
    local ip='' url
    for url in 'https://api64.ipify.org' 'https://ifconfig.me/ip'; do
      ip="$(_net_fetch 6 "$url")" || ip=''
      [[ $ip == *:* ]] && break
      ip=''
    done
    if [[ -z $ip ]] && has_cmd ip; then
      ip="$(ip -6 addr show scope global 2>/dev/null |
        awk '/inet6 / {sub(/\/.*/, "", $2); print $2; exit}')" || ip=''
    fi
    ST_CACHE_IP6="${ip:-N/A}"
  fi
  printf '%s' "$ST_CACHE_IP6"
}
