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

# _ss_listen_ports SS_OUTPUT — ports of listeners reachable from OFF the box,
# one per line.
#
# Loopback-bound listeners are deliberately excluded, and that single rule is
# what separates a configured service port from a random internal one. Xray
# keeps internal plumbing on 127.0.0.1 with a port the kernel picks afresh on
# every start (127.0.0.1:39036 one run, 127.0.0.1:57035 after a restart), while
# every port that actually serves clients is bound to a wildcard or a real
# address and comes back unchanged. Reserving a random loopback port is
# meaningless — nothing outside can reach it and the app asked for "any free
# port" in the first place — and it made the generated value differ on every run.
_ss_listen_ports() {
  awk 'NR > 1 {
        addr = $4
        port = addr
        sub(/.*:/, "", port)
        sub(/:[^:]*$/, "", addr) # strip ":port", leaving the local address
        gsub(/[][]/, "", addr)   # drop IPv6 brackets
        if (addr ~ /^127\./ || addr == "::1" || addr ~ /^::ffff:127\./ || addr ~ /%lo$/) next
        if (port ~ /^[0-9]+$/) print port
      }' <<<"$1" | sort -un
}

# _ss_ports_in_range SS_OUTPUT — as above, restricted to the ephemeral range.
# The "+ 0" is not decoration: sub() turns the field into a string, and a
# string comparison would rank "22" above "10240" and let it through.
_ss_ports_in_range() {
  _ss_listen_ports "$1" | awk '$1 + 0 >= 10240 && $1 + 0 <= 65535'
}

# The tool runs with a hardened global IFS ($'\n\t' — deliberately no space).
# That makes two everyday bash idioms silently WRONG on space-separated data:
#   for x in ${list//,/ }  -> no split at all; the whole list arrives as one word
#   "${array[*]}"          -> joined with a NEWLINE instead of a space
# Both failed silently in real features (a port list became one bogus "port";
# a generated systemd ExecStart line was split across nine lines). These two
# helpers are the supported way to do each, and must be used instead.

# ports_split LIST — one token per line from a "80,443 1000-1002" list.
ports_split() {
  local -a items=()
  [[ -n ${1:-} ]] || return 0
  IFS=$', \t' read -ra items <<<"$1"
  ((${#items[@]} > 0)) && printf '%s\n' "${items[@]}"
  return 0
}

# join_sp WORD... — the words joined by single spaces (for argv-shaped strings).
join_sp() {
  local IFS=' '
  printf '%s' "$*"
}

# _ports_subtract SET — read candidate ports (one per line) from stdin and
# print those NOT in SET (a newline-separated list passed as the argument).
# This replaces `comm`, which needs its input in *byte* order while our ports
# are in *numeric* order ("8443" sorts before "51820" numerically but after it
# bytewise), so comm silently returned wrong results. An empty SET is handled
# correctly (everything passes through).
_ports_subtract() {
  awk -v set="$1" '
    BEGIN { n = split(set, a, "\n"); for (i = 1; i <= n; i++) if (a[i] != "") m[a[i]] = 1 }
    !($1 in m)'
}

# wg_listen_ports — the ports WireGuard is configured to listen on, asked of
# wg itself (one per line). Authoritative, unlike inspecting sockets.
wg_listen_ports() {
  has_cmd wg || return 0
  local out
  out="$(wg show all listen-port 2>/dev/null)" || return 0
  awk 'NF {print $NF}' <<<"$out" | grep -E '^[0-9]+$' | sort -un
}

# listening_service_ports — ports of REAL services inside the ephemeral range
# (10240-65535), one per line. Only unambiguous evidence counts:
#
#   - TCP sockets in LISTEN state — a listener IS a service, by definition;
#   - WireGuard's configured listen port, read from `wg` itself.
#
# Generic UDP listeners are deliberately NOT auto-detected. A userspace proxy
# (Xray/sing-box) opens one UNCONN socket per UDP session, and a QUIC/Hysteria
# session outlives any sampling window we could afford — so by socket inspection
# alone those ephemeral ports are indistinguishable from a service. Reserving
# them spent the list on ports that belong to nothing AND, because the set is
# rebuilt from the live system on every render, made the rendered value differ
# on every single run. Sampling twice and capping the count only reduced how
# often that happened; it could not fix it, because the input is genuinely
# ambiguous. A UDP-only service on a fixed port is pinned explicitly with the
# `reserved_ports` config key instead — deterministic by construction.
listening_service_ports() {
  local tcp wg_ports
  {
    if has_cmd ss; then
      tcp="$(ss -tln 2>/dev/null)" || tcp=''
      _ss_ports_in_range "$tcp"
    fi
    wg_ports="$(wg_listen_ports)" || wg_ports=''
    # Only ports inside the ephemeral range can ever be stolen by an outgoing
    # connection; reserving anything outside it would be noise.
    if [[ -n $wg_ports ]]; then
      awk '$1 + 0 >= 10240 && $1 + 0 <= 65535' <<<"$wg_ports"
    fi
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
