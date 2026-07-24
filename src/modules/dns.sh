# shellcheck shell=bash
# ============================================================================
# modules/dns.sh — DNS provider selection and application that actually sticks.
#
# Selection and application are deliberately decoupled: "Keep current DNS"
# really keeps it. Applying is harder than writing one file:
#
#   * systemd list settings ACCUMULATE across drop-ins — without an empty
#     reset assignment the previously configured servers stay ahead of ours;
#   * per-link DNS (netplan / DHCP) takes PRECEDENCE over the global resolved
#     configuration, so it must be overridden now and persisted for reboots;
#   * /etc/resolv.conf may bypass systemd-resolved entirely.
#
# Every path therefore ends in a verification of what will really answer
# queries — a written config file alone is never reported as success.
# ============================================================================

readonly ST_RESOLVED_DROPIN='/etc/systemd/resolved.conf.d/99-server-tools.conf'
readonly ST_DNS_UNIT='/etc/systemd/system/server-tools-dns.service'

ST_DNS1=''
ST_DNS2=''

# Format: name|primary|secondary
# Iran-hosted anti-sanction resolvers with PUBLIC IPs only — services like
# 403.online announce private-range addresses that only route inside Iran.
readonly -a ST_DNS_PROVIDERS=(
  'Cloudflare|1.1.1.1|1.0.0.1'
  'Google|8.8.8.8|8.8.4.4'
  'Quad9|9.9.9.9|149.112.112.112'
  'OpenDNS|208.67.222.222|208.67.220.220'
  'Shecan (for Iran-hosted servers)|178.22.122.100|185.51.200.2'
  'Electro (for Iran-hosted servers)|78.157.42.100|78.157.42.101'
  'Begzar (for Iran-hosted servers)|185.55.226.26|185.55.225.25'
)

# is_valid_ip — a real address in either family (see core/utils.sh).
is_valid_ip() {
  is_valid_ipv4 "$1" || is_valid_ipv6 "$1"
}

# --- Inspection -----------------------------------------------------------

# dns_stack — which resolver actually owns /etc/resolv.conf on this host.
dns_stack() {
  if has_cmd systemctl && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    printf 'resolved'
  elif has_cmd resolvconf && [[ -d /etc/resolvconf/resolv.conf.d ]]; then
    printf 'resolvconf'
  else
    printf 'plain'
  fi
}

# _dns_link_servers IFACE — servers configured on that link ("" when none).
_dns_link_servers() {
  has_cmd resolvectl || return 0
  resolvectl dns "$1" 2>/dev/null |
    sed -e 's/^Link [0-9]* ([^)]*)://' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# _resolvectl_status — cached copy of `resolvectl status`.
# Parsing it through a pipe is a trap: an awk that exits early kills the
# producer with SIGPIPE, pipefail turns that into a failed command, and the
# caller's error branch then discards the value that was read correctly.
# Capture first, parse from a here-string.
ST_RESOLVECTL_STATUS=''

_resolvectl_status() {
  has_cmd resolvectl || return 1
  if [[ -z $ST_RESOLVECTL_STATUS ]]; then
    ST_RESOLVECTL_STATUS="$(resolvectl status 2>/dev/null)" || ST_RESOLVECTL_STATUS=''
  fi
  [[ -n $ST_RESOLVECTL_STATUS ]] || return 1
  printf '%s' "$ST_RESOLVECTL_STATUS"
}

# _dns_global_servers — servers in the resolved global scope ("" when none).
_dns_global_servers() {
  local status
  status="$(_resolvectl_status)" || return 0
  awk '/^ *DNS Servers:/ {sub(/^ *DNS Servers: */, ""); print; exit}' <<<"$status"
}

# dns_effective_servers — what will really answer queries: link scope first
# (it wins over global), then global, then plain resolv.conf.
dns_effective_servers() {
  local iface link
  if has_cmd resolvectl; then
    iface="$(net_default_iface)" || iface=''
    if [[ -n $iface ]]; then
      link="$(_dns_link_servers "$iface")"
      if [[ -n $link ]]; then
        printf '%s' "$link"
        return 0
      fi
    fi
    link="$(_dns_global_servers)"
    if [[ -n $link ]]; then
      printf '%s' "$link"
      return 0
    fi
  fi
  awk '/^[[:space:]]*nameserver/ {printf "%s ", $2}' /etc/resolv.conf 2>/dev/null |
    sed 's/[[:space:]]*$//'
}

# dns_over_tls_state — current DNSOverTLS mode, "n/a" without resolved.
dns_over_tls_state() {
  local status mode=''
  if status="$(_resolvectl_status)"; then
    mode="$(sed -n 's/.*DNSOverTLS=\([^ ]*\).*/\1/p' <<<"$status" | head -n1)"
  fi
  printf '%s' "${mode:-n/a}"
}

# --- Latency test ---------------------------------------------------------

# _dns_probe_ms IP — a real DNS query time when dig exists (resolvers often
# deprioritize ICMP, so ping understates real performance); ping fallback.
_dns_probe_ms() {
  local out=''
  if has_cmd dig; then
    out="$(dig +tries=1 +time=2 "@$1" google.com A 2>/dev/null)" || return 0
    awk '/Query time:/ {print $4; exit}' <<<"$out"
  elif has_cmd ping; then
    out="$(ping -c 1 -W 1 "$1" 2>/dev/null)" || return 0
    awk -F'time=' '/time=/ {split($2, a, " "); print a[1]; exit}' <<<"$out"
  fi
}

dns_latency_test() {
  if ! has_cmd dig && ! has_cmd ping; then
    printf 'Neither dig nor ping is available on this system.\n'
    return 0
  fi
  local entry name ip1 ip2 ms method='ping'
  has_cmd dig && method='real DNS query (dig)'
  printf '%sLatency per provider — measured via %s:%s\n' "$C_MUTED" "$method" "$C_RESET"
  for entry in "${ST_DNS_PROVIDERS[@]}"; do
    IFS='|' read -r name ip1 ip2 <<<"$entry"
    ms="$(_dns_probe_ms "$ip1")" || ms=''
    if [[ -n $ms ]]; then
      printf '  %-34s %s ms\n' "$name" "$ms"
    else
      printf '  %-34s timeout\n' "$name"
    fi
  done
}

# --- Selection ------------------------------------------------------------

# dns_select_menu — sets ST_DNS1/ST_DNS2 and returns 0 when the user picked
# a provider to apply; returns 1 for "keep current" (caller MUST skip apply).
dns_select_menu() {
  local choice entry name ip1 ip2 i
  while true; do
    printf '\n%s[DNS provider]%s  current: %s\n' \
      "$C_TITLE" "$C_RESET" "$(dns_effective_servers)"
    i=1
    for entry in "${ST_DNS_PROVIDERS[@]}"; do
      IFS='|' read -r name ip1 ip2 <<<"$entry"
      ui_menu_item "$i" "$name" "${ip1} / ${ip2}"
      i=$((i + 1))
    done
    ui_menu_item 8 "Custom" "enter your own (IPv4 or IPv6)"
    ui_menu_item t "Latency test" "measure every provider first"
    ui_menu_item 0 "Keep current DNS" "no DNS change"
    read -rp "Select [0]: " choice || return 1
    case "${choice:-0}" in
      [1-7])
        IFS='|' read -r name ST_DNS1 ST_DNS2 <<<"${ST_DNS_PROVIDERS[$((choice - 1))]}"
        return 0
        ;;
      8)
        read -rp "Primary DNS: " ST_DNS1 || return 1
        read -rp "Secondary DNS: " ST_DNS2 || return 1
        if is_valid_ip "$ST_DNS1" && is_valid_ip "$ST_DNS2"; then
          return 0
        fi
        printf '%sInvalid address — DNS left unchanged.%s\n' "$C_ERR" "$C_RESET"
        return 1
        ;;
      t | T) dns_latency_test ;;
      0) return 1 ;;
      *) printf '%sInvalid choice.%s\n' "$C_ERR" "$C_RESET" ;;
    esac
  done
}

# dns_resolve_cli VALUE — non-interactive parsing for --dns: a provider name
# or "primary,secondary" addresses.
dns_resolve_cli() {
  local value="$1"
  case "${value,,}" in
    cloudflare)
      ST_DNS1='1.1.1.1'
      ST_DNS2='1.0.0.1'
      ;;
    google)
      ST_DNS1='8.8.8.8'
      ST_DNS2='8.8.4.4'
      ;;
    quad9)
      ST_DNS1='9.9.9.9'
      ST_DNS2='149.112.112.112'
      ;;
    opendns)
      ST_DNS1='208.67.222.222'
      ST_DNS2='208.67.220.220'
      ;;
    shecan)
      ST_DNS1='178.22.122.100'
      ST_DNS2='185.51.200.2'
      ;;
    electro)
      ST_DNS1='78.157.42.100'
      ST_DNS2='78.157.42.101'
      ;;
    begzar)
      ST_DNS1='185.55.226.26'
      ST_DNS2='185.55.225.25'
      ;;
    *,*)
      ST_DNS1="${value%%,*}"
      ST_DNS2="${value#*,}"
      is_valid_ip "$ST_DNS1" && is_valid_ip "$ST_DNS2"
      ;;
    *) return 1 ;;
  esac
}

# --- Application ----------------------------------------------------------

# _dns_persist_link IFACE — a runtime `resolvectl dns` override is lost on
# reboot and on DHCP renewal. Preferred fix: clear the link's own DNS in a
# systemd-networkd drop-in so the global configuration governs it (addressing
# is untouched). Fallback for NetworkManager/unmanaged links: a oneshot unit
# that re-applies the override at boot and exits.
_dns_persist_link() {
  local iface="$1" netfile='' dropin
  if has_cmd networkctl; then
    local status
    status="$(SYSTEMD_COLORS=0 networkctl status --no-pager "$iface" 2>/dev/null)" || status=''
    [[ -n $status ]] && netfile="$(awk '/Network File:/ {print $NF; exit}' <<<"$status")"
  fi

  if [[ $netfile == /*.network ]]; then
    dropin="/etc/systemd/network/$(basename "$netfile").d/99-server-tools.conf"
    st_track_file "$dropin"
    mkdir -p "$(dirname "$dropin")"
    cat >"$dropin" <<EOF
# Generated by ${ST_NAME} v${ST_VERSION}
# Pin the chosen DNS on this link and stop consuming the DHCP-provided servers,
# so per-link DNS (which OUTRANKS the global resolved config) points where we
# want. Addressing and routing are deliberately untouched.
[Network]
DNS=${ST_DNS1}
DNS=${ST_DNS2}
[DHCPv4]
UseDNS=false
[DHCPv6]
UseDNS=false
EOF
    # Apply the drop-in now. This is a config-only reload (no re-addressing, so
    # no connectivity blip); networkd then re-pushes the corrected DNS to
    # resolved and stops overwriting it with the DHCP servers.
    if has_cmd networkctl; then
      networkctl reload 2>>"$ST_LOG_FILE" ||
        log_warn "networkctl reload failed — the link DNS drop-in applies on reboot."
    fi
    log_info "Link DNS persistence: networkd drop-in ${dropin} (DHCP DNS disabled)."
    return 0
  fi

  if [[ ! -d /etc/systemd/system ]] || ! has_cmd systemctl || ! has_cmd resolvectl; then
    log_warn "No way to persist the link DNS override — it is active now but resets on reboot."
    return 3
  fi

  # The interface is resolved at boot instead of being baked in: cloud images
  # rename NICs, and network-online.target must be pulled in with Wants= or
  # the After= alone never activates it.
  st_track_file "$ST_DNS_UNIT"
  cat >"$ST_DNS_UNIT" <<EOF
# Generated by ${ST_NAME} v${ST_VERSION}
[Unit]
Description=ServerTools per-link DNS override (oneshot, exits after boot)
After=systemd-resolved.service network-online.target
Wants=systemd-resolved.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'for i in \$(ip -o link show up | awk -F": " "{print \\\$2}" | sed "s/@.*//" | grep -vE "^(lo|docker|br-|veth|cni|virbr)"); do $(command -v resolvectl) dns "\$i" ${ST_DNS1} ${ST_DNS2} || true; done'

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>>"$ST_LOG_FILE" || log_warn "daemon-reload failed."
  if systemctl enable server-tools-dns.service >/dev/null 2>>"$ST_LOG_FILE"; then
    manifest_add unit server-tools-dns.service
    log_info "Link DNS persistence: oneshot unit server-tools-dns.service."
    return 0
  fi
  log_warn "Could not enable the DNS persistence unit — override resets on reboot."
  return 3
}

# _dns_override_link — per-link DNS OUTRANKS the global config, so every up
# link that carries its own servers must be re-pointed. This runs the PERSISTENT
# fix (networkd drop-in / oneshot unit) and is called BEFORE the resolved
# restart, so resolved reloads the corrected link DNS instead of the DHCP
# servers. The immediate runtime override is a separate step after the restart
# (see _dns_reassert_links) — doing it before would just be clobbered by
# networkd's post-restart re-push.
_dns_override_link() {
  has_cmd resolvectl || return 0
  local iface current rc=0 handled=0

  while IFS= read -r iface; do
    [[ -n $iface ]] || continue
    current="$(_dns_link_servers "$iface")"
    # No link-level servers: the global scope already governs this link.
    [[ -n $current ]] || continue
    [[ $current == "${ST_DNS1} ${ST_DNS2}" ]] && continue

    log_info "Link ${iface} carries its own DNS (${current}) — pinning ours."
    _dns_persist_link "$iface" || rc=$?
    handled=1
  done < <(net_dns_capable_links)

  ((handled)) && log_info "Per-link DNS pinned."
  return "$rc"
}

# _dns_reassert_links — the immediate runtime override, applied AFTER resolved
# restarts. With DHCP DNS now disabled per link (drop-in above), networkd no
# longer overwrites this, so it holds for the session while the drop-in covers
# reboots.
_dns_reassert_links() {
  has_cmd resolvectl || return 0
  local iface
  while IFS= read -r iface; do
    [[ -n $iface ]] || continue
    resolvectl dns "$iface" "$ST_DNS1" "$ST_DNS2" 2>>"$ST_LOG_FILE" ||
      log_warn "Could not set runtime DNS on ${iface}."
  done < <(net_dns_capable_links)
}

# _dns_resolv_conf_visible — do applications reading /etc/resolv.conf end up
# at our servers? True via the resolved stub, or by listing them directly.
_dns_resolv_conf_visible() {
  grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.5[34]' /etc/resolv.conf 2>/dev/null ||
    grep -qF "$ST_DNS1" /etc/resolv.conf 2>/dev/null
}

_dns_write_resolv_conf() {
  st_track_file /etc/resolv.conf
  if has_cmd chattr; then
    # Some providers lock resolv.conf with +i; unlocking may legitimately
    # fail when the attribute is not set — the write below is the real test.
    chattr -i /etc/resolv.conf 2>/dev/null || true
  fi
  rm -f /etc/resolv.conf
  cat >/etc/resolv.conf <<EOF
# Generated by ${ST_NAME} v${ST_VERSION}
nameserver ${ST_DNS1}
nameserver ${ST_DNS2}
# Fast failover: 2s per try, alternate between the two servers.
options timeout:2 attempts:2 rotate
EOF
}

_dns_apply_resolved() {
  local rc=0
  st_track_file "$ST_RESOLVED_DROPIN"
  mkdir -p "$(dirname "$ST_RESOLVED_DROPIN")"
  cat >"$ST_RESOLVED_DROPIN" <<EOF
# Generated by ${ST_NAME} v${ST_VERSION}
[Resolve]
# The empty assignments RESET the lists inherited from resolved.conf and
# earlier drop-ins — systemd appends to list settings, so without them the
# previously configured servers would stay ahead of ours.
DNS=
DNS=${ST_DNS1} ${ST_DNS2}
# Left empty on purpose: distributions ship Google/Cloudflare fallbacks that
# would silently answer queries the chosen resolver cannot. resolved only
# uses FallbackDNS when no DNS= is known, so a value here would be dead code.
FallbackDNS=
# Encrypt DNS when the resolver supports it, fall back to plain otherwise.
DNSOverTLS=opportunistic
EOF

  # Pin the per-link DNS and disable DHCP DNS BEFORE restarting resolved, so
  # the restart's reload from networkd already carries our servers instead of
  # the ISP's — otherwise networkd's post-restart re-push shadows the global
  # config (the exact failure seen on netplan+DHCP hosts).
  _dns_override_link || rc=$?

  if ! systemctl restart systemd-resolved 2>>"$ST_LOG_FILE"; then
    log_warn "systemd-resolved restart failed — drop-in written but not active yet."
    return 3
  fi

  # Immediate runtime override, now safe from networkd's re-push (DHCP DNS off).
  _dns_reassert_links

  if ! _dns_resolv_conf_visible; then
    log_info "/etc/resolv.conf bypasses systemd-resolved — writing the servers into it directly as well."
    _dns_write_resolv_conf
  fi
  return "$rc"
}

_dns_apply_resolvconf() {
  local head='/etc/resolvconf/resolv.conf.d/head'
  st_track_file "$head"
  cat >"$head" <<EOF
# Generated by ${ST_NAME} v${ST_VERSION}
nameserver ${ST_DNS1}
nameserver ${ST_DNS2}
options timeout:2 attempts:2 rotate
EOF
  if resolvconf -u 2>>"$ST_LOG_FILE"; then
    return 0
  fi
  log_warn "resolvconf -u failed — writing /etc/resolv.conf directly instead."
  _dns_write_resolv_conf
  return 3
}

_dns_apply_plain() {
  _dns_write_resolv_conf
  if has_cmd systemctl && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    log_warn "NetworkManager is active and may rewrite /etc/resolv.conf on the next connection change."
  fi
  return 0
}

# dns_verify — do the servers we configured actually answer queries?
# Returns 0 on match, 3 on drift, 2 when nothing was ever configured.
dns_verify() {
  local want effective
  want="$(config_get dns_primary '')"
  [[ -n $want ]] || return 2
  effective="$(dns_effective_servers)"
  [[ $effective == *"$want"* ]] && return 0
  return 3
}

dns_apply() {
  [[ -n $ST_DNS1 && -n $ST_DNS2 ]] || return 2 # nothing selected — skip

  local stack rc=0
  stack="$(dns_stack)"
  case "$stack" in
    resolved) _dns_apply_resolved || rc=$? ;;
    resolvconf) _dns_apply_resolvconf || rc=$? ;;
    *) _dns_apply_plain || rc=$? ;;
  esac
  ((rc == 1)) && return 1 # hard failure — do not claim anything was applied

  # Config files mean nothing on their own: verify what answers queries now.
  local effective
  effective="$(dns_effective_servers)"
  if [[ $effective != *"$ST_DNS1"* ]]; then
    log_warn "DNS verification failed: '${effective:-none}' is in effect, expected ${ST_DNS1} (stack: ${stack})."
    rc=3
  fi

  config_set dns_primary "$ST_DNS1"
  config_set dns_secondary "$ST_DNS2"
  log_info "DNS applied via ${stack}: ${ST_DNS1} / ${ST_DNS2} (in effect: ${effective:-unknown})"
  return "$rc"
}
