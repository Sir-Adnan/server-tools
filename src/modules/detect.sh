# shellcheck shell=bash
# ============================================================================
# modules/detect.sh — detect which VPN workload runs on this server.
#
# A server is usually EITHER a panel (Marzban/Pasarguard dashboard, no VPN
# traffic) OR a node (marzban-node / pg-node — the Xray core carrying user
# traffic) OR a WireGuard host. Detection picks the workload layer that the
# optimizer will suggest; the base layer always covers the whole server.
# ============================================================================

ST_DETECTED=()

_detect_add() { # _detect_add TAG — append once.
  local tag="$1" existing
  for existing in "${ST_DETECTED[@]-}"; do
    [[ $existing == "$tag" ]] && return 0
  done
  ST_DETECTED+=("$tag")
}

_detect_match() { # _detect_match HAYSTACK REGEX
  [[ -n $1 ]] && grep -qiE "$2" <<<"$1"
}

detect_stack() {
  ST_DETECTED=()

  # Containers from docker AND podman — some hosts run nodes under podman.
  local containers=''
  if has_cmd docker; then
    containers="$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null)" || containers=''
  fi
  if has_cmd podman; then
    local podman_ps
    podman_ps="$(podman ps --format '{{.Names}} {{.Image}}' 2>/dev/null)" || podman_ps=''
    containers="${containers}${containers:+$'\n'}${podman_ps}"
  fi

  # Nodes first — "marzban" alone must not swallow "marzban-node".
  _detect_match "$containers" 'marzban[-_]node' && _detect_add 'marzban-node'
  _detect_match "$containers" 'pg[-_]node|pasarguard' && _detect_add 'pg-node'
  if _detect_match "$containers" 'marzban|marzneshin' &&
    ! _detect_match "$containers" 'marzban[-_]node'; then
    _detect_add 'marzban-panel'
  fi
  _detect_match "$containers" 'hiddify' && _detect_add 'hiddify'
  _detect_match "$containers" '3x-ui|x-ui' && _detect_add 'x-ui'
  _detect_match "$containers" 'sing-?box' && _detect_add 'sing-box'
  _detect_match "$containers" 'hysteria' && _detect_add 'hysteria'
  _detect_match "$containers" 'openvpn' && _detect_add 'openvpn'
  _detect_match "$containers" 'wgdashboard|wg-easy' && _detect_add 'wg-dashboard'

  if has_cmd systemctl; then
    systemctl is-active --quiet x-ui 2>/dev/null && _detect_add 'x-ui'
    systemctl is-active --quiet xray 2>/dev/null && _detect_add 'xray'
    systemctl is-active --quiet sing-box 2>/dev/null && _detect_add 'sing-box'
    systemctl is-active --quiet hysteria-server 2>/dev/null && _detect_add 'hysteria'
    systemctl is-active --quiet openvpn 2>/dev/null && _detect_add 'openvpn'
  fi

  if has_cmd wg && [[ -n "$(wg show interfaces 2>/dev/null)" ]]; then
    _detect_add 'wireguard'
  fi

  log_debug "detected workloads: ${ST_DETECTED[*]-none}"
  return 0
}

detect_summary() {
  if ((${#ST_DETECTED[@]} == 0)); then
    printf 'none (general server)'
  else
    local IFS=', '
    printf '%s' "${ST_DETECTED[*]}"
  fi
}
