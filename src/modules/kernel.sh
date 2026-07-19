# shellcheck shell=bash
# ============================================================================
# modules/kernel.sh — ADVANCED, opt-in only: XanMod kernel for BBRv3.
#
# BBRv3 is not in mainline kernels; XanMod ships it. Replacing the kernel is
# the riskiest thing this project can do, so this flow is apt-only, warns
# twice, and never runs inside Quick/Auto optimize. After a reboot the
# existing sysctl config picks BBRv3 up automatically (it registers as
# "bbr"), so nothing else needs to change.
# ============================================================================

readonly ST_XANMOD_KEYRING='/usr/share/keyrings/xanmod-archive-keyring.gpg'
readonly ST_XANMOD_LIST='/etc/apt/sources.list.d/xanmod-release.list'

# _cpu_psabi_level — x86-64 microarchitecture level (1-4) for the right
# XanMod package variant.
_cpu_psabi_level() {
  local flags
  flags=" $(awk -F': ' '/^flags/ {print $2; exit}' /proc/cpuinfo 2>/dev/null) "
  if [[ $flags == *' avx512f '* && $flags == *' avx512bw '* ]]; then
    printf '4'
  elif [[ $flags == *' avx2 '* && $flags == *' bmi2 '* ]]; then
    printf '3'
  elif [[ $flags == *' sse4_2 '* && $flags == *' popcnt '* ]]; then
    printf '2'
  else
    printf '1'
  fi
}

kernel_xanmod_install() {
  ui_section "XanMod kernel / BBRv3 — ADVANCED"
  printf '%sThis REPLACES the distribution kernel.%s Risks: exotic VPS images or\n' "$C_WARN" "$C_RESET"
  printf 'custom drivers may fail to boot; a provider rescue console is your safety\n'
  printf 'net. Benefit: BBRv3 congestion control (not available in stock kernels).\n'
  ui_hr

  if ! has_cmd apt-get; then
    log_error "XanMod install is only supported on apt-based systems (Debian/Ubuntu)."
    return 0
  fi
  if ! has_cmd curl || ! has_cmd gpg; then
    log_error "curl and gpg are required for the XanMod repository setup."
    return 0
  fi
  if [[ "$(detect_virt)" == "openvz" || "$(detect_virt)" == "lxc" ]]; then
    log_error "Container virtualization ($(detect_virt)) cannot change its kernel."
    return 0
  fi

  ui_confirm "I understand this replaces the kernel and needs a reboot. Continue?" || return 0
  local level
  level="$(_cpu_psabi_level)"
  printf 'CPU supports microarchitecture level: x64v%s\n' "$level"
  ui_confirm "Install linux-xanmod-x64v${level} now? (several minutes)" || return 0

  st_track_file "$ST_XANMOD_KEYRING"
  if ! curl -fsSL --max-time 30 'https://dl.xanmod.org/archive.key' 2>>"$ST_LOG_FILE" |
    gpg --dearmor --yes -o "$ST_XANMOD_KEYRING" 2>>"$ST_LOG_FILE"; then
    log_error "Could not fetch the XanMod signing key — nothing changed."
    return 0
  fi

  st_track_file "$ST_XANMOD_LIST"
  printf 'deb [signed-by=%s] http://deb.xanmod.org releases main\n' \
    "$ST_XANMOD_KEYRING" >"$ST_XANMOD_LIST"

  export DEBIAN_FRONTEND=noninteractive
  printf 'Updating package index and installing (watch %s for details)...\n' "$ST_LOG_FILE"
  if ! apt-get update -qq >>"$ST_LOG_FILE" 2>&1 ||
    ! apt-get install -y "linux-xanmod-x64v${level}" >>"$ST_LOG_FILE" 2>&1; then
    log_error "XanMod installation failed — see the log. Repo files can be rolled back."
    return 0
  fi

  printf '%sXanMod kernel installed.%s Reboot to activate it; BBRv3 registers as\n' "$C_OK" "$C_RESET"
  printf '"bbr", so the existing sysctl config uses it automatically. Verify after\n'
  printf 'reboot with: uname -r  and  sysctl net.ipv4.tcp_congestion_control\n'
  log_info "XanMod linux-xanmod-x64v${level} installed (reboot pending)."
}
