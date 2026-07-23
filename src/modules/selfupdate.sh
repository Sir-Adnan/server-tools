# shellcheck shell=bash
# ============================================================================
# modules/selfupdate.sh — install as the `st` command and self-update.
#
# Downloads prefer the latest GitHub Release (with SHA-256 verification when
# sha256sum is available) and fall back to the raw main build only while no
# release exists yet. Every downloaded file must pass `bash -n` and a
# fingerprint check before it replaces anything.
# ============================================================================

readonly ST_INSTALL_PATH='/usr/local/bin/st'
readonly ST_URL_RELEASE='https://github.com/Sir-Adnan/server-tools/releases/latest/download/server-tools.sh'
readonly ST_URL_RELEASE_SUMS='https://github.com/Sir-Adnan/server-tools/releases/latest/download/SHA256SUMS'
readonly ST_URL_RAW='https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh'

# _self_source_path — path of the running script, empty when running from a
# pipe/process substitution (`bash <(curl ...)` yields a non-reusable /dev/fd).
_self_source_path() {
  local src="${BASH_SOURCE[0]:-}"
  if [[ -f $src && -r $src ]]; then
    printf '%s' "$src"
    return 0
  fi
  return 1
}

# _self_download DEST — fetch, verify (checksum + parse + fingerprint), move.
_self_download() {
  local dest="$1" tmp="${ST_LIB_DIR}/download.$$" from_release=0
  if ! has_cmd curl; then
    log_error "curl is required to download ServerTools."
    return 1
  fi

  if curl -fsSL --max-time 60 "$ST_URL_RELEASE" -o "$tmp" 2>>"$ST_LOG_FILE"; then
    from_release=1
  elif ! curl -fsSL --max-time 60 "$ST_URL_RAW" -o "$tmp" 2>>"$ST_LOG_FILE"; then
    rm -f "$tmp"
    log_error "Download failed (release and raw fallback) — see the log."
    return 1
  fi

  if ((from_release)) && has_cmd sha256sum; then
    local sums expected actual
    sums="$(curl -fsSL --max-time 30 "$ST_URL_RELEASE_SUMS" 2>>"$ST_LOG_FILE")" || sums=''
    if [[ -z $sums ]]; then
      log_warn "SHA256SUMS could not be fetched — the release was NOT checksum-verified."
      printf '%sWarning:%s checksum file unavailable; only syntax checks were run.\n' "$C_WARN" "$C_RESET"
    fi
    if [[ -n $sums ]]; then
      expected="$(awk '/server-tools\.sh/ {print $1; exit}' <<<"$sums")"
      actual="$(sha256sum "$tmp" | awk '{print $1}')"
      if [[ -n $expected && $expected != "$actual" ]]; then
        rm -f "$tmp"
        log_error "SHA-256 mismatch on the downloaded release — aborting."
        return 1
      fi
    fi
  fi

  if ! bash -n "$tmp" 2>>"$ST_LOG_FILE" || ! grep -q 'ST_NAME="ServerTools"' "$tmp"; then
    rm -f "$tmp"
    log_error "Downloaded file failed sanity checks — nothing was replaced."
    return 1
  fi
  mv -f "$tmp" "$dest"
}

st_self_install() {
  local src
  mkdir -p "$(dirname "$ST_INSTALL_PATH")"
  # Deliberately NOT tracked: the installed command is the tool itself, not a
  # system change — a later rollback must never delete the user's `st`.
  if src="$(_self_source_path)"; then
    cp -f "$src" "$ST_INSTALL_PATH"
  else
    printf 'Running from a pipe — downloading the current build instead.\n'
    _self_download "$ST_INSTALL_PATH" || return 1
  fi
  chmod 755 "$ST_INSTALL_PATH"
  printf '%sInstalled.%s Run %sst%s from now on; update anytime with: st --update\n' \
    "$C_OK" "$C_RESET" "$C_KEY" "$C_RESET"
  log_info "Installed to ${ST_INSTALL_PATH} (v${ST_VERSION})."
}

st_self_update() {
  local target new_ver staged="${ST_LIB_DIR}/update.$$"
  if [[ -f $ST_INSTALL_PATH ]]; then
    target="$ST_INSTALL_PATH"
  elif ! target="$(_self_source_path)"; then
    log_error "Not installed and not running from a file — use --install first."
    return 1
  fi

  # Single download: fetch once through the verifying path into a staging
  # file, read its version, and promote that exact verified file.
  _self_download "$staged" || return 1

  new_ver="$(grep -oE 'ST_VERSION="[^"]+"' "$staged" | head -n1 | cut -d'"' -f2)" || new_ver=''
  if [[ -z $new_ver ]]; then
    rm -f "$staged"
    log_error "Could not read the downloaded version — aborting."
    return 1
  fi
  if [[ $new_ver == "$ST_VERSION" ]]; then
    printf 'Already up to date (v%s).\n' "$ST_VERSION"
    rm -f "$staged"
    return 0
  fi

  mv -f "$staged" "$target"
  chmod 755 "$target"
  printf '%sUpdated:%s v%s -> v%s (%s)\n' "$C_OK" "$C_RESET" "$ST_VERSION" "$new_ver" "$target"
  log_info "Self-updated: v${ST_VERSION} -> v${new_ver}."
}
