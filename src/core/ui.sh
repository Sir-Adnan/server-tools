# shellcheck shell=bash
# ============================================================================
# core/ui.sh — reusable terminal UI kit: rules, titles, key/value rows,
# menu items, confirm/pause. Pure bash + printf, no external UI tools.
# ============================================================================

ui_width() {
  local cols
  cols="$(tput cols 2>/dev/null)" || cols=90
  [[ $cols =~ ^[0-9]+$ ]] || cols=90
  ((cols < 70)) && cols=70
  ((cols > 100)) && cols=100
  printf '%s' "$cols"
}

# ui_repeat CHAR COUNT — prints CHAR repeated COUNT times.
ui_repeat() {
  local pad
  printf -v pad '%*s' "$2" ''
  printf '%s' "${pad// /$1}"
}

# _ui_glyph UTF8 ASCII — the first form on UTF-8 terminals, the second (safe
# on any terminal, and under NO_COLOR/dumb) everywhere else.
_ui_glyph() {
  if ((ST_UTF8)); then printf '%s' "$1"; else printf '%s' "$2"; fi
}

ui_hr() {
  local ch='-'
  ((ST_UTF8)) && ch='─'
  printf '%s%s%s\n' "$C_LINE" "$(ui_repeat "$ch" "$(ui_width)")" "$C_RESET"
}

ui_hr_heavy() {
  local ch='='
  ((ST_UTF8)) && ch='═'
  printf '%s%s%s\n' "$C_LINE" "$(ui_repeat "$ch" "$(ui_width)")" "$C_RESET"
}

# ui_center TEXT [COLOR] — center TEXT within the terminal width.
ui_center() {
  local text="$1" color="${2:-}"
  local width pad
  width="$(ui_width)"
  pad=0
  ((${#text} < width)) && pad=$(((width - ${#text}) / 2))
  printf '%*s%s%s%s\n' "$pad" '' "$color" "$text" "${color:+$C_RESET}"
}

ui_title() {
  ui_hr
  ui_center "$1" "$C_TITLE"
  ui_hr
}

# ui_section TITLE — a titled sub-heading (▸ Title).
ui_section() {
  printf '%s%s %s%s\n' "$C_TITLE" "$(_ui_glyph '▸' '#')" "$1" "$C_RESET"
}

# ui_menu_group TITLE — a titled separator that groups related menu items.
ui_menu_group() {
  local title="$1" ch='-' width text rest
  ((ST_UTF8)) && ch='─'
  width="$(ui_width)"
  text=" ${title} "
  rest=$((width - 2 - ${#text}))
  ((rest < 0)) && rest=0
  printf '\n%s%s%s%s%s%s%s\n' \
    "$C_LINE" "$(ui_repeat "$ch" 2)" \
    "$C_ACCENT" "$text" \
    "$C_LINE" "$(ui_repeat "$ch" "$rest")" "$C_RESET"
}

# ui_badge STATE — a colored status glyph. STATE: ok | warn | err | idle.
ui_badge() {
  case "$1" in
    ok) printf '%s%s%s' "$C_OK" "$(_ui_glyph '●' '[ok]')" "$C_RESET" ;;
    warn) printf '%s%s%s' "$C_WARN" "$(_ui_glyph '▲' '[!]')" "$C_RESET" ;;
    err) printf '%s%s%s' "$C_ERR" "$(_ui_glyph '✘' '[x]')" "$C_RESET" ;;
    *) printf '%s%s%s' "$C_MUTED" "$(_ui_glyph '○' '[-]')" "$C_RESET" ;;
  esac
}

# ui_hint TEXT — a dim, unobtrusive helper line for less-experienced users.
ui_hint() {
  printf ' %s%s %s%s\n' "$C_MUTED" "$(_ui_glyph 'ℹ' 'i')" "$1" "$C_RESET"
}

# ui_kv KEY VALUE — colored label, plain value.
ui_kv() {
  printf '  %s%-21s%s %s\n' "$C_KEY" "$1:" "$C_RESET" "$2"
}

# ui_menu_item KEY LABEL [HINT] — a selectable row: ❯ [key] Label — hint.
ui_menu_item() {
  local key="$1" label="$2" hint="${3:-}" arrow
  arrow="$(_ui_glyph '❯' '>')"
  if [[ -n $hint ]]; then
    printf '  %s%s%s %s[%s]%s %-22s %s%s %s%s\n' \
      "$C_ACCENT" "$arrow" "$C_RESET" "$C_KEY" "$key" "$C_RESET" \
      "$label" "$C_MUTED" "$(_ui_glyph '—' '-')" "$hint" "$C_RESET"
  else
    printf '  %s%s%s %s[%s]%s %s\n' \
      "$C_ACCENT" "$arrow" "$C_RESET" "$C_KEY" "$key" "$C_RESET" "$label"
  fi
}

ui_logo() {
  # clear can fail on TERM=dumb / weird terminals — purely cosmetic.
  ((ST_OPT_BATCH)) || clear 2>/dev/null || true
  printf '%s' "$C_TITLE"
  cat <<'LOGO'
  ____                          _____           _
 / ___|  ___ _ ____   _____ _ _|_   _|__   ___ | |___
 \___ \ / _ \ '__\ \ / / _ \ '__|| |/ _ \ / _ \| / __|
  ___) |  __/ |   \ V /  __/ |   | | (_) | (_) | \__ \
 |____/ \___|_|    \_/ \___|_|   |_|\___/ \___/|_|___/
LOGO
  printf '%s' "$C_RESET"
  ui_center "Linux server optimization · zero runtime footprint · by @UnknownZero" "$C_MUTED"
  ui_center "v${ST_VERSION}" "$C_ACCENT"
  ui_hr_heavy
}

# ui_confirm PROMPT — returns 0 only on an explicit yes.
ui_confirm() {
  local reply
  read -rp "$1 [y/N]: " reply || return 1
  [[ ${reply,,} == y || ${reply,,} == yes ]]
}

# ui_confirm_yes PROMPT — like ui_confirm but Enter means yes.
ui_confirm_yes() {
  local reply
  read -rp "$1 [Y/n]: " reply || return 1
  [[ -z $reply || ${reply,,} == y || ${reply,,} == yes ]]
}

ui_pause() {
  ((ST_OPT_BATCH)) && return 0
  [[ -t 0 ]] || return 0
  # EOF from a closed stdin is not an error here.
  read -rsn1 -p "Press any key to continue..." || true
  printf '\n'
}

# ui_todo FEATURE — honest placeholder for milestones not yet implemented.
ui_todo() {
  printf '%s[planned]%s %s is not implemented yet — it arrives in an upcoming v2 milestone.\n' \
    "$C_WARN" "$C_RESET" "$1"
  printf '%sRoadmap: %s#روادمپ / docs in the repository.%s\n' "$C_MUTED" "$ST_REPO_URL" "$C_RESET"
  ui_pause
}
