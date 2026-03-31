#!/usr/bin/env bash
# audit/menu.sh — Two-level menu: categories → submenus
# Sourced by server_audit.sh after all check modules are loaded.

# ── Category & submenu definitions ───────────────────────────────────────────
# MAIN_ITEMS      : labels shown on the main menu (selectable + special entries)
# SUBMENU_<name>  : items shown when that category is selected

MAIN_ITEMS=(
    "SSH & Authentication"
    "Processes & Network"
    "Persistence & Startup"
    "Users & Permissions"
    "File System"
    "Malware Scanning"
    "Run ALL checks"
    "Quit"
)

SUBMENU_SSH=(
    "Active sessions"
    "Recent login history"
    "Failed login attempts"
    "Successful logins (possible intrusions)"
    "Authorized SSH keys"
    "SSH daemon config"
    "Run all SSH & Auth checks"
    "← Back"
)

SUBMENU_NETWORK=(
    "All running processes"
    "Listening ports"
    "Established outbound connections"
    "Firewall (UFW)"
    "Run all Processes & Network checks"
    "← Back"
)

SUBMENU_PERSISTENCE=(
    "Enabled systemd services"
    "Currently running services"
    "Crontabs (all users)"
    "Startup scripts (init.d / rc*.d)"
    "Run all Persistence & Startup checks"
    "← Back"
)

SUBMENU_USERS=(
    "Users with shell access"
    "Users with root UID (UID 0)"
    "Sudoers configuration"
    "Files with SUID bit set"
    "Run all Users & Permissions checks"
    "← Back"
)

SUBMENU_FILESYSTEM=(
    "Recently modified /etc files (7 days)"
    "Recently modified system binaries (30 days)"
    "Hidden files in /tmp and /var/tmp"
    "Run all File System checks"
    "← Back"
)

SUBMENU_MALWARE=(
    "Install & run rkhunter"
    "Install & run chkrootkit"
    "Install & run ClamAV"
    "Check for crypto miners"
    "Run all Malware checks"
    "← Back"
)

# ── Clean exit ───────────────────────────────────────────────────────────────
# Moves the cursor back to the top of the menu block and erases exactly the
# lines the menu drew — leaving everything above it in the terminal untouched.
_quit() {
    tput cnorm   # restore cursor
    tput rmcup   # restore original screen — everything before launch reappears
    exit 0
}

# ── Box drawing ───────────────────────────────────────────────────────────────
# Computed fresh each time a menu is drawn from the items passed to draw_menu.

_compute_box_width() {
    # $@ = menu item strings; sets BOX_INNER
    local max=0 i=1
    for item in "$@"; do
        local plain="  ${i}.   ${item}  "
        (( ${#plain} > max )) && max=${#plain}
        (( i++ ))
    done
    BOX_INNER=$max
}

_hrule() {
    printf '%s' "$1"
    printf '─%.0s' $(seq 1 "$BOX_INNER")
    printf '%s\n' "$3"
}

_box_row() {
    # $1 = plain string (for width), $2 = colored string (printed)
    local pad=$(( BOX_INNER - ${#1} ))
    printf '│'; printf '%b' "$2"; printf '%*s' "$pad" ''; printf '│\n'
}

# ── Generic menu renderer ─────────────────────────────────────────────────────
# draw_menu FIRST|"" TITLE SELECTED_IDX ITEM [ITEM ...]
#   FIRST    : pass "first" to clear screen, anything else to redraw in-place
#   TITLE    : subtitle shown inside the banner (e.g. "SSH & Authentication")
#   SEL      : 0-based index of the highlighted item

MENU_LINE_COUNT=0

draw_menu() {
    local first_draw="$1" title="$2" sel="$3"
    shift 3
    local items=("$@")

    [ "$first_draw" = "first" ] && clear || printf '\033[%dA' "$MENU_LINE_COUNT"

    _compute_box_width "${items[@]}"

    local lines=0
    _line() { printf '\033[2K'; printf '%b\n' "$1"; (( lines++ )); }

    # ── Banner ──
    _line "${BOLD}"
    _line "  ╔══════════════════════════════════════════╗"
    _line "  ║       Ubuntu Server Security Audit       ║"
    _line "  ╚══════════════════════════════════════════╝"
    _line "${RESET}"

    # ── Disclaimer ──
    _line "  ${AMBER}${BOLD}⚠  Disclaimer${RESET}"
    _line "  ${AMBER}Always independently verify command outputs.${RESET}"
    _line "  ${AMBER}Do not rely solely on this script to assess server security.${RESET}"
    _line ""

    # ── Subtitle (category name, empty on main menu) ──
    if [ -n "$title" ]; then
        _line "  ${BOLD}${CYAN}${title}${RESET}"
        _line ""
    fi

    # ── Box ──
    _line "  $(_hrule ┌ ─ ┐)"

    local i
    for i in "${!items[@]}"; do
        local item="${items[$i]}"
        local num=$(( i + 1 ))
        if [ "$i" -eq "$sel" ]; then
            _line "  $(_box_row "  ${num}. ❯ ${item}  " "${CYAN}${BOLD}  ${num}. ❯ ${item}  ${RESET}")"
        else
            _line "  $(_box_row "  ${num}.   ${item}  " "${DIM}  ${num}.${RESET}   ${item}  ")"
        fi
    done

    _line "  $(_hrule └ ─ ┘)"
    _line ""
    _line "  ${DIM}↑ ↓ arrow keys  or  type a number + Enter  │  q to quit${RESET}"

    MENU_LINE_COUNT=$lines
}

# ── Generic submenu runner ────────────────────────────────────────────────────
# run_submenu TITLE ITEM [ITEM ...]
# Loops until the user selects "← Back", then returns to the caller.

run_submenu() {
    local title="$1"; shift
    local items=("$@")
    local count=${#items[@]}
    local sel=0
    local num_buf=""

    tput civis
    draw_menu first "$title" "$sel" "${items[@]}"

    while true; do
        IFS= read -rsn1 key
        if [[ "$key" == $'\x1b' ]]; then
            read -rsn2 -t 0.1 rest
            key="${key}${rest}"
        fi

        case "$key" in
            $'\x1b[A'|$'\x1b[OA')   # up
                num_buf=""
                (( sel > 0 )) && (( sel-- ))
                draw_menu "" "$title" "$sel" "${items[@]}" ;;
            $'\x1b[B'|$'\x1b[OB')   # down
                num_buf=""
                (( sel < count - 1 )) && (( sel++ ))
                draw_menu "" "$title" "$sel" "${items[@]}" ;;
            [0-9])
                local tentative="${num_buf}${key}"
                if [ "$tentative" -le "$count" ] 2>/dev/null && [ "$tentative" -ge 1 ]; then
                    num_buf="$tentative"
                    sel=$(( num_buf - 1 ))
                    draw_menu "" "$title" "$sel" "${items[@]}"
                fi ;;
            $'\x7f'|$'\x08')         # backspace
                if [ -n "$num_buf" ]; then
                    num_buf="${num_buf%?}"
                    if [ -n "$num_buf" ] && [ "$num_buf" -ge 1 ] && [ "$num_buf" -le "$count" ] 2>/dev/null; then
                        sel=$(( num_buf - 1 ))
                    fi
                    draw_menu "" "$title" "$sel" "${items[@]}"
                fi ;;
            '')                       # enter
                num_buf=""
                local chosen="${items[$sel]}"
                if [ "$chosen" = "← Back" ]; then
                    tput cnorm
                    return
                fi
                tput cnorm
                submenu_dispatch "$chosen"
                tput civis
                draw_menu first "$title" "$sel" "${items[@]}" ;;
            q|Q)
                _quit ;;
        esac
    done
}

# ── Submenu dispatch ──────────────────────────────────────────────────────────
# Maps every leaf item label to its check function.

submenu_dispatch() {
    case "$1" in
        # SSH & Auth
        "Active sessions")                              check_active_sessions ;;
        "Recent login history")                         check_login_history ;;
        "Failed login attempts")                        check_failed_logins ;;
        "Successful logins (possible intrusions)")      check_accepted_logins ;;
        "Authorized SSH keys")                          check_ssh_keys ;;
        "SSH daemon config")                            check_ssh_config ;;
        "Run all SSH & Auth checks")
            check_active_sessions; check_login_history; check_failed_logins
            check_accepted_logins; check_ssh_keys; check_ssh_config ;;
        # Processes & Network
        "All running processes")                        check_processes ;;
        "Listening ports")                              check_ports ;;
        "Established outbound connections")             check_outbound ;;
        "Firewall (UFW)")                                check_firewall ;;
        "Run all Processes & Network checks")
            check_processes; check_ports; check_outbound; check_firewall ;;
        # Persistence & Startup
        "Enabled systemd services")                     check_enabled_services ;;
        "Currently running services")                   check_running_services ;;
        "Crontabs (all users)")                         check_crontabs ;;
        "Startup scripts (init.d / rc*.d)")             check_startup_scripts ;;
        "Run all Persistence & Startup checks")
            check_enabled_services; check_running_services
            check_crontabs; check_startup_scripts ;;
        # Users & Permissions
        "Users with shell access")                      check_shell_users ;;
        "Users with root UID (UID 0)")                  check_root_uid ;;
        "Sudoers configuration")                        check_sudoers ;;
        "Files with SUID bit set")                      check_suid ;;
        "Run all Users & Permissions checks")
            check_shell_users; check_root_uid; check_sudoers; check_suid ;;
        # File System
        "Recently modified /etc files (7 days)")        check_etc_modified ;;
        "Recently modified system binaries (30 days)")  check_bin_modified ;;
        "Hidden files in /tmp and /var/tmp")            check_tmp_hidden ;;
        "Run all File System checks")
            check_etc_modified; check_bin_modified; check_tmp_hidden ;;
        # Malware
        "Install & run rkhunter")                       check_rkhunter ;;
        "Install & run chkrootkit")                     check_chkrootkit ;;
        "Install & run ClamAV")                         check_clamav ;;
        "Check for crypto miners")                      check_miners ;;
        "Run all Malware checks")
            check_rkhunter; check_chkrootkit; check_clamav; check_miners ;;
    esac
}

# ── Main menu runner ──────────────────────────────────────────────────────────

run_menu() {
    tput smcup  # switch to alternate screen buffer
    tput civis
    trap '_quit' EXIT INT TERM

    local sel=0
    local count=${#MAIN_ITEMS[@]}
    local num_buf=""

    draw_menu first "" "$sel" "${MAIN_ITEMS[@]}"

    while true; do
        IFS= read -rsn1 key
        if [[ "$key" == $'\x1b' ]]; then
            read -rsn2 -t 0.1 rest
            key="${key}${rest}"
        fi

        case "$key" in
            $'\x1b[A'|$'\x1b[OA')
                num_buf=""
                (( sel > 0 )) && (( sel-- ))
                draw_menu "" "" "$sel" "${MAIN_ITEMS[@]}" ;;
            $'\x1b[B'|$'\x1b[OB')
                num_buf=""
                (( sel < count - 1 )) && (( sel++ ))
                draw_menu "" "" "$sel" "${MAIN_ITEMS[@]}" ;;
            [0-9])
                local tentative="${num_buf}${key}"
                if [ "$tentative" -le "$count" ] 2>/dev/null && [ "$tentative" -ge 1 ]; then
                    num_buf="$tentative"
                    sel=$(( num_buf - 1 ))
                    draw_menu "" "" "$sel" "${MAIN_ITEMS[@]}"
                fi ;;
            $'\x7f'|$'\x08')
                if [ -n "$num_buf" ]; then
                    num_buf="${num_buf%?}"
                    if [ -n "$num_buf" ] && [ "$num_buf" -ge 1 ] && [ "$num_buf" -le "$count" ] 2>/dev/null; then
                        sel=$(( num_buf - 1 ))
                    fi
                    draw_menu "" "" "$sel" "${MAIN_ITEMS[@]}"
                fi ;;
            '')
                num_buf=""
                case "${MAIN_ITEMS[$sel]}" in
                    "SSH & Authentication")
                        tput cnorm
                        run_submenu "SSH & Authentication" "${SUBMENU_SSH[@]}"
                        tput civis
                        draw_menu first "" "$sel" "${MAIN_ITEMS[@]}" ;;
                    "Processes & Network")
                        tput cnorm
                        run_submenu "Processes & Network" "${SUBMENU_NETWORK[@]}"
                        tput civis
                        draw_menu first "" "$sel" "${MAIN_ITEMS[@]}" ;;
                    "Persistence & Startup")
                        tput cnorm
                        run_submenu "Persistence & Startup" "${SUBMENU_PERSISTENCE[@]}"
                        tput civis
                        draw_menu first "" "$sel" "${MAIN_ITEMS[@]}" ;;
                    "Users & Permissions")
                        tput cnorm
                        run_submenu "Users & Permissions" "${SUBMENU_USERS[@]}"
                        tput civis
                        draw_menu first "" "$sel" "${MAIN_ITEMS[@]}" ;;
                    "File System")
                        tput cnorm
                        run_submenu "File System" "${SUBMENU_FILESYSTEM[@]}"
                        tput civis
                        draw_menu first "" "$sel" "${MAIN_ITEMS[@]}" ;;
                    "Malware Scanning")
                        tput cnorm
                        run_submenu "Malware Scanning" "${SUBMENU_MALWARE[@]}"
                        tput civis
                        draw_menu first "" "$sel" "${MAIN_ITEMS[@]}" ;;
                    "Run ALL checks")
                        tput cnorm; run_all; tput civis
                        draw_menu first "" "$sel" "${MAIN_ITEMS[@]}" ;;
                    "Quit")
                        _quit ;;
                esac ;;
            q|Q)
                _quit ;;
        esac
    done
}
