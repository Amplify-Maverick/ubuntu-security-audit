#!/usr/bin/env bash
# audit/menu.sh — Menu definition, box renderer, input loop
# Sourced by server_audit.sh after all check modules are loaded.

# ── Menu items ────────────────────────────────────────────────────────────────
# Lines starting with ── are non-selectable section headers.

MENU_ITEMS=(
    "── SSH & Authentication ──────────────────"
    "Active sessions"
    "Recent login history"
    "Failed login attempts"
    "Successful logins (possible intrusions)"
    "Authorized SSH keys"
    "SSH daemon config"
    "── Processes & Network ───────────────────"
    "All running processes"
    "Listening ports"
    "Established outbound connections"
    "── Persistence & Startup ─────────────────"
    "Enabled systemd services"
    "Currently running services"
    "Crontabs (all users)"
    "Startup scripts (init.d / rc*.d)"
    "── Users & Permissions ───────────────────"
    "Users with shell access"
    "Users with root UID (UID 0)"
    "Sudoers configuration"
    "Files with SUID bit set"
    "── File System ───────────────────────────"
    "Recently modified /etc files (7 days)"
    "Recently modified system binaries (30 days)"
    "Hidden files in /tmp and /var/tmp"
    "── Malware Scanning ──────────────────────"
    "Install & run rkhunter"
    "Install & run chkrootkit"
    "Install & run ClamAV"
    "Check for crypto miners"
    "── Bulk ──────────────────────────────────"
    "Run ALL checks (no scanners)"
    "Quit"
)

# ── Index maps ────────────────────────────────────────────────────────────────

declare -A IDX_TO_NUM   # array index  → display number
declare -A NUM_TO_IDX   # display number → array index
_num=1
for _i in "${!MENU_ITEMS[@]}"; do
    if [[ "${MENU_ITEMS[$_i]}" != ──* ]]; then
        IDX_TO_NUM[$_i]=$_num
        NUM_TO_IDX[$_num]=$_i
        (( _num++ ))
    fi
done
MAX_NUM=$(( _num - 1 ))

is_separator()    { [[ "${MENU_ITEMS[$1]}" == ──* ]]; }

next_selectable() {
    local i=$(( SELECTED + 1 ))
    while [ "$i" -lt "${#MENU_ITEMS[@]}" ]; do
        is_separator "$i" || { echo "$i"; return; }
        (( i++ ))
    done
    echo "$SELECTED"
}

prev_selectable() {
    local i=$(( SELECTED - 1 ))
    while [ "$i" -ge 0 ]; do
        is_separator "$i" || { echo "$i"; return; }
        (( i-- ))
    done
    echo "$SELECTED"
}

# ── Box drawing ───────────────────────────────────────────────────────────────
# BOX_INNER is the inner width of the box, computed from the longest menu item.
# All padding arithmetic uses plain (no-ANSI) strings to stay accurate.

BOX_INNER=0
_build_box_width() {
    local max=0
    for i in "${!MENU_ITEMS[@]}"; do
        local plain
        if is_separator "$i"; then
            plain="   ${MENU_ITEMS[$i]}  "
        else
            plain="  ${IDX_TO_NUM[$i]}.   ${MENU_ITEMS[$i]}  "
        fi
        (( ${#plain} > max )) && max=${#plain}
    done
    BOX_INNER=$max
}
_build_box_width

_hrule() {
    printf '%s' "$1"
    printf '─%.0s' $(seq 1 "$BOX_INNER")
    printf '%s\n' "$3"
}

_box_row() {
    # $1 = plain content (for length measurement), $2 = colored content (printed)
    local pad=$(( BOX_INNER - ${#1} ))
    printf '│'; printf '%b' "$2"; printf '%*s' "$pad" ''; printf '│\n'
}

# ── Flicker-free draw ─────────────────────────────────────────────────────────
# On first call: clear + draw. On subsequent calls: cursor-up + overwrite in
# place, so the menu never blanks (no flash on arrow key presses).

MENU_LINE_COUNT=0

draw_menu() {
    local first_draw="${1:-}"
    [ "$first_draw" = "first" ] && clear || printf '\033[%dA' "$MENU_LINE_COUNT"

    local lines=0
    _line() { printf '\033[2K'; printf '%b\n' "$1"; (( lines++ )); }

    _line "${BOLD}"
    _line "  ╔══════════════════════════════════════════╗"
    _line "  ║       Ubuntu Server Security Audit       ║"
    _line "  ╚══════════════════════════════════════════╝"
    _line "${RESET}"
    _line "  $(_hrule ┌ ─ ┐)"

    local i
    for i in "${!MENU_ITEMS[@]}"; do
        local item="${MENU_ITEMS[$i]}"
        if is_separator "$i"; then
            [ "$i" -ne 0 ] && _line "  $(_hrule ├ ─ ┤)"
            _line "  $(_box_row "   ${item}  " "${DIM}   ${item}  ${RESET}")"
        else
            local num="${IDX_TO_NUM[$i]}"
            if [ "$i" -eq "$SELECTED" ]; then
                _line "  $(_box_row "  ${num}. ❯ ${item}  " "${CYAN}${BOLD}  ${num}. ❯ ${item}  ${RESET}")"
            else
                _line "  $(_box_row "  ${num}.   ${item}  " "${DIM}  ${num}.${RESET}   ${item}  ")"
            fi
        fi
    done

    _line "  $(_hrule └ ─ ┘)"
    _line ""
    _line "  ${DIM}↑ ↓ arrow keys  or  type a number + Enter  │  q to quit${RESET}"
    MENU_LINE_COUNT=$lines
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

dispatch() {
    case "${MENU_ITEMS[$1]}" in
        "Active sessions")                              check_active_sessions ;;
        "Recent login history")                         check_login_history ;;
        "Failed login attempts")                        check_failed_logins ;;
        "Successful logins (possible intrusions)")      check_accepted_logins ;;
        "Authorized SSH keys")                          check_ssh_keys ;;
        "SSH daemon config")                            check_ssh_config ;;
        "All running processes")                        check_processes ;;
        "Listening ports")                              check_ports ;;
        "Established outbound connections")             check_outbound ;;
        "Enabled systemd services")                     check_enabled_services ;;
        "Currently running services")                   check_running_services ;;
        "Crontabs (all users)")                         check_crontabs ;;
        "Startup scripts (init.d / rc*.d)")             check_startup_scripts ;;
        "Users with shell access")                      check_shell_users ;;
        "Users with root UID (UID 0)")                  check_root_uid ;;
        "Sudoers configuration")                        check_sudoers ;;
        "Files with SUID bit set")                      check_suid ;;
        "Recently modified /etc files (7 days)")        check_etc_modified ;;
        "Recently modified system binaries (30 days)")  check_bin_modified ;;
        "Hidden files in /tmp and /var/tmp")            check_tmp_hidden ;;
        "Install & run rkhunter")                       check_rkhunter ;;
        "Install & run chkrootkit")                     check_chkrootkit ;;
        "Install & run ClamAV")                         check_clamav ;;
        "Check for crypto miners")                      check_miners ;;
        "Run ALL checks (no scanners)")                 run_all ;;
        "Quit")                                         tput cnorm; echo "Bye."; exit 0 ;;
    esac
}

# ── Number input ──────────────────────────────────────────────────────────────

NUMBER_BUF=""

handle_digit() {
    local tentative="${NUMBER_BUF}$1"
    if [ "$tentative" -le "$MAX_NUM" ] 2>/dev/null; then
        NUMBER_BUF="$tentative"
        local idx="${NUM_TO_IDX[$NUMBER_BUF]}"
        [ -n "$idx" ] && SELECTED="$idx" && draw_menu
    fi
}

handle_backspace() {
    if [ -n "$NUMBER_BUF" ]; then
        NUMBER_BUF="${NUMBER_BUF%?}"
        if [ -n "$NUMBER_BUF" ]; then
            local idx="${NUM_TO_IDX[$NUMBER_BUF]}"
            [ -n "$idx" ] && SELECTED="$idx"
        fi
        draw_menu
    fi
}

# ── Main input loop ───────────────────────────────────────────────────────────

run_menu() {
    tput civis
    trap 'tput cnorm; echo' EXIT

    SELECTED=1
    draw_menu first

    while true; do
        IFS= read -rsn1 key
        if [[ "$key" == $'\x1b' ]]; then
            read -rsn2 -t 0.1 rest
            key="${key}${rest}"
        fi

        case "$key" in
            $'\x1b[A'|$'\x1b[OA')
                NUMBER_BUF=""; SELECTED=$(prev_selectable); draw_menu ;;
            $'\x1b[B'|$'\x1b[OB')
                NUMBER_BUF=""; SELECTED=$(next_selectable); draw_menu ;;
            $'\x7f'|$'\x08')
                handle_backspace ;;
            [0-9])
                handle_digit "$key" ;;
            '')
                NUMBER_BUF=""; tput cnorm; dispatch "$SELECTED"; tput civis; draw_menu first ;;
            q|Q)
                tput cnorm; echo "Bye."; exit 0 ;;
        esac
    done
}
