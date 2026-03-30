#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  server_audit.sh — Ubuntu Server Security Audit
#  Run: chmod +x server_audit.sh && sudo ./server_audit.sh
# ─────────────────────────────────────────────

AMBER='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

divider() { echo -e "${CYAN}────────────────────────────────────────────────────${RESET}"; }
header()  { clear; echo -e "\n${BOLD}${CYAN}$1${RESET}"; divider; }
desc()    { echo -e "${AMBER}▸ $1${RESET}"; }
run()     { echo -e "${GREEN}\$ $1${RESET}"; eval "$1"; echo; }
pause()   { echo -e "\n${DIM}Press Enter to return to menu...${RESET}"; read -r; }

# Strip ANSI escape sequences to get the visible length of a string
visible_len() {
    local s="$1"
    # Remove ESC[ ... m sequences
    s="${s//$'\033'[*([0-9;])m/}"
    # Also strip any remaining ESC sequences
    s=$(printf '%s' "$s" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g')
    # ❯ is 3 bytes but 1 display column — subtract 2 per occurrence
    local arrows
    arrows=$(grep -o '❯' <<< "$s" | wc -l)
    echo $(( ${#s} - arrows * 2 ))
}

# ─── Menu items ──────────────────────────────

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

# Build index<->number maps
declare -A IDX_TO_NUM
declare -A NUM_TO_IDX
_num=1
for _i in "${!MENU_ITEMS[@]}"; do
    if [[ "${MENU_ITEMS[$_i]}" != ──* ]]; then
        IDX_TO_NUM[$_i]=$_num
        NUM_TO_IDX[$_num]=$_i
        (( _num++ ))
    fi
done
MAX_NUM=$(( _num - 1 ))

is_separator() { [[ "${MENU_ITEMS[$1]}" == ──* ]]; }

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

# ─── Box width ───────────────────────────────
# Measure using plain text only (no color codes, no cursor char)
# Format: "  NN.   <item>  " — 2 indent + up to 2 digits + ". " + 3 spaces + item + 2 trailing

BOX_INNER=0
_build_box_width() {
    local max=0
    for i in "${!MENU_ITEMS[@]}"; do
        local item="${MENU_ITEMS[$i]}"
        local plain
        if is_separator "$i"; then
            plain="   ${item}  "
        else
            local num="${IDX_TO_NUM[$i]}"
            plain="  ${num}.   ${item}  "
        fi
        local len=${#plain}
        (( len > max )) && max=$len
    done
    BOX_INNER=$max
}
_build_box_width

# Print horizontal box rule using BOX_INNER dashes
_hrule() {
    local l="$1" m="$2" r="$3"
    printf '%s' "$l"
    printf '─%.0s' $(seq 1 "$BOX_INNER")
    printf '%s\n' "$r"
}

# Print one box row with correct right-border alignment.
# $1 = plain text content (no escapes) — used for width measurement
# $2 = colored content to actually print
_box_row() {
    local plain="$1"
    local colored="$2"
    local pad=$(( BOX_INNER - ${#plain} ))
    printf '│'
    printf '%b' "$colored"
    printf '%*s' "$pad" ''
    printf '│\n'
}

# ─── Flicker-free menu draw ──────────────────

MENU_LINE_COUNT=0

draw_menu() {
    local first_draw="${1:-}"
    if [ "$first_draw" = "first" ]; then
        clear
    else
        printf '\033[%dA' "$MENU_LINE_COUNT"
    fi

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
            local plain="   ${item}  "
            local colored="${DIM}   ${item}  ${RESET}"
            _line "  $(_box_row "$plain" "$colored")"

        else
            local num="${IDX_TO_NUM[$i]}"
            if [ "$i" -eq "$SELECTED" ]; then
                # Plain version: cursor char is 1 display col, pad accordingly
                local plain="  ${num}. ❯ ${item}  "
                local colored="${CYAN}${BOLD}  ${num}. ❯ ${item}  ${RESET}"
            else
                local plain="  ${num}.   ${item}  "
                local colored="${DIM}  ${num}.${RESET}   ${item}  "
            fi
            _line "  $(_box_row "$plain" "$colored")"
        fi
    done

    _line "  $(_hrule └ ─ ┘)"
    _line ""
    _line "  ${DIM}↑ ↓ arrow keys  or  type a number + Enter  │  q to quit${RESET}"

    MENU_LINE_COUNT=$lines
}

# ─── Checks ──────────────────────────────────

check_active_sessions() {
    header "Active Sessions"
    desc "Shows who is currently logged in, from which IP, and what they are running."
    desc "Any unfamiliar users or source IPs are a red flag."
    run "w"
    pause
}

check_login_history() {
    header "Recent Login History"
    desc "Lists the last 20 logins with timestamps and source IP addresses."
    desc "Look for logins at unusual times or from unknown locations."
    run "last -n 20"
    pause
}

check_failed_logins() {
    header "Failed Login Attempts"
    desc "Scans auth.log for failed SSH password attempts."
    desc "A flood of failures from a single IP indicates a brute-force attack."
    run "grep 'Failed password' /var/log/auth.log | tail -30"
    pause
}

check_accepted_logins() {
    header "Successful Logins"
    desc "Shows SSH logins that were accepted. Any login you did not initiate"
    desc "yourself is the clearest sign of an intruder."
    run "grep 'Accepted' /var/log/auth.log | tail -20"
    pause
}

check_ssh_keys() {
    header "Authorized SSH Keys"
    desc "Lists public keys allowed to log in as your user and as root."
    desc "Any key you do not recognize could be an attacker's backdoor."
    echo -e "${GREEN}\$ cat ~/.ssh/authorized_keys${RESET}"
    cat ~/.ssh/authorized_keys 2>/dev/null || echo "(no keys found)"
    echo
    echo -e "${GREEN}\$ sudo cat /root/.ssh/authorized_keys${RESET}"
    sudo cat /root/.ssh/authorized_keys 2>/dev/null || echo "(no keys found for root)"
    echo
    pause
}

check_ssh_config() {
    header "SSH Daemon Configuration"
    desc "Checks key SSH settings: whether root login is permitted,"
    desc "whether password auth is enabled (riskier than key-only), and the port."
    run "sudo sshd -T | grep -E 'permitrootlogin|passwordauth|port'"
    pause
}

check_processes() {
    header "All Running Processes"
    desc "Full process tree showing every running process, its owner, and CPU/memory."
    desc "Look for unfamiliar names, especially running as root, or high CPU usage."
    run "ps auxf"
    pause
}

check_ports() {
    header "Listening Ports"
    desc "Shows all TCP/UDP ports the server is listening on, and which process owns each."
    desc "Any unexpected open port could be a backdoor or rogue service."
    run "ss -tulpn"
    pause
}

check_outbound() {
    header "Established Outbound Connections"
    desc "Shows active connections your server has opened to external hosts."
    desc "Malware (especially crypto miners) maintains persistent outbound connections"
    desc "to command-and-control servers or mining pools."
    run "ss -tupn state established"
    pause
}

check_enabled_services() {
    header "Enabled Systemd Services"
    desc "Lists all services configured to start at boot."
    desc "Malware often installs itself as a service to survive reboots."
    run "systemctl list-unit-files --state=enabled"
    pause
}

check_running_services() {
    header "Currently Running Services"
    desc "Lists only services that are active right now."
    desc "Cross-reference against what you know you have installed."
    run "systemctl list-units --type=service --state=running"
    pause
}

check_crontabs() {
    header "Crontabs (All Users)"
    desc "Scans scheduled tasks for every user on the system."
    desc "Crypto miners and other malware commonly use cron for persistence —"
    desc "a cron job can re-download and re-launch a miner even after you kill it."
    local found=0
    for u in $(cut -f1 -d: /etc/passwd); do
        local CRON
        CRON=$(crontab -u "$u" -l 2>/dev/null | grep -v '^#')
        if [ -n "$CRON" ]; then
            echo -e "${GREEN}[user: $u]${RESET}"
            echo "$CRON"
            echo
            found=1
        fi
    done
    [ "$found" -eq 0 ] && echo "(no user crontabs found)"
    echo
    desc "System-wide cron directories:"
    ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null
    echo
    pause
}

check_startup_scripts() {
    header "Startup Scripts"
    desc "Lists legacy SysV init scripts and their runlevel symlinks."
    desc "An unexpected script here would start automatically at boot."
    run "ls -la /etc/init.d/"
    run "ls -la /etc/rc2.d/"
    pause
}

check_shell_users() {
    header "Users With Shell Access"
    desc "Lists accounts that can run interactive commands (bash/sh)."
    desc "Any user you did not create with /bin/bash or /bin/sh is suspicious."
    run "grep -v '/nologin\|/false' /etc/passwd"
    pause
}

check_root_uid() {
    header "Users With UID 0 (root-level)"
    desc "Only the 'root' account should have UID 0."
    desc "A second entry here means an attacker has created a hidden root account."
    run "awk -F: '\$3==0' /etc/passwd"
    pause
}

check_sudoers() {
    header "Sudoers Configuration"
    desc "Shows who can run commands as root via sudo."
    desc "Unexpected entries grant an attacker root-level control."
    run "sudo cat /etc/sudoers"
    echo -e "${GREEN}\$ sudo ls /etc/sudoers.d/${RESET}"
    sudo ls /etc/sudoers.d/ 2>/dev/null
    echo
    pause
}

check_suid() {
    header "SUID Binaries"
    desc "Finds executables with the setuid bit — they run as their owner (often root)"
    desc "regardless of who launches them. Attackers set SUID on shells or tools"
    desc "to maintain root access. Compare against a known-good baseline."
    run "find / -perm -4000 -type f 2>/dev/null"
    pause
}

check_etc_modified() {
    header "Recently Modified /etc Files (last 7 days)"
    desc "Config files changed after your initial setup date may have been tampered with."
    desc "On a fresh server, everything should date back to provisioning."
    run "find /etc -mtime -7 -type f 2>/dev/null"
    pause
}

check_bin_modified() {
    header "Recently Modified System Binaries (last 30 days)"
    desc "Rootkits work by replacing trusted system binaries (ls, ps, netstat) with"
    desc "versions that hide the attacker's activity. Any binary modified after"
    desc "the last known package update should be treated as suspicious."
    run "find /usr/bin /usr/sbin /bin /sbin -mtime -30 -type f 2>/dev/null"
    pause
}

check_tmp_hidden() {
    header "Hidden Files in /tmp and /var/tmp"
    desc "/tmp and /var/tmp are world-writable, making them favourite drop zones"
    desc "for malware. Hidden files (dot-files) here are especially suspicious."
    echo -e "${GREEN}\$ find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null${RESET}"
    find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null
    echo
    run "ls -la /tmp /var/tmp"
    pause
}

check_rkhunter() {
    header "rkhunter — Rootkit Hunter"
    desc "Scans for known rootkits, backdoors, and suspicious file properties."
    desc "Checks binary hashes, SUID files, hidden processes, and more."
    sudo apt install rkhunter -y -q
    run "sudo rkhunter --update"
    echo -e "${GREEN}\$ sudo rkhunter --check --sk 2>&1 | grep -E 'Warning|Found|Infected|OK'${RESET}"
    sudo rkhunter --check --sk 2>&1 | grep -E 'Warning|Found|Infected|OK'
    echo
    pause
}

check_chkrootkit() {
    header "chkrootkit"
    desc "A second rootkit scanner — good practice to use both rkhunter and chkrootkit"
    desc "since they use different detection signatures (like two antivirus engines)."
    sudo apt install chkrootkit -y -q
    run "sudo chkrootkit 2>&1 | grep -v 'not found\|not tested'"
    pause
}

check_clamav() {
    header "ClamAV Malware Scanner"
    desc "Scans /home, /var/www, and /tmp for known malware signatures."
    desc "Best for catching file-based malware like web shells or dropped binaries."
    sudo apt install clamav -y -q
    run "sudo freshclam"
    run "sudo clamscan -r /home /var/www /tmp --remove=yes"
    pause
}

check_miners() {
    header "Crypto Miner Detection"
    desc "Looks for known miner process names and binaries on disk."
    desc "Miners disguise themselves with kernel-like names (kdevtmpfsi, kthreaddi)"
    desc "and hide in /tmp, /dev/shm, or /var/tmp."
    echo -e "${GREEN}\$ ps aux --sort=-%cpu | head -20${RESET}"
    ps aux --sort=-%cpu | head -20
    echo
    desc "Scanning for known miner binary names..."
    run "find / -name 'xmrig' -o -name 'minerd' -o -name 'kdevtmpfsi' -o -name 'kthreaddi' -o -name 'sysupdate' 2>/dev/null"
    desc "Checking for miner-related network connections (common pool ports)..."
    run "ss -tupn | grep -E ':3333|:4444|:14444|:45700|:5555'"
    pause
}

run_all() {
    check_active_sessions;    check_login_history;     check_failed_logins
    check_accepted_logins;    check_ssh_keys;          check_ssh_config
    check_processes;          check_ports;             check_outbound
    check_enabled_services;   check_running_services;  check_crontabs
    check_startup_scripts;    check_shell_users;       check_root_uid
    check_sudoers;            check_suid;              check_etc_modified
    check_bin_modified;       check_tmp_hidden;        check_miners
    echo -e "${GREEN}${BOLD}All checks complete. Run scanner options separately to install and run malware scanners.${RESET}"
    pause
}

# ─── Dispatch ────────────────────────────────

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

# ─── Number input ────────────────────────────

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

# ─── Main loop ───────────────────────────────

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
            NUMBER_BUF=""
            SELECTED=$(prev_selectable)
            draw_menu
            ;;
        $'\x1b[B'|$'\x1b[OB')
            NUMBER_BUF=""
            SELECTED=$(next_selectable)
            draw_menu
            ;;
        $'\x7f'|$'\x08')
            handle_backspace
            ;;
        [0-9])
            handle_digit "$key"
            ;;
        '')
            NUMBER_BUF=""
            tput cnorm
            dispatch "$SELECTED"
            tput civis
            draw_menu first
            ;;
        q|Q)
            tput cnorm
            echo "Bye."
            exit 0
            ;;
    esac
done
