#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  server_audit.sh — Ubuntu Server Security Audit
#  Run: chmod +x server_audit.sh && sudo ./server_audit.sh
# ─────────────────────────────────────────────

AMBER='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

divider()  { echo -e "${CYAN}────────────────────────────────────────────────────${RESET}"; }
header()   { clear; echo -e "\n${BOLD}${CYAN}$1${RESET}"; divider; }
desc()     { echo -e "${AMBER}▸ $1${RESET}"; }
run()      { echo -e "${GREEN}\$ $1${RESET}"; eval "$1"; echo; }
pause()    { echo -e "\n${DIM}Press Enter to return to menu...${RESET}"; read -r; }

# Analysis helpers
analysis_header() { echo -e "\n${BOLD}${CYAN}── Analysis ────────────────────────────────────────${RESET}"; }
flag()   { echo -e "  ${RED}${BOLD}[!]${RESET} $1"; }
warn()   { echo -e "  ${AMBER}${BOLD}[~]${RESET} $1"; }
ok()     { echo -e "  ${GREEN}${BOLD}[✓]${RESET} $1"; }
info()   { echo -e "  ${CYAN}[-]${RESET} $1"; }

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

# ─── Box drawing ─────────────────────────────

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

_hrule() {
    printf '%s' "$1"
    printf '─%.0s' $(seq 1 "$BOX_INNER")
    printf '%s\n' "$3"
}

_box_row() {
    local plain="$1" colored="$2"
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

# ═══════════════════════════════════════════════
#  CHECKS WITH ANALYSIS
# ═══════════════════════════════════════════════

check_active_sessions() {
    header "Active Sessions"
    desc "Shows who is currently logged in, from which IP, and what they are running."
    desc "Any unfamiliar users or source IPs are a red flag."
    local output
    output=$(w)
    echo "$output"
    echo

    analysis_header
    local session_count
    session_count=$(echo "$output" | tail -n +3 | grep -c '.' || true)
    local unique_ips
    unique_ips=$(echo "$output" | tail -n +3 | awk '{print $3}' | sort -u | grep -v '^$' || true)
    local root_sessions
    root_sessions=$(echo "$output" | grep '^root' || true)

    [ "$session_count" -le 2 ] && ok "Normal number of active sessions ($session_count)." \
        || warn "$session_count active sessions — verify all are expected."
    [ -z "$root_sessions" ] && ok "No root sessions detected." \
        || flag "Root is logged in directly: $root_sessions"
    if [ -n "$unique_ips" ]; then
        while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
                && info "Session from IP: ${BOLD}$ip${RESET} — verify this is you." \
                || true
        done <<< "$unique_ips"
    fi
    pause
}

check_login_history() {
    header "Recent Login History"
    desc "Lists the last 20 logins with timestamps and source IP addresses."
    desc "Look for logins at unusual times or from unknown locations."
    local output
    output=$(last -n 20)
    echo "$output"
    echo

    analysis_header
    local unique_ips
    unique_ips=$(echo "$output" | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
    local unique_users
    unique_users=$(echo "$output" | awk '{print $1}' | grep -vE '^(reboot|wtmp|$)' | sort -u)
    local reboot_count
    reboot_count=$(echo "$output" | grep -c 'reboot' || true)

    if [ -z "$unique_ips" ]; then
        info "No external IP logins found in this sample."
    else
        ok "Unique source IPs in history:"
        while IFS= read -r ip; do
            info "  ${BOLD}$ip${RESET}"
        done <<< "$unique_ips"
        local ip_count
        ip_count=$(echo "$unique_ips" | grep -c '.' || true)
        [ "$ip_count" -gt 3 ] && warn "$ip_count distinct IPs — expected if you access from multiple locations, suspicious otherwise."
    fi
    [ -n "$unique_users" ] && info "Users seen in login history: $(echo "$unique_users" | tr '\n' ' ')"
    [ "$reboot_count" -gt 3 ] \
        && warn "$reboot_count reboots in recent history — could indicate crashes or forced restarts." \
        || ok "$reboot_count reboot(s) in recent history — normal."
    pause
}

check_failed_logins() {
    header "Failed Login Attempts"
    desc "Scans auth.log for failed SSH password attempts."
    desc "A flood of failures from a single IP indicates a brute-force attack."
    local output
    output=$(grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -30)
    if [ -z "$output" ]; then
        echo "(no failed password attempts found in auth.log)"
    else
        echo "$output"
    fi
    echo

    analysis_header
    local total
    total=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0)
    local top_ips
    top_ips=$(grep 'Failed password' /var/log/auth.log 2>/dev/null \
        | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
        | awk '{print $2}' | sort | uniq -c | sort -rn | head -5)
    local top_users
    top_users=$(grep 'Failed password' /var/log/auth.log 2>/dev/null \
        | grep -oP 'for (invalid user )?\K\S+' | sort | uniq -c | sort -rn | head -5)

    if [ "$total" -eq 0 ]; then
        ok "No failed login attempts found."
    elif [ "$total" -lt 20 ]; then
        warn "$total failed attempt(s) total — low level, possibly just noise."
    elif [ "$total" -lt 200 ]; then
        warn "$total failed attempts — moderate. Monitor for increases."
    else
        flag "$total failed attempts — this server is under active brute-force attack."
        info "Consider installing fail2ban: sudo apt install fail2ban"
    fi

    if [ -n "$top_ips" ]; then
        info "Top offending IPs:"
        while IFS= read -r line; do
            local count ip
            count=$(echo "$line" | awk '{print $1}')
            ip=$(echo "$line" | awk '{print $2}')
            [ "$count" -gt 50 ] \
                && flag "  $count attempts from ${BOLD}$ip${RESET} — consider blocking with: ufw deny from $ip" \
                || warn "  $count attempts from ${BOLD}$ip${RESET}"
        done <<< "$top_ips"
    fi

    if [ -n "$top_users" ]; then
        info "Most targeted usernames:"
        while IFS= read -r line; do
            info "  $(echo "$line" | awk '{print $1}') attempts for user '$(echo "$line" | awk '{print $2}')'"
        done <<< "$top_users"
    fi
    pause
}

check_accepted_logins() {
    header "Successful Logins"
    desc "Shows SSH logins that were accepted. Any login you did not initiate"
    desc "yourself is the clearest sign of an intruder."
    local output
    output=$(grep 'Accepted' /var/log/auth.log 2>/dev/null | tail -20)
    if [ -z "$output" ]; then
        echo "(no accepted logins found in auth.log)"
    else
        echo "$output"
    fi
    echo

    analysis_header
    local total
    total=$(grep -c 'Accepted' /var/log/auth.log 2>/dev/null || echo 0)
    local pw_logins
    pw_logins=$(grep 'Accepted password' /var/log/auth.log 2>/dev/null | wc -l)
    local key_logins
    key_logins=$(grep 'Accepted publickey' /var/log/auth.log 2>/dev/null | wc -l)
    local unique_ips
    unique_ips=$(grep 'Accepted' /var/log/auth.log 2>/dev/null \
        | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort -u)
    local root_logins
    root_logins=$(grep 'Accepted' /var/log/auth.log 2>/dev/null | grep 'for root' || true)

    [ "$total" -eq 0 ] && ok "No accepted logins on record." || info "$total accepted login(s) total."
    [ "$key_logins" -gt 0 ] && ok "$key_logins login(s) via SSH key (secure)."
    if [ "$pw_logins" -gt 0 ]; then
        flag "$pw_logins login(s) via password — password auth should be disabled in sshd_config."
        info "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
    fi
    [ -n "$root_logins" ] && flag "Direct root login(s) detected — root SSH access should be disabled." \
        || ok "No direct root logins found."
    if [ -n "$unique_ips" ]; then
        info "IPs that have successfully logged in:"
        while IFS= read -r ip; do
            info "  ${BOLD}$ip${RESET} — verify this is a known address."
        done <<< "$unique_ips"
    fi
    pause
}

check_ssh_keys() {
    header "Authorized SSH Keys"
    desc "Lists public keys allowed to log in as your user and as root."
    desc "Any key you do not recognize could be an attacker's backdoor."

    local user_keys root_keys
    user_keys=$(cat ~/.ssh/authorized_keys 2>/dev/null)
    root_keys=$(sudo cat /root/.ssh/authorized_keys 2>/dev/null)

    echo -e "${GREEN}\$ cat ~/.ssh/authorized_keys${RESET}"
    [ -n "$user_keys" ] && echo "$user_keys" || echo "(no keys found)"
    echo
    echo -e "${GREEN}\$ sudo cat /root/.ssh/authorized_keys${RESET}"
    [ -n "$root_keys" ] && echo "$root_keys" || echo "(no keys found for root)"
    echo

    analysis_header
    local user_count=0 root_count=0
    [ -n "$user_keys" ] && user_count=$(echo "$user_keys" | grep -c 'ssh-' || true)
    [ -n "$root_keys" ] && root_count=$(echo "$root_keys" | grep -c 'ssh-' || true)

    [ "$user_count" -eq 0 ] && info "No authorized keys for current user." \
        || ok "$user_count authorized key(s) for current user — verify each is intentional."
    if [ "$root_count" -gt 0 ]; then
        warn "$root_count authorized key(s) for root — root key login is a security risk if not required."
    else
        ok "No authorized keys for root."
    fi
    info "If you see an unfamiliar key, remove it immediately and rotate your own keys."
    pause
}

check_ssh_config() {
    header "SSH Daemon Configuration"
    desc "Checks key SSH settings: whether root login is permitted,"
    desc "whether password auth is enabled (riskier than key-only), and the port."
    local output
    output=$(sudo sshd -T 2>/dev/null | grep -E 'permitrootlogin|passwordauth|port|pubkeyauth|maxauthtries|logingracetime')
    echo "$output"
    echo

    analysis_header
    local root_login pw_auth port pubkey max_tries grace
    root_login=$(echo "$output" | grep 'permitrootlogin' | awk '{print $2}')
    pw_auth=$(echo "$output" | grep 'passwordauthentication' | awk '{print $2}')
    port=$(echo "$output" | grep '^port ' | awk '{print $2}')
    pubkey=$(echo "$output" | grep 'pubkeyauthentication' | awk '{print $2}')
    max_tries=$(echo "$output" | grep 'maxauthtries' | awk '{print $2}')
    grace=$(echo "$output" | grep 'logingracetime' | awk '{print $2}')

    case "$root_login" in
        no)        ok "PermitRootLogin is disabled." ;;
        yes)       flag "PermitRootLogin is YES — root can log in directly over SSH. Set to 'no'." ;;
        prohibit-password) warn "PermitRootLogin is 'prohibit-password' — root can log in with a key. Consider setting to 'no'." ;;
        *)         info "PermitRootLogin: ${root_login:-unknown}" ;;
    esac

    case "$pw_auth" in
        no)  ok "PasswordAuthentication is disabled — key-only login enforced." ;;
        yes) flag "PasswordAuthentication is YES — brute-force attacks are possible. Set to 'no' and use SSH keys only." ;;
        *)   info "PasswordAuthentication: ${pw_auth:-unknown}" ;;
    esac

    [ "$pubkey" = "yes" ] && ok "PubkeyAuthentication is enabled." \
        || warn "PubkeyAuthentication may be disabled — ensure you have another way in before changing settings."

    if [ "$port" = "22" ]; then
        warn "SSH is on default port 22 — bots actively scan this port. Changing to a non-standard port reduces noise."
    else
        ok "SSH is on non-standard port $port — reduces automated scan traffic."
    fi

    [ -n "$max_tries" ] && [ "$max_tries" -gt 4 ] \
        && warn "MaxAuthTries is $max_tries — consider reducing to 3 to limit brute-force attempts." \
        || ok "MaxAuthTries is ${max_tries:-default} — acceptable."

    pause
}

check_processes() {
    header "All Running Processes"
    desc "Full process tree showing every running process, its owner, and CPU/memory."
    desc "Look for unfamiliar names, especially running as root, or high CPU usage."
    local output
    output=$(ps auxf)
    echo "$output"
    echo

    analysis_header
    # Known miner names
    local miner_names=("xmrig" "minerd" "kdevtmpfsi" "kthreaddi" "sysupdate" "networkservice" "cryptonight")
    local found_miners=0
    for name in "${miner_names[@]}"; do
        local matches
        matches=$(echo "$output" | grep -v grep | grep "$name" || true)
        if [ -n "$matches" ]; then
            flag "Possible miner process found: ${BOLD}$name${RESET}"
            echo "$matches"
            found_miners=1
        fi
    done
    [ "$found_miners" -eq 0 ] && ok "No known crypto miner process names detected."

    # High CPU processes (>50%)
    local high_cpu
    high_cpu=$(echo "$output" | awk 'NR>1 && $3>50 {print $1, $3"% CPU", $11}')
    if [ -n "$high_cpu" ]; then
        warn "Processes using >50% CPU:"
        while IFS= read -r line; do warn "  $line"; done <<< "$high_cpu"
    else
        ok "No processes with unexpectedly high CPU usage."
    fi

    # Processes with no TTY running as non-system users (could be unexpected daemons)
    local unexpected
    unexpected=$(echo "$output" | awk 'NR>1 && $7=="?" && $1!="root" && $1!="www-data" && $1!="systemd+" && $1!="syslog" && $1!="_chrony" && $1!="message+" && $1!="polkitd" && $1!="ubuntu" && $1!="nobody" {print $1, $11}' | sort -u)
    if [ -n "$unexpected" ]; then
        warn "Background processes running as non-standard users (review these):"
        while IFS= read -r line; do info "  $line"; done <<< "$unexpected"
    fi
    pause
}

check_ports() {
    header "Listening Ports"
    desc "Shows all TCP/UDP ports the server is listening on, and which process owns each."
    desc "Any unexpected open port could be a backdoor or rogue service."
    local output
    output=$(ss -tulpn)
    echo "$output"
    echo

    analysis_header
    # Ports exposed on 0.0.0.0 or :: (all interfaces = public)
    local public_ports
    public_ports=$(echo "$output" | grep -E '0\.0\.0\.0:|:::' | grep LISTEN)
    local local_only
    local_only=$(echo "$output" | grep -E '127\.' | grep LISTEN)

    local known_ports=(22 80 443 8080 8443)
    local flagged=0

    while IFS= read -r line; do
        local port
        port=$(echo "$line" | grep -oE ':[0-9]+' | head -1 | tr -d ':')
        local known=0
        for k in "${known_ports[@]}"; do [ "$port" = "$k" ] && known=1 && break; done
        if [ "$known" -eq 0 ] && [ -n "$port" ]; then
            warn "Port ${BOLD}$port${RESET} is publicly exposed — verify this service is intentional."
            flagged=1
        fi
    done <<< "$public_ports"

    [ "$flagged" -eq 0 ] && ok "All publicly exposed ports are in the expected set (22, 80, 443)."

    local lcount
    lcount=$(echo "$local_only" | grep -c '.' 2>/dev/null || true)
    [ "$lcount" -gt 0 ] && ok "$lcount port(s) listening on localhost only — not exposed externally."

    # Check for anything on suspicious high ports
    local high_ports
    high_ports=$(echo "$output" | grep LISTEN | grep -oE ':[0-9]+' | tr -d ':' | awk '$1>10000 && $1!=65535')
    [ -n "$high_ports" ] && warn "High port(s) listening: $high_ports — verify these are expected." \
        || ok "No unexpected high-numbered ports detected."
    pause
}

check_outbound() {
    header "Established Outbound Connections"
    desc "Shows active connections your server has opened to external hosts."
    desc "Malware (especially crypto miners) maintains persistent outbound connections."
    local output
    output=$(ss -tupn state established 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local conn_count
    conn_count=$(echo "$output" | grep -c 'ESTAB' || true)

    if [ "$conn_count" -eq 0 ]; then
        ok "No established outbound connections — clean."
    else
        info "$conn_count established connection(s)."
        # Flag known miner pool ports
        local miner_ports=(3333 4444 14444 45700 5555 7777 9999 3032)
        for p in "${miner_ports[@]}"; do
            local hit
            hit=$(echo "$output" | grep ":$p" || true)
            [ -n "$hit" ] && flag "Connection on port $p — known crypto mining pool port!" && echo "$hit"
        done

        # Show unique remote IPs
        local remote_ips
        remote_ips=$(echo "$output" | grep ESTAB | awk '{print $6}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
        if [ -n "$remote_ips" ]; then
            info "Remote IPs with active connections:"
            while IFS= read -r ip; do
                # Flag private RFC1918 ranges talking back as unexpected
                if echo "$ip" | grep -qE '^(169\.254\.|100\.[6-9][0-9]\.|100\.1[0-2][0-9]\.)'; then
                    info "  ${BOLD}$ip${RESET} (link-local / AWS metadata — expected)"
                else
                    info "  ${BOLD}$ip${RESET} — verify this destination is expected"
                fi
            done <<< "$remote_ips"
        fi
    fi
    pause
}

check_enabled_services() {
    header "Enabled Systemd Services"
    desc "Lists all services configured to start at boot."
    desc "Malware often installs itself as a service to survive reboots."
    local output
    output=$(systemctl list-unit-files --state=enabled 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c 'enabled' || true)
    info "$count enabled service(s) total."

    # Known legitimate Ubuntu/AWS services
    local known_services=("ssh" "cron" "nginx" "apache2" "ufw" "rsyslog" "chrony" "snapd"
        "systemd-" "dbus" "NetworkManager" "networkd" "resolved" "logind" "udevd"
        "multipathd" "unattended-upgrades" "ModemManager" "polkit" "udisks2"
        "amazon-ssm" "cloud-" "iscsid" "open-iscsi" "irqbalance" "acpid"
        "apparmor" "apport" "grub" "plymouth" "procps" "rsync" "sysstat"
        "uuidd" "hibagent" "open-vm-tools" "screen-cleanup")

    local suspicious=0
    while IFS= read -r line; do
        local svc
        svc=$(echo "$line" | awk '{print $1}' | sed 's/\.service$//')
        [ -z "$svc" ] || [[ "$svc" == "UNIT" ]] && continue
        local known=0
        for k in "${known_services[@]}"; do
            [[ "$svc" == *"$k"* ]] && known=1 && break
        done
        if [ "$known" -eq 0 ]; then
            warn "Unfamiliar enabled service: ${BOLD}$svc${RESET} — verify this is intentional."
            suspicious=1
        fi
    done <<< "$(echo "$output" | grep 'enabled')"

    [ "$suspicious" -eq 0 ] && ok "All enabled services match known Ubuntu/AWS defaults."
    pause
}

check_running_services() {
    header "Currently Running Services"
    desc "Lists only services that are active right now."
    local output
    output=$(systemctl list-units --type=service --state=running 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c 'running' || true)
    ok "$count service(s) currently running."
    info "Cross-reference with your expected stack. If you only run nginx, there should be no mysql, redis, or other unexpected daemons active."
    pause
}

check_crontabs() {
    header "Crontabs (All Users)"
    desc "Scans scheduled tasks for every user on the system."
    desc "Crypto miners and other malware commonly use cron for persistence."
    local all_crons=""
    local found=0

    for u in $(cut -f1 -d: /etc/passwd); do
        local CRON
        CRON=$(crontab -u "$u" -l 2>/dev/null | grep -v '^#')
        if [ -n "$CRON" ]; then
            echo -e "${GREEN}[user: $u]${RESET}"
            echo "$CRON"
            echo
            all_crons="${all_crons}\n${CRON}"
            found=1
        fi
    done
    [ "$found" -eq 0 ] && echo "(no user crontabs found)"
    echo
    desc "System-wide cron directories:"
    ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null
    echo

    analysis_header
    if [ "$found" -eq 0 ]; then
        ok "No user crontabs found — clean."
    else
        # Look for suspicious patterns in cron entries
        local suspicious_patterns=("curl" "wget" "bash -i" "/tmp/" "/dev/shm" "chmod" "base64" "python -c" "perl -e" "|bash" "|sh")
        local flagged=0
        for pat in "${suspicious_patterns[@]}"; do
            if echo -e "$all_crons" | grep -q "$pat"; then
                flag "Crontab contains suspicious pattern: ${BOLD}${pat}${RESET}"
                flagged=1
            fi
        done
        [ "$flagged" -eq 0 ] && ok "No obviously suspicious commands in crontabs." \
            || info "Review the crontab entries above carefully."
    fi
    pause
}

check_startup_scripts() {
    header "Startup Scripts"
    desc "Lists legacy SysV init scripts and their runlevel symlinks."
    run "ls -la /etc/init.d/"
    run "ls -la /etc/rc2.d/"

    analysis_header
    local init_scripts
    init_scripts=$(ls /etc/init.d/)
    local known=("acpid" "apparmor" "apport" "chrony" "console-setup.sh" "cron"
        "cryptdisks" "cryptdisks-early" "dbus" "grub-common" "hibagent"
        "irqbalance" "iscsid" "keyboard-setup.sh" "kmod" "nginx" "open-iscsi"
        "open-vm-tools" "plymouth" "plymouth-log" "procps" "rsync"
        "screen-cleanup" "ssh" "sysstat" "ufw" "unattended-upgrades" "uuidd")
    local flagged=0
    while IFS= read -r script; do
        local k=0
        for kn in "${known[@]}"; do [ "$script" = "$kn" ] && k=1 && break; done
        [ "$k" -eq 0 ] && warn "Unfamiliar init.d script: ${BOLD}$script${RESET}" && flagged=1
    done <<< "$init_scripts"
    [ "$flagged" -eq 0 ] && ok "All init.d scripts match known Ubuntu defaults."
    pause
}

check_shell_users() {
    header "Users With Shell Access"
    desc "Lists accounts that can run interactive commands (bash/sh)."
    local output
    output=$(grep -v '/nologin\|/false' /etc/passwd)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c '.' || true)
    local non_system
    non_system=$(echo "$output" | awk -F: '$3>=1000 && $1!="nobody" {print $1}')
    local system_shell
    system_shell=$(echo "$output" | awk -F: '$3<1000 && $3>0 && ($7=="/bin/bash" || $7=="/bin/sh") {print $1}')

    info "$count account(s) with a shell (including system accounts like root, sync)."
    if [ -n "$non_system" ]; then
        ok "Human user account(s) with shell access (UID ≥ 1000):"
        while IFS= read -r u; do info "  ${BOLD}$u${RESET}"; done <<< "$non_system"
    fi
    if [ -n "$system_shell" ]; then
        warn "System account(s) with a real shell (review these):"
        while IFS= read -r u; do warn "  ${BOLD}$u${RESET}"; done <<< "$system_shell"
    else
        ok "No unexpected system accounts with interactive shell access."
    fi
    pause
}

check_root_uid() {
    header "Users With UID 0 (root-level)"
    desc "Only the 'root' account should have UID 0."
    local output
    output=$(awk -F: '$3==0' /etc/passwd)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c '.' || true)
    if [ "$count" -eq 1 ] && echo "$output" | grep -q '^root:'; then
        ok "Only 'root' has UID 0 — expected."
    elif [ "$count" -eq 0 ]; then
        warn "No UID 0 account found — unusual, root may have been renamed."
    else
        flag "$count accounts with UID 0 detected! Only 'root' should have UID 0."
        flag "Extra UID 0 accounts are a classic attacker backdoor — investigate immediately."
        echo "$output" | grep -v '^root:' | while IFS= read -r line; do
            flag "  Suspicious: $line"
        done
    fi
    pause
}

check_sudoers() {
    header "Sudoers Configuration"
    desc "Shows who can run commands as root via sudo."
    run "sudo cat /etc/sudoers"
    echo -e "${GREEN}\$ sudo ls /etc/sudoers.d/${RESET}"
    sudo ls /etc/sudoers.d/ 2>/dev/null
    echo

    analysis_header
    local sudoers_content
    sudoers_content=$(sudo cat /etc/sudoers 2>/dev/null)
    local nopasswd
    nopasswd=$(echo "$sudoers_content" | grep 'NOPASSWD' | grep -v '^#' || true)
    local all_all
    all_all=$(echo "$sudoers_content" | grep 'ALL=(ALL' | grep -v '^#' || true)
    local sudod_files
    sudod_files=$(sudo ls /etc/sudoers.d/ 2>/dev/null | grep -v README || true)

    [ -n "$nopasswd" ] && warn "NOPASSWD entries found — these users can sudo without a password:" \
        && while IFS= read -r l; do warn "  $l"; done <<< "$nopasswd" \
        || ok "No NOPASSWD entries — sudo requires a password."

    [ -n "$all_all" ] && info "Full sudo access entries (ALL=(ALL)):" \
        && while IFS= read -r l; do info "  $l"; done <<< "$all_all"

    if [ -n "$sudod_files" ]; then
        info "Files in /etc/sudoers.d/ (each grants additional sudo rules):"
        while IFS= read -r f; do info "  $f"; done <<< "$sudod_files"
    else
        ok "No additional sudoers.d files."
    fi
    pause
}

check_suid() {
    header "SUID Binaries"
    desc "Finds executables with the setuid bit — they run as their owner (often root)."
    local output
    output=$(find / -perm -4000 -type f 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c '.' || true)
    info "$count SUID binaries found."

    # Known legitimate SUID binaries on Ubuntu
    local known_suid=("sudo" "su" "passwd" "newgrp" "gpasswd" "chsh" "chfn"
        "mount" "umount" "ping" "ping6" "traceroute6" "at" "crontab"
        "pkexec" "fusermount" "fusermount3" "ssh-keysign" "Xorg"
        "vmware-user-suid-wrapper" "unix_chkpwd" "pam_timestamp_check"
        "newuidmap" "newgidmap" "snap" "ntfs-3g" "polkit")

    local flagged=0
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        local base
        base=$(basename "$path")
        local known=0
        for k in "${known_suid[@]}"; do [ "$base" = "$k" ] && known=1 && break; done
        if [ "$known" -eq 0 ]; then
            flag "Unexpected SUID binary: ${BOLD}$path${RESET}"
            flagged=1
        fi
    done <<< "$output"
    [ "$flagged" -eq 0 ] && ok "All SUID binaries are in the known-legitimate set."
    pause
}

check_etc_modified() {
    header "Recently Modified /etc Files (last 7 days)"
    desc "Config files changed after your initial setup date may have been tampered with."
    local output
    output=$(find /etc -mtime -7 -type f 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c '.' || true)
    info "$count file(s) in /etc modified in the last 7 days."

    # Flag high-sensitivity files
    local sensitive=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config"
        "/etc/crontab" "/etc/hosts" "/etc/ld.so.preload" "/etc/pam.d/sshd"
        "/etc/pam.d/sudo" "/etc/profile" "/etc/bash.bashrc" "/etc/environment")
    local flagged=0
    for f in "${sensitive[@]}"; do
        if echo "$output" | grep -q "^${f}$"; then
            warn "Sensitive file was recently modified: ${BOLD}$f${RESET} — verify this change was intentional."
            flagged=1
        fi
    done

    # /etc/ld.so.preload is a classic rootkit trick
    if echo "$output" | grep -q 'ld.so.preload'; then
        flag "/etc/ld.so.preload was modified — this file is used by rootkits to inject malicious libraries!"
    fi

    [ "$flagged" -eq 0 ] && ok "No high-sensitivity config files were recently modified."
    pause
}

check_bin_modified() {
    header "Recently Modified System Binaries (last 30 days)"
    desc "Rootkits replace system binaries with versions that hide attacker activity."
    local output
    output=$(find /usr/bin /usr/sbin /bin /sbin -mtime -30 -type f 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c '.' || true)

    if [ "$count" -eq 0 ]; then
        ok "No system binaries modified in the last 30 days."
    else
        info "$count binary/binaries modified in the last 30 days."
        # If there were recent apt upgrades this is expected — check dpkg log
        local apt_upgrades
        apt_upgrades=$(grep 'upgrade\|install' /var/log/dpkg.log 2>/dev/null | tail -5)
        if [ -n "$apt_upgrades" ]; then
            ok "Recent apt activity found — binary changes are likely from package upgrades."
            info "Last apt operations:"
            while IFS= read -r line; do info "  $line"; done <<< "$apt_upgrades"
        else
            warn "No recent apt activity found but binaries were modified — investigate manually."
            flag "Check each binary with: dpkg -S <binary_path> to confirm it belongs to a package."
        fi
        # Flag specific high-risk binaries if modified
        local risky=("ps" "ls" "netstat" "ss" "top" "find" "who" "w" "last" "login" "sshd" "cron")
        while IFS= read -r f; do
            local base; base=$(basename "$f")
            for r in "${risky[@]}"; do
                [ "$base" = "$r" ] && flag "High-risk binary modified: ${BOLD}$f${RESET} — rootkits commonly replace this." && break
            done
        done <<< "$output"
    fi
    pause
}

check_tmp_hidden() {
    header "Hidden Files in /tmp and /var/tmp"
    desc "/tmp and /var/tmp are world-writable drop zones for malware."
    local hidden
    hidden=$(find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null)
    echo -e "${GREEN}\$ find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null${RESET}"
    [ -n "$hidden" ] && echo "$hidden" || echo "(none found)"
    echo
    run "ls -la /tmp /var/tmp"

    analysis_header
    if [ -z "$hidden" ]; then
        ok "No hidden files in /tmp, /var/tmp, or /dev/shm — clean."
    else
        flag "Hidden files found:"
        while IFS= read -r f; do
            flag "  ${BOLD}$f${RESET}"
            # Check if executable
            [ -x "$f" ] && flag "  ^^^ This file is EXECUTABLE — high suspicion of malware."
        done <<< "$hidden"
    fi

    # Check for executable files in /tmp regardless of hidden status
    local exec_tmp
    exec_tmp=$(find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null | grep -v '\.sh$' || true)
    if [ -n "$exec_tmp" ]; then
        flag "Executable binaries found in /tmp or /dev/shm (common malware location):"
        while IFS= read -r f; do flag "  ${BOLD}$f${RESET}"; done <<< "$exec_tmp"
    else
        ok "No unexpected executable binaries in /tmp or /dev/shm."
    fi
    pause
}

check_rkhunter() {
    header "rkhunter — Rootkit Hunter"
    desc "Scans for known rootkits, backdoors, and suspicious file properties."
    sudo apt install rkhunter -y -q
    run "sudo rkhunter --update"
    echo -e "${GREEN}\$ sudo rkhunter --check --sk${RESET}"
    local output
    output=$(sudo rkhunter --check --sk 2>&1)
    echo "$output" | grep -E 'Warning|Found|Infected|OK'
    echo

    analysis_header
    local warnings infections
    warnings=$(echo "$output" | grep -c 'Warning' || true)
    infections=$(echo "$output" | grep -c 'Infected' || true)
    [ "$infections" -gt 0 ] && flag "$infections infection(s) found by rkhunter — investigate immediately!" \
        || ok "No infections detected by rkhunter."
    [ "$warnings" -gt 0 ] && warn "$warnings warning(s) from rkhunter — review output above." \
        || ok "No warnings from rkhunter."
    pause
}

check_chkrootkit() {
    header "chkrootkit"
    desc "A second rootkit scanner with different detection signatures."
    sudo apt install chkrootkit -y -q
    local output
    output=$(sudo chkrootkit 2>&1)
    echo "$output" | grep -v 'not found\|not tested'
    echo

    analysis_header
    local infected
    infected=$(echo "$output" | grep 'INFECTED' || true)
    [ -n "$infected" ] && flag "chkrootkit found INFECTED entries:" \
        && while IFS= read -r l; do flag "  $l"; done <<< "$infected" \
        || ok "chkrootkit found no infections."
    pause
}

check_clamav() {
    header "ClamAV Malware Scanner"
    desc "Scans /home, /var/www, and /tmp for known malware signatures."
    sudo apt install clamav -y -q
    run "sudo freshclam"
    local output
    output=$(sudo clamscan -r /home /var/www /tmp --remove=yes 2>&1)
    echo "$output"
    echo

    analysis_header
    local infected
    infected=$(echo "$output" | grep 'Infected files:' | awk '{print $3}')
    [ "$infected" = "0" ] || [ -z "$infected" ] \
        && ok "ClamAV found no infected files." \
        || flag "ClamAV found ${BOLD}$infected${RESET} infected file(s) — check output above for details."
    pause
}

check_miners() {
    header "Crypto Miner Detection"
    desc "Looks for known miner process names, binaries, and network connections."
    echo -e "${GREEN}\$ ps aux --sort=-%cpu | head -20${RESET}"
    local ps_out
    ps_out=$(ps aux --sort=-%cpu | head -20)
    echo "$ps_out"
    echo
    desc "Scanning for known miner binary names..."
    local find_out
    find_out=$(find / -name 'xmrig' -o -name 'minerd' -o -name 'kdevtmpfsi' -o -name 'kthreaddi' -o -name 'sysupdate' 2>/dev/null)
    [ -n "$find_out" ] && echo "$find_out" || echo "(none found)"
    echo
    desc "Checking for miner pool ports..."
    local net_out
    net_out=$(ss -tupn | grep -E ':3333|:4444|:14444|:45700|:5555' || true)
    [ -n "$net_out" ] && echo "$net_out" || echo "(none found)"
    echo

    analysis_header
    local flagged=0
    local miner_names=("xmrig" "minerd" "kdevtmpfsi" "kthreaddi" "sysupdate" "cryptonight" "kdevtmpfs ")
    for name in "${miner_names[@]}"; do
        echo "$ps_out" | grep -v grep | grep -q "$name" \
            && flag "Miner process name ${BOLD}$name${RESET} found in process list!" && flagged=1
    done
    [ -n "$find_out" ] && flag "Miner binary found on disk: $find_out" && flagged=1
    [ -n "$net_out" ] && flag "Active connection on a known mining pool port!" && flagged=1

    # Check CPU — miners always spike it
    local top_cpu
    top_cpu=$(echo "$ps_out" | awk 'NR>1 && $3>80 {print $1, $3"% CPU", $11}')
    [ -n "$top_cpu" ] && warn "Process(es) using >80% CPU — miners will always appear here:" \
        && while IFS= read -r l; do warn "  $l"; done <<< "$top_cpu"

    [ "$flagged" -eq 0 ] && ok "No crypto miner indicators detected — clean."
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
    echo -e "${GREEN}${BOLD}All checks complete. Run scanner options separately to install malware scanners.${RESET}"
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
