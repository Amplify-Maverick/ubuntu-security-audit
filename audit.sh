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

divider()         { echo -e "${CYAN}────────────────────────────────────────────────────${RESET}"; }
header()          { clear; echo -e "\n${BOLD}${CYAN}$1${RESET}"; divider; }
desc()            { echo -e "${AMBER}▸ $1${RESET}"; }
run()             { echo -e "${GREEN}\$ $1${RESET}"; eval "$1"; echo; }
pause()           { echo -e "\n${DIM}Press Enter to return to menu...${RESET}"; read -r; }
analysis_header() { echo -e "\n${BOLD}${CYAN}── Analysis ────────────────────────────────────────${RESET}"; }
flag()            { echo -e "  ${RED}${BOLD}[!]${RESET} $1";   RISK_FLAGS=$(( RISK_FLAGS + 1 )); }
warn()            { echo -e "  ${AMBER}${BOLD}[~]${RESET} $1"; RISK_WARNS=$(( RISK_WARNS + 1 )); }
ok()              { echo -e "  ${GREEN}${BOLD}[✓]${RESET} $1"; }
info()            { echo -e "  ${CYAN}[-]${RESET} $1"; }
fix()             { echo -e "    ${DIM}↳ fix: $1${RESET}"; }  # actionable remediation hint

# Global risk counters (accumulated across run_all)
RISK_FLAGS=0
RISK_WARNS=0

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
    local output
    output=$(w)
    echo "$output"
    echo

    analysis_header
    # Parse session lines (skip header rows)
    local sessions
    sessions=$(echo "$output" | tail -n +3 | grep -v '^$' || true)
    local session_count
    session_count=$(echo "$sessions" | grep -c '.' 2>/dev/null || echo 0)

    # Root sessions
    local root_sessions
    root_sessions=$(echo "$sessions" | awk '$1=="root"' || true)
    if [ -n "$root_sessions" ]; then
        flag "Root is directly logged in — root should not have interactive SSH sessions."
        fix "Disable root SSH: set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: sudo systemctl restart ssh"
    else
        ok "No direct root sessions."
    fi

    # Unexpected users (anyone other than expected ubuntu/admin user)
    local current_user
    current_user=$(whoami)
    local unexpected_users
    unexpected_users=$(echo "$sessions" | awk -v u="$current_user" '$1 != u && $1 != "root" {print $1}' | sort -u || true)
    if [ -n "$unexpected_users" ]; then
        flag "Unexpected user(s) currently logged in:"
        while IFS= read -r u; do
            flag "  User: ${BOLD}$u${RESET}"
            fix "Terminate their sessions: sudo pkill -u $u && sudo passwd -l $u"
        done <<< "$unexpected_users"
    else
        ok "Only expected user(s) are logged in."
    fi

    # Sessions from multiple distinct IPs simultaneously
    local active_ips
    active_ips=$(echo "$sessions" | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
    local ip_count
    ip_count=$(echo "$active_ips" | grep -c '.' 2>/dev/null || echo 0)
    if [ "$ip_count" -gt 1 ]; then
        warn "$ip_count different IPs have active sessions simultaneously:"
        while IFS= read -r ip; do warn "  ${BOLD}$ip${RESET}"; done <<< "$active_ips"
        fix "If any IP is unrecognised, kill their session: sudo pkill -9 -u <user>"
    elif [ "$ip_count" -eq 1 ]; then
        ok "All active sessions from a single IP: ${BOLD}$(echo "$active_ips")${RESET}"
    fi

    # Long-running sessions (idle > 1 hour — column 5 is IDLE in w output)
    local idle_sessions
    idle_sessions=$(echo "$sessions" | awk '$5 ~ /^[0-9]+:[0-9]+/ && substr($5,1,2)+0 >= 1 {print $1, $3, "idle", $5}' || true)
    [ -n "$idle_sessions" ] && warn "Long-idle session(s) detected (may be a forgotten open connection):" \
        && while IFS= read -r l; do warn "  $l"; done <<< "$idle_sessions"

    pause
}

check_login_history() {
    header "Recent Login History"
    desc "Lists the last 20 logins with timestamps and source IP addresses."
    local output
    output=$(last -n 20)
    echo "$output"
    echo

    analysis_header
    # Extract IPs and timestamps from successful logins
    local login_lines
    login_lines=$(echo "$output" | grep -v 'reboot\|wtmp\|^$' | head -20)

    local unique_ips
    unique_ips=$(echo "$login_lines" | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
    local ip_count
    ip_count=$(echo "$unique_ips" | grep -c '.' 2>/dev/null || echo 0)

    # Unusual hours — logins between midnight and 5am
    local odd_hour_logins
    odd_hour_logins=$(echo "$login_lines" | awk '{
        for(i=1;i<=NF;i++) if($i ~ /^[0-2][0-9]:[0-5][0-9]$/) {
            h=substr($i,1,2)+0
            if(h>=0 && h<5) print $0
        }
    }' || true)

    # Multiple IPs
    if [ "$ip_count" -eq 0 ]; then
        ok "No external IP logins in this sample (key-based or local logins only)."
    elif [ "$ip_count" -eq 1 ]; then
        ok "All logins from a single IP address: ${BOLD}$(echo "$unique_ips")${RESET} — consistent with one admin location."
    elif [ "$ip_count" -le 3 ]; then
        warn "$ip_count distinct source IPs — expected if you connect from multiple locations, suspicious otherwise:"
        while IFS= read -r ip; do info "  ${BOLD}$ip${RESET}"; done <<< "$unique_ips"
    else
        flag "$ip_count distinct source IPs in recent login history — unusually high."
        fix "Review each IP. Block unknowns with: sudo ufw deny from <ip>"
        while IFS= read -r ip; do info "  ${BOLD}$ip${RESET}"; done <<< "$unique_ips"
    fi

    # Off-hours logins
    if [ -n "$odd_hour_logins" ]; then
        warn "Login(s) detected between midnight and 5am — verify these were you:"
        while IFS= read -r l; do warn "  $l"; done <<< "$odd_hour_logins"
        fix "If unexpected, check accepted logins immediately: grep 'Accepted' /var/log/auth.log"
    else
        ok "No logins detected during unusual hours (midnight–5am)."
    fi

    # Rapid consecutive reboots
    local reboot_count
    reboot_count=$(echo "$output" | grep -c 'reboot' || echo 0)
    if [ "$reboot_count" -ge 5 ]; then
        warn "$reboot_count reboots in recent history — could indicate crashes, OOM kills, or an attacker rebooting to clear state."
        fix "Check kernel logs for OOM or panic: sudo journalctl -k -b -1 | tail -30"
    fi

    pause
}

check_failed_logins() {
    header "Failed Login Attempts"
    desc "Scans auth.log for failed SSH password attempts."
    local output
    output=$(grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -30)
    [ -n "$output" ] && echo "$output" || echo "(no failed password attempts in auth.log)"
    echo

    analysis_header
    local total
    total=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0)

    # Top attacking IPs with counts
    local top_ips
    top_ips=$(grep 'Failed password' /var/log/auth.log 2>/dev/null \
        | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
        | awk '{print $2}' | sort | uniq -c | sort -rn | head -5)

    # Most targeted usernames
    local top_users
    top_users=$(grep 'Failed password' /var/log/auth.log 2>/dev/null \
        | grep -oP '(?<=for (invalid user )?)\S+(?= from)' \
        | sort | uniq -c | sort -rn | head -5)

    # Assess severity
    if [ "$total" -eq 0 ]; then
        ok "No failed login attempts on record."
    elif [ "$total" -lt 50 ]; then
        ok "$total failed attempt(s) — low noise level, likely just background internet scanning."
    elif [ "$total" -lt 500 ]; then
        warn "$total failed attempts — moderate. Your server is being probed."
        fix "Install fail2ban to auto-block repeat offenders: sudo apt install fail2ban -y"
    else
        flag "$total failed attempts — your server is under sustained brute-force attack."
        fix "Immediately install fail2ban: sudo apt install fail2ban -y && sudo systemctl enable --now fail2ban"
        fix "Also disable password auth entirely: set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
    fi

    # Per-IP breakdown
    if [ -n "$top_ips" ]; then
        info "Top attacking IPs:"
        while IFS= read -r line; do
            local count ip
            count=$(echo "$line" | awk '{print $1}')
            ip=$(echo "$line" | awk '{print $2}')
            if [ "$count" -gt 100 ]; then
                flag "  ${BOLD}$count${RESET} attempts from ${BOLD}$ip${RESET}"
                fix "  Block now: sudo ufw deny from $ip to any && sudo ufw reload"
            elif [ "$count" -gt 20 ]; then
                warn "  ${BOLD}$count${RESET} attempts from ${BOLD}$ip${RESET}"
            else
                info "  $count attempts from $ip"
            fi
        done <<< "$top_ips"
    fi

    # Invalid usernames being tried — indicates credential stuffing
    if [ -n "$top_users" ]; then
        local invalid_count
        invalid_count=$(grep 'invalid user' /var/log/auth.log 2>/dev/null | wc -l)
        if [ "$invalid_count" -gt 10 ]; then
            warn "$invalid_count attempts for non-existent usernames — credential stuffing or user enumeration."
            info "Most targeted usernames (real and invalid):"
        else
            info "Most targeted usernames:"
        fi
        while IFS= read -r line; do
            info "  $(echo "$line" | awk '{print $1}') attempts → user '$(echo "$line" | awk '{print $2}')'"
        done <<< "$top_users"
    fi

    # Check if fail2ban is already running
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        ok "fail2ban is active — repeat offenders are being automatically blocked."
        local banned
        banned=$(sudo fail2ban-client status sshd 2>/dev/null | grep 'Banned IP' | awk -F: '{print $2}' | xargs)
        [ -n "$banned" ] && info "Currently banned IPs: $banned"
    else
        warn "fail2ban is not running — failed logins are not being automatically blocked."
        fix "sudo apt install fail2ban -y && sudo systemctl enable --now fail2ban"
    fi

    pause
}

check_accepted_logins() {
    header "Successful Logins"
    desc "Shows SSH logins that were accepted. Any login you did not initiate is an intruder."
    local output
    output=$(grep 'Accepted' /var/log/auth.log 2>/dev/null | tail -20)
    [ -n "$output" ] && echo "$output" || echo "(no accepted logins in auth.log)"
    echo

    analysis_header
    local total
    total=$(grep -c 'Accepted' /var/log/auth.log 2>/dev/null || echo 0)
    local pw_logins
    pw_logins=$(grep -c 'Accepted password' /var/log/auth.log 2>/dev/null || echo 0)
    local key_logins
    key_logins=$(grep -c 'Accepted publickey' /var/log/auth.log 2>/dev/null || echo 0)
    local root_logins
    root_logins=$(grep 'Accepted' /var/log/auth.log 2>/dev/null | grep 'for root' || true)

    # Auth method breakdown
    [ "$key_logins" -gt 0 ] && ok "$key_logins login(s) via SSH public key (most secure method)."
    if [ "$pw_logins" -gt 0 ]; then
        flag "$pw_logins login(s) authenticated via password — passwords are vulnerable to brute-force."
        fix "Disable password auth: set 'PasswordAuthentication no' in /etc/ssh/sshd_config, then restart ssh"
    fi

    # Root logins
    if [ -n "$root_logins" ]; then
        flag "Direct root login(s) detected — attackers always target root first."
        fix "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: sudo systemctl restart ssh"
        while IFS= read -r l; do flag "  $l"; done <<< "$root_logins"
    else
        ok "No direct root logins on record."
    fi

    # Source IP analysis — flag if more than expected distinct IPs
    local all_ips
    all_ips=$(grep 'Accepted' /var/log/auth.log 2>/dev/null \
        | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort -u)
    local ip_count
    ip_count=$(echo "$all_ips" | grep -c '.' 2>/dev/null || echo 0)

    if [ "$ip_count" -eq 0 ]; then
        [ "$total" -gt 0 ] && info "No external IPs found — logins may be from localhost or internal network."
    elif [ "$ip_count" -eq 1 ]; then
        ok "All successful logins from a single IP: ${BOLD}$(echo "$all_ips")${RESET}"
    else
        warn "$ip_count distinct IPs have successfully logged in — verify every one of these:"
        while IFS= read -r ip; do
            warn "  ${BOLD}$ip${RESET}"
            fix "  Restrict SSH to known IPs: sudo ufw allow from $ip to any port 22"
        done <<< "$all_ips"
        fix "After allowlisting your IP, block all others: sudo ufw deny 22"
    fi

    # Recent logins in the last hour (timestamps in auth.log — approximate)
    local recent
    recent=$(grep 'Accepted' /var/log/auth.log 2>/dev/null | tail -5)
    if [ -n "$recent" ]; then
        info "5 most recent successful logins:"
        while IFS= read -r l; do info "  $l"; done <<< "$recent"
    fi

    pause
}

check_ssh_keys() {
    header "Authorized SSH Keys"
    desc "Lists public keys permitted to log in. Any unrecognised key is a backdoor."

    local user_keys root_keys
    user_keys=$(cat ~/.ssh/authorized_keys 2>/dev/null || true)
    root_keys=$(sudo cat /root/.ssh/authorized_keys 2>/dev/null || true)

    echo -e "${GREEN}\$ cat ~/.ssh/authorized_keys${RESET}"
    [ -n "$user_keys" ] && echo "$user_keys" || echo "(none)"
    echo
    echo -e "${GREEN}\$ sudo cat /root/.ssh/authorized_keys${RESET}"
    [ -n "$root_keys" ] && echo "$root_keys" || echo "(none)"
    echo

    analysis_header

    # Analyse each key: type, bits, comment
    _analyse_keys() {
        local label="$1" keys="$2"
        local count
        count=$(echo "$keys" | grep -cE '^(ssh-|ecdsa-|sk-)' 2>/dev/null || echo 0)
        [ "$count" -eq 0 ] && ok "No authorized keys for $label." && return

        ok "$count authorized key(s) for $label:"
        while IFS= read -r keyline; do
            [[ "$keyline" =~ ^(ssh-|ecdsa-|sk-) ]] || continue
            local keytype comment
            keytype=$(echo "$keyline" | awk '{print $1}')
            comment=$(echo "$keyline" | awk '{print $3}')
            [ -z "$comment" ] && comment="(no comment)"

            case "$keytype" in
                ssh-ed25519|sk-ssh-ed25519*)
                    ok "  ${BOLD}$comment${RESET} — Ed25519 key (modern, strong)" ;;
                ecdsa-sha2-*|sk-ecdsa-*)
                    ok "  ${BOLD}$comment${RESET} — ECDSA key (good)" ;;
                ssh-rsa)
                    # Try to get key length
                    local bits
                    bits=$(echo "$keyline" | ssh-keygen -l -f /dev/stdin 2>/dev/null | awk '{print $1}' || echo "?")
                    if [ "$bits" != "?" ] && [ "$bits" -lt 2048 ] 2>/dev/null; then
                        flag "  ${BOLD}$comment${RESET} — RSA key only ${BOLD}${bits}-bit${RESET} (too weak, must be ≥2048)"
                        fix "  Regenerate: ssh-keygen -t ed25519 -C 'your@email'"
                    elif [ "$bits" != "?" ] && [ "$bits" -lt 4096 ] 2>/dev/null; then
                        warn "  ${BOLD}$comment${RESET} — RSA ${bits}-bit (acceptable, but Ed25519 is preferred)"
                    else
                        ok "  ${BOLD}$comment${RESET} — RSA key"
                    fi
                    ;;
                ssh-dss)
                    flag "  ${BOLD}$comment${RESET} — DSA key (${BOLD}obsolete and broken${RESET}, remove immediately)"
                    fix "  Remove this key and regenerate: ssh-keygen -t ed25519 -C 'your@email'" ;;
                *)
                    warn "  ${BOLD}$comment${RESET} — unknown key type: $keytype" ;;
            esac
        done <<< "$keys"

        # Warn if no comment — makes keys hard to audit
        local no_comment
        no_comment=$(echo "$keys" | grep -cE '^(ssh-|ecdsa-|sk-)[^ ]+ [^ ]+$' 2>/dev/null || echo 0)
        [ "$no_comment" -gt 0 ] && warn "  $no_comment key(s) have no comment — add comments so you can identify which device each key belongs to."
    }

    _analyse_keys "current user ($(whoami))" "$user_keys"
    echo
    if [ -n "$root_keys" ]; then
        flag "Root has authorized SSH keys — direct root login via key is possible."
        fix "Remove root keys and use sudo instead: sudo rm /root/.ssh/authorized_keys"
        _analyse_keys "root" "$root_keys"
    else
        ok "No authorized keys for root."
    fi

    # Check for keys in unusual home directories
    local other_keys
    other_keys=$(sudo find /home -name authorized_keys 2>/dev/null | grep -v "$(whoami)" || true)
    if [ -n "$other_keys" ]; then
        info "authorized_keys files found for other users:"
        while IFS= read -r f; do
            local kcount
            kcount=$(sudo grep -cE '^(ssh-|ecdsa-|sk-)' "$f" 2>/dev/null || echo 0)
            info "  $f ($kcount key(s))"
        done <<< "$other_keys"
    fi

    pause
}

check_ssh_config() {
    header "SSH Daemon Configuration"
    desc "Reviews sshd settings for security misconfigurations."
    local output
    output=$(sudo sshd -T 2>/dev/null)
    echo "$output" | grep -E 'permitrootlogin|passwordauth|port|pubkeyauth|maxauthtries|logingracetime|permitemptypasswords|x11forwarding|allowtcpforwarding|clientaliveinterval|banner'
    echo

    analysis_header
    _val() { echo "$output" | grep "^$1 " | awk '{print $2}'; }

    local root_login;    root_login=$(_val permitrootlogin)
    local pw_auth;       pw_auth=$(_val passwordauthentication)
    local port;          port=$(_val port)
    local pubkey;        pubkey=$(_val pubkeyauthentication)
    local max_tries;     max_tries=$(_val maxauthtries)
    local grace;         grace=$(_val logingracetime)
    local empty_pw;      empty_pw=$(_val permitemptypasswords)
    local x11;           x11=$(_val x11forwarding)
    local tcp_fwd;       tcp_fwd=$(_val allowtcpforwarding)
    local alive;         alive=$(_val clientaliveinterval)
    local banner;        banner=$(_val banner)

    # Root login
    case "$root_login" in
        no)                 ok "PermitRootLogin no — root cannot log in over SSH." ;;
        yes)                flag "PermitRootLogin yes — root can log in with a password over SSH."
                            fix "Set 'PermitRootLogin no' in /etc/ssh/sshd_config" ;;
        prohibit-password)  warn "PermitRootLogin prohibit-password — root can log in with an SSH key."
                            fix "Set 'PermitRootLogin no' unless you specifically need root key access." ;;
        forced-commands-only) info "PermitRootLogin forced-commands-only — root access limited to specific commands." ;;
    esac

    # Password auth
    case "$pw_auth" in
        no)  ok "PasswordAuthentication no — only SSH keys accepted (most secure)." ;;
        yes) flag "PasswordAuthentication yes — password logins allowed, enabling brute-force attacks."
             fix "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config, ensure your key is in authorized_keys first." ;;
    esac

    # Empty passwords
    [ "$empty_pw" = "yes" ] && flag "PermitEmptyPasswords yes — accounts with no password can log in!" \
        && fix "Set 'PermitEmptyPasswords no' immediately."

    # Public key auth
    [ "$pubkey" = "no" ] && flag "PubkeyAuthentication is disabled — SSH key login won't work." \
        && fix "Set 'PubkeyAuthentication yes'" \
        || ok "PubkeyAuthentication yes — SSH key login enabled."

    # Port
    if [ "$port" = "22" ]; then
        warn "SSH on default port 22 — automated bots scan this port constantly."
        fix "Change to a high port (e.g. 2222) in /etc/ssh/sshd_config to reduce scan noise. Update firewall rules too."
    else
        ok "SSH on non-default port $port — reduces automated scan traffic."
    fi

    # MaxAuthTries
    if [ -n "$max_tries" ] && [ "$max_tries" -gt 3 ] 2>/dev/null; then
        warn "MaxAuthTries $max_tries — allows $max_tries failed attempts per connection before disconnecting."
        fix "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config"
    else
        ok "MaxAuthTries ${max_tries:-default (6)} — acceptable."
    fi

    # LoginGraceTime
    if [ -n "$grace" ] && [ "$grace" -gt 30 ] 2>/dev/null; then
        warn "LoginGraceTime ${grace}s — long window for unauthenticated connections to linger."
        fix "Set 'LoginGraceTime 20' in /etc/ssh/sshd_config"
    else
        ok "LoginGraceTime ${grace:-default} — acceptable."
    fi

    # X11 forwarding (attack surface if not needed)
    [ "$x11" = "yes" ] && warn "X11Forwarding yes — increases attack surface if you don't need GUI forwarding." \
        && fix "Set 'X11Forwarding no' unless you need to forward graphical applications."

    # TCP forwarding (can be abused to tunnel traffic)
    [ "$tcp_fwd" = "yes" ] && warn "AllowTcpForwarding yes — SSH tunnelling is enabled. Can be abused to bypass firewall rules." \
        && fix "Set 'AllowTcpForwarding no' if you don't use SSH port forwarding."

    # Client keepalive
    if [ -z "$alive" ] || [ "$alive" -eq 0 ] 2>/dev/null; then
        warn "ClientAliveInterval not set — idle sessions stay open indefinitely."
        fix "Add 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' to /etc/ssh/sshd_config"
    else
        ok "ClientAliveInterval ${alive}s — idle sessions will eventually time out."
    fi

    # Login banner
    [ -z "$banner" ] || [ "$banner" = "none" ] && info "No SSH login banner configured." \
        || ok "SSH login banner is set: $banner"

    pause
}

check_processes() {
    header "All Running Processes"
    desc "Full process tree with CPU and memory usage."
    local output
    output=$(ps auxf)
    echo "$output"
    echo

    analysis_header

    # Known miner process names (exact and partial)
    local miner_names=("xmrig" "minerd" "kdevtmpfsi" "kthreaddi" "sysupdate"
        "networkservice" "cryptonight" "cpuminer" "ccminer" "bfgminer"
        "cgminer" "ethminer" "claymore" "phoenixminer" "lolminer")
    local found_miner=0
    for name in "${miner_names[@]}"; do
        local match
        match=$(echo "$output" | grep -v 'grep\|server_audit' | grep -i "$name" | grep -v '\[' || true)
        if [ -n "$match" ]; then
            flag "Known miner process name detected: ${BOLD}$name${RESET}"
            echo "$match"
            fix "Kill it: sudo pkill -f $name && sudo find / -name '$name' -delete 2>/dev/null"
            found_miner=1
        fi
    done
    [ "$found_miner" -eq 0 ] && ok "No known crypto miner process names found."

    # Processes with deleted executables — classic fileless malware indicator
    local deleted_exes
    deleted_exes=$(ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | awk '{print $NF}' | sed 's/ (deleted)//' || true)
    if [ -n "$deleted_exes" ]; then
        flag "Process(es) running from deleted executables — strong indicator of fileless malware:"
        while IFS= read -r d; do
            local pid
            pid=$(echo "$d" | grep -oE '/proc/[0-9]+' | grep -oE '[0-9]+')
            local pname
            pname=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            flag "  PID $pid ($pname): $d"
            fix "  Investigate: ls -la /proc/$pid/exe && cat /proc/$pid/cmdline | tr '\\0' ' '"
        done <<< "$deleted_exes"
    else
        ok "No processes running from deleted executables."
    fi

    # High CPU usage (>50%) by non-kernel processes
    local high_cpu
    high_cpu=$(echo "$output" | awk 'NR>1 && $3>50 && $11!~/^\[/ {printf "  PID %-6s  CPU %-6s  User %-10s  %s\n", $2, $3"%", $1, $11}')
    if [ -n "$high_cpu" ]; then
        warn "Process(es) consuming >50% CPU — miners always show here:"
        echo "$high_cpu"
        fix "Investigate high-CPU process: sudo lsof -p <PID> && cat /proc/<PID>/cmdline | tr '\\0' ' '"
    else
        ok "No non-kernel processes with >50% CPU usage."
    fi

    # Processes running as root that aren't kernel threads and aren't in a known list
    local known_root=("systemd" "sshd" "cron" "nginx" "rsyslogd" "agetty" "multipathd"
        "snapd" "amazon-ssm" "udisksd" "ModemManager" "polkitd" "irqbalance"
        "chronyd" "unattended" "networkd-dispatcher" "python3" "udevd" "journald"
        "logind" "acpid" "dbus-daemon" "init" "bash" "sh" "ps" "grep" "awk")
    local suspicious_root
    suspicious_root=$(echo "$output" | awk 'NR>1 && $1=="root" && $11!~/^\[/ {print $2, $11}' | while read -r pid cmd; do
        base=$(basename "$cmd" 2>/dev/null || echo "$cmd")
        known=0
        for k in "${known_root[@]}"; do [[ "$base" == *"$k"* ]] && known=1 && break; done
        [ "$known" -eq 0 ] && echo "  PID $pid: $cmd"
    done || true)
    if [ -n "$suspicious_root" ]; then
        warn "Root processes not in the known-legitimate list (review these):"
        echo "$suspicious_root"
        fix "Investigate unknown root process: sudo lsof -p <PID>"
    fi

    pause
}

check_ports() {
    header "Listening Ports"
    desc "Shows all ports the server is listening on, correlated with the owning process."
    local output
    output=$(ss -tulpn)
    echo "$output"
    echo

    analysis_header

    # Extract publicly exposed ports (0.0.0.0 or ::) with process names
    local public
    public=$(echo "$output" | grep -E '(0\.0\.0\.0|:::| \*:)' | grep LISTEN)

    # Ports we expect on a typical Ubuntu web server
    local expected_ports=(22 80 443 8080 8443)
    local flagged_ports=0

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local port process
        port=$(echo "$line" | grep -oE ':[0-9]+\s' | head -1 | tr -d ': ')
        process=$(echo "$line" | grep -oP '(?<=users:\(\(")[^"]+' || echo "unknown")

        local expected=0
        for e in "${expected_ports[@]}"; do [ "$port" = "$e" ] && expected=1 && break; done

        if [ "$expected" -eq 1 ]; then
            ok "Port ${BOLD}$port${RESET} ($process) — expected."
        else
            warn "Port ${BOLD}$port${RESET} ($process) is publicly exposed — verify this is intentional."
            fix "If not needed: sudo ufw deny $port && sudo systemctl stop <service>"
            flagged_ports=$(( flagged_ports + 1 ))
        fi
    done <<< "$public"

    [ "$flagged_ports" -eq 0 ] && ok "All publicly exposed ports are in the expected set."

    # Ports only on localhost — informational
    local local_count
    local_count=$(echo "$output" | grep -c '127\.' || echo 0)
    [ "$local_count" -gt 0 ] && ok "$local_count port(s) on localhost only — not reachable externally."

    # High ports (>10000) exposed publicly — unusual
    local high_public
    high_public=$(echo "$public" | grep -oE ':[0-9]+' | tr -d ':' | awk '$1>10000')
    if [ -n "$high_public" ]; then
        warn "High port(s) exposed publicly: $high_public"
        fix "Confirm these belong to legitimate services. If unknown: sudo ss -tulpn | grep <port>"
    fi

    pause
}

check_outbound() {
    header "Established Outbound Connections"
    desc "Active connections this server has opened to external hosts."
    local output
    output=$(ss -tupn state established 2>/dev/null)
    echo "$output"
    echo

    analysis_header

    local conn_count
    conn_count=$(echo "$output" | grep -c 'ESTAB' 2>/dev/null || echo 0)

    if [ "$conn_count" -eq 0 ]; then
        ok "No established outbound connections — clean."
        pause
        return
    fi

    info "$conn_count established connection(s) found."

    # Known miner pool ports
    local miner_ports=(3333 4444 14444 45700 5555 7777 9999 3032 14433 45560)
    for p in "${miner_ports[@]}"; do
        local hit
        hit=$(echo "$output" | grep ":$p[^0-9]" || true)
        if [ -n "$hit" ]; then
            flag "Connection on port $p — this is a well-known crypto mining pool port!"
            echo "$hit"
            fix "Kill the process: sudo ss -tulpn | grep $p, then: sudo kill -9 <PID>"
        fi
    done

    # Check each unique remote IP
    local remote_ips
    remote_ips=$(echo "$output" | grep ESTAB | awk '{print $6}' \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | grep -v '127\.' || true)

    if [ -n "$remote_ips" ]; then
        info "Unique remote IPs with active connections:"
        while IFS= read -r ip; do
            local proc
            proc=$(echo "$output" | grep "$ip" | grep -oP '(?<=\(\(")[^"]+' | head -1 || echo "unknown")
            # Flag non-AWS private space connections
            if echo "$ip" | grep -qE '^(169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)'; then
                ok "  ${BOLD}$ip${RESET} ($proc) — AWS link-local/metadata range, expected."
            else
                info "  ${BOLD}$ip${RESET} ($proc)"
                fix "  Verify: whois $ip  or  curl -s https://ipinfo.io/$ip"
            fi
        done <<< "$remote_ips"
    fi

    # Persistent connections to same IP (could be C2 beacon)
    local repeated
    repeated=$(echo "$output" | grep ESTAB | awk '{print $6}' \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn \
        | awk '$1>3 {print $1, $2}' || true)
    if [ -n "$repeated" ]; then
        warn "Multiple connections to the same IP — could indicate C2 beaconing:"
        while IFS= read -r l; do warn "  $l connections"; done <<< "$repeated"
        fix "Investigate: sudo ss -tupn | grep <ip>"
    fi

    pause
}

check_enabled_services() {
    header "Enabled Systemd Services"
    desc "Services configured to start automatically at boot."
    local output
    output=$(systemctl list-unit-files --state=enabled 2>/dev/null)
    echo "$output"
    echo

    analysis_header

    # Known legitimate Ubuntu/AWS service name fragments
    local known=("ssh" "cron" "nginx" "apache2" "mysql" "postgresql" "redis" "mongodb"
        "ufw" "rsyslog" "chrony" "ntp" "snapd" "systemd-" "dbus" "network"
        "resolved" "logind" "udevd" "multipathd" "unattended" "ModemManager"
        "polkit" "udisks2" "amazon-ssm" "cloud-" "iscsid" "open-iscsi"
        "irqbalance" "acpid" "apparmor" "apport" "grub" "plymouth" "procps"
        "rsync" "sysstat" "uuidd" "hibagent" "open-vm-tools" "screen-cleanup"
        "fail2ban" "docker" "containerd" "kubelet" "php" "node" "gunicorn"
        "uwsgi" "postfix" "dovecot" "bind9" "named" "avahi" "cups" "bluetooth"
        "thermald" "fwupd" "packagekit" "gdm" "lightdm" "snap." "lxd")

    local unknown_services=()
    while IFS= read -r line; do
        local svc
        svc=$(echo "$line" | awk '{print $1}')
        [[ -z "$svc" || "$svc" == "UNIT" || "$svc" == "systemd-"* ]] && continue
        local k=0
        for kn in "${known[@]}"; do [[ "$svc" == *"$kn"* ]] && k=1 && break; done
        [ "$k" -eq 0 ] && unknown_services+=("$svc")
    done <<< "$(echo "$output" | grep 'enabled')"

    if [ "${#unknown_services[@]}" -eq 0 ]; then
        ok "All enabled services match known legitimate Ubuntu/AWS service patterns."
    else
        warn "${#unknown_services[@]} service(s) not in the known-legitimate list — review these:"
        for s in "${unknown_services[@]}"; do
            warn "  ${BOLD}$s${RESET}"
            fix "  Inspect: sudo systemctl status $s && sudo systemctl cat $s"
        done
    fi

    pause
}

check_running_services() {
    header "Currently Running Services"
    desc "Services that are active right now."
    local output
    output=$(systemctl list-units --type=service --state=running 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c 'running' 2>/dev/null || echo 0)
    ok "$count service(s) currently running."

    # Count failed services — a crashed service could indicate a tampered binary that fails to start
    local failed
    failed=$(systemctl list-units --type=service --state=failed 2>/dev/null | grep 'failed' || true)
    if [ -n "$failed" ]; then
        warn "Failed service(s) detected — a legitimate service crashing can open security gaps:"
        while IFS= read -r l; do
            warn "  $l"
            local svc
            svc=$(echo "$l" | awk '{print $1}')
            fix "  Inspect logs: sudo journalctl -u $svc -n 20"
        done <<< "$failed"
    else
        ok "No failed services."
    fi

    pause
}

check_crontabs() {
    header "Crontabs (All Users)"
    desc "Scheduled tasks for all users — a common malware persistence mechanism."
    local all_crons=""
    local found=0

    for u in $(cut -f1 -d: /etc/passwd); do
        local cron
        cron=$(crontab -u "$u" -l 2>/dev/null | grep -v '^#' || true)
        if [ -n "$cron" ]; then
            echo -e "${GREEN}[user: $u]${RESET}"
            echo "$cron"
            echo
            all_crons="${all_crons}
${cron}"
            found=1
        fi
    done
    [ "$found" -eq 0 ] && echo "(no user crontabs found)"
    echo

    desc "System cron directories:"
    ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ 2>/dev/null
    echo

    analysis_header
    if [ "$found" -eq 0 ]; then
        ok "No user crontabs — clean."
    else
        # High-risk patterns in cron commands
        declare -A CRON_PATTERNS
        CRON_PATTERNS["curl .* | bash"]="downloads and immediately executes remote code"
        CRON_PATTERNS["wget .* | bash"]="downloads and immediately executes remote code"
        CRON_PATTERNS["wget .* -O .* && bash"]="downloads a file then executes it"
        CRON_PATTERNS["curl .* -o .* && bash"]="downloads a file then executes it"
        CRON_PATTERNS["/tmp/"]="executes something from /tmp — common malware location"
        CRON_PATTERNS["/dev/shm"]="executes something from /dev/shm — common malware location"
        CRON_PATTERNS["base64 -d"]="decodes and possibly executes base64-encoded payload"
        CRON_PATTERNS["\$(.*curl\|.*wget"]="command substitution downloading remote content"
        CRON_PATTERNS["python.*-c"]="inline Python execution — can hide obfuscated commands"
        CRON_PATTERNS["perl.*-e"]="inline Perl execution — can hide obfuscated commands"
        CRON_PATTERNS["bash -i"]="interactive shell in cron — used to establish reverse shells"
        CRON_PATTERNS["nc .*-e"]="netcat with -e flag — classic reverse shell"
        CRON_PATTERNS["chmod.*777"]="making a file world-writable/executable"
        CRON_PATTERNS["chmod.*\+x.*&&"]="making something executable then running it"

        local clean=1
        for pattern in "${!CRON_PATTERNS[@]}"; do
            if echo "$all_crons" | grep -qiE "$pattern"; then
                flag "Suspicious cron pattern: ${BOLD}${pattern}${RESET} (${CRON_PATTERNS[$pattern]})"
                fix "Inspect and remove: crontab -e"
                clean=0
            fi
        done
        [ "$clean" -eq 1 ] && ok "No high-risk patterns found in crontabs."
    fi

    # Check system cron files for same patterns
    local sys_cron
    sys_cron=$(cat /etc/cron.d/* /etc/crontab 2>/dev/null || true)
    if echo "$sys_cron" | grep -qE '/tmp/|/dev/shm|base64|curl.*\|.*sh|wget.*\|.*sh'; then
        flag "Suspicious pattern found in system cron files (/etc/cron.d or /etc/crontab)."
        fix "Review: cat /etc/crontab && ls -la /etc/cron.d/"
    else
        ok "No suspicious patterns in system cron files."
    fi

    pause
}

check_startup_scripts() {
    header "Startup Scripts"
    desc "Legacy SysV init scripts — another persistence location."
    run "ls -la /etc/init.d/"
    run "ls -la /etc/rc2.d/"

    analysis_header
    local known=("acpid" "apparmor" "apport" "chrony" "console-setup.sh" "cron"
        "cryptdisks" "cryptdisks-early" "dbus" "grub-common" "hibagent"
        "irqbalance" "iscsid" "keyboard-setup.sh" "kmod" "nginx" "open-iscsi"
        "open-vm-tools" "plymouth" "plymouth-log" "procps" "rsync"
        "screen-cleanup" "ssh" "sysstat" "ufw" "unattended-upgrades" "uuidd")

    local unknown_scripts=()
    while IFS= read -r script; do
        [ -z "$script" ] && continue
        local k=0
        for kn in "${known[@]}"; do [ "$script" = "$kn" ] && k=1 && break; done
        [ "$k" -eq 0 ] && unknown_scripts+=("$script")
    done <<< "$(ls /etc/init.d/ 2>/dev/null)"

    if [ "${#unknown_scripts[@]}" -eq 0 ]; then
        ok "All init.d scripts match known Ubuntu defaults."
    else
        warn "${#unknown_scripts[@]} unfamiliar init.d script(s) — review these:"
        for s in "${unknown_scripts[@]}"; do
            warn "  ${BOLD}/etc/init.d/$s${RESET}"
            fix "  Inspect: cat /etc/init.d/$s | head -30"
        done
    fi

    pause
}

check_shell_users() {
    header "Users With Shell Access"
    desc "Accounts that can run interactive commands."
    local output
    output=$(grep -v '/nologin\|/false' /etc/passwd)
    echo "$output"
    echo

    analysis_header

    # Human users (UID >= 1000)
    local human_users
    human_users=$(echo "$output" | awk -F: '$3>=1000 && $1!="nobody" {print $1, $3, $7}')
    if [ -n "$human_users" ]; then
        ok "Human account(s) with shell access (UID ≥ 1000):"
        while IFS= read -r line; do
            local user uid shell
            user=$(echo "$line" | awk '{print $1}')
            uid=$(echo "$line" | awk '{print $2}')
            shell=$(echo "$line" | awk '{print $3}')
            ok "  ${BOLD}$user${RESET} (UID $uid, shell: $shell)"
            # Check if account has a password set (! or * = locked/no password)
            local pw_status
            pw_status=$(sudo passwd -S "$user" 2>/dev/null | awk '{print $2}')
            case "$pw_status" in
                P)  warn "  ↳ $user has a password set — SSH key-only login is more secure." ;;
                NP) flag "  ↳ $user has NO PASSWORD — account can be accessed without credentials!"
                    fix "  Lock or set a password: sudo passwd $user" ;;
                L)  ok "  ↳ $user's password is locked (SSH key only — good)." ;;
            esac
        done <<< "$human_users"
    fi

    # System accounts with real shells (should have /bin/false or /usr/sbin/nologin)
    local system_with_shell
    system_with_shell=$(echo "$output" | awk -F: '$3>0 && $3<1000 && ($7=="/bin/bash" || $7=="/bin/sh") {print $1, $3}')
    if [ -n "$system_with_shell" ]; then
        flag "System account(s) with an interactive shell — these should use /usr/sbin/nologin:"
        while IFS= read -r line; do
            flag "  ${BOLD}$(echo "$line" | awk '{print $1}')${RESET} (UID $(echo "$line" | awk '{print $2}'))"
            fix "  Fix: sudo usermod -s /usr/sbin/nologin $(echo "$line" | awk '{print $1}')"
        done <<< "$system_with_shell"
    else
        ok "No system accounts have an interactive shell."
    fi

    pause
}

check_root_uid() {
    header "Users With UID 0 (root-level)"
    desc "Every account with UID 0 has full system control."
    local output
    output=$(awk -F: '$3==0' /etc/passwd)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c '.' 2>/dev/null || echo 0)

    if [ "$count" -eq 1 ] && echo "$output" | grep -q '^root:'; then
        ok "Only 'root' has UID 0 — expected."
    elif [ "$count" -eq 0 ]; then
        warn "No UID 0 account found — root may have been renamed (unusual but not necessarily malicious)."
    else
        flag "$count accounts with UID 0 — only 'root' should have UID 0!"
        flag "Extra UID 0 accounts are the oldest trick in the attacker handbook."
        echo "$output" | grep -v '^root:' | while IFS= read -r line; do
            local extra_user
            extra_user=$(echo "$line" | cut -d: -f1)
            flag "  Backdoor account: ${BOLD}$extra_user${RESET} — delete immediately"
            fix "  sudo userdel -r $extra_user"
        done
    fi

    pause
}

check_sudoers() {
    header "Sudoers Configuration"
    desc "Who can run what as root."
    run "sudo cat /etc/sudoers"
    echo -e "${GREEN}\$ sudo ls /etc/sudoers.d/${RESET}"
    sudo ls /etc/sudoers.d/ 2>/dev/null
    echo

    analysis_header
    local sudoers
    sudoers=$(sudo cat /etc/sudoers 2>/dev/null)

    # NOPASSWD — dangerous if applied broadly
    local nopasswd_all
    nopasswd_all=$(echo "$sudoers" | grep -v '^#' | grep 'NOPASSWD' | grep 'ALL' || true)
    local nopasswd_limited
    nopasswd_limited=$(echo "$sudoers" | grep -v '^#' | grep 'NOPASSWD' | grep -v 'ALL' || true)

    if [ -n "$nopasswd_all" ]; then
        flag "NOPASSWD ALL — these entries can run any command as root without a password:"
        while IFS= read -r l; do flag "  $l"; done <<< "$nopasswd_all"
        fix "Restrict to specific commands or require a password: remove NOPASSWD from /etc/sudoers"
    elif [ -n "$nopasswd_limited" ]; then
        warn "NOPASSWD entries for specific commands (lower risk, but review):"
        while IFS= read -r l; do warn "  $l"; done <<< "$nopasswd_limited"
    else
        ok "No NOPASSWD entries — sudo always requires a password."
    fi

    # Wildcard commands — 'ALL' grants everything
    local unrestricted
    unrestricted=$(echo "$sudoers" | grep -v '^#' | grep 'ALL=(ALL.*) ALL' | grep -v 'NOPASSWD' || true)
    [ -n "$unrestricted" ] && info "Full sudo access (with password) granted to:" \
        && while IFS= read -r l; do info "  $l"; done <<< "$unrestricted"

    # sudoers.d files — attackers sometimes drop files here
    local sudod_files
    sudod_files=$(sudo ls /etc/sudoers.d/ 2>/dev/null | grep -v README || true)
    if [ -n "$sudod_files" ]; then
        info "Additional sudoers rules in /etc/sudoers.d/:"
        while IFS= read -r f; do
            local content
            content=$(sudo cat "/etc/sudoers.d/$f" 2>/dev/null | grep -v '^#' | grep -v '^$' || true)
            info "  ${BOLD}$f${RESET}:"
            [ -n "$content" ] && while IFS= read -r l; do info "    $l"; done <<< "$content"
            # Flag if a sudoers.d file grants NOPASSWD ALL
            echo "$content" | grep -q 'NOPASSWD.*ALL' \
                && flag "  /etc/sudoers.d/$f grants NOPASSWD ALL — high risk!" \
                && fix "  sudo rm /etc/sudoers.d/$f  (after verifying it's not needed)"
        done <<< "$sudod_files"
    else
        ok "No additional files in /etc/sudoers.d/."
    fi

    pause
}

check_suid() {
    header "SUID Binaries"
    desc "Executables that run as their owner (often root) regardless of who launches them."
    local output
    output=$(find / -perm -4000 -type f 2>/dev/null)
    echo "$output"
    echo

    analysis_header

    # Instead of a denylist, cross-reference against dpkg to see if each binary
    # is owned by an installed package — unpackaged SUID binaries are suspicious
    local unpackaged=()
    local pkg_count=0
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        local pkg
        pkg=$(dpkg -S "$path" 2>/dev/null | cut -d: -f1 || true)
        if [ -z "$pkg" ]; then
            unpackaged+=("$path")
        else
            pkg_count=$(( pkg_count + 1 ))
        fi
    done <<< "$output"

    ok "$pkg_count SUID binaries are owned by installed packages — expected."
    if [ "${#unpackaged[@]}" -gt 0 ]; then
        flag "${#unpackaged[@]} SUID binary/binaries NOT owned by any package — investigate:"
        for f in "${unpackaged[@]}"; do
            flag "  ${BOLD}$f${RESET}"
            fix "  Check: ls -la $f && file $f && strings $f | head -20"
            fix "  Remove SUID if not needed: sudo chmod u-s $f"
        done
    else
        ok "All SUID binaries are owned by installed packages."
    fi

    # Specifically flag shells or interpreters with SUID — instant root escalation
    local suid_shells
    suid_shells=$(echo "$output" | grep -E '/(bash|sh|dash|zsh|python|perl|ruby|node|php)$' || true)
    if [ -n "$suid_shells" ]; then
        flag "SUID set on a shell or interpreter — this grants instant root to anyone who runs it!"
        while IFS= read -r s; do
            flag "  ${BOLD}$s${RESET}"
            fix "  Remove immediately: sudo chmod u-s $s"
        done <<< "$suid_shells"
    fi

    pause
}

check_etc_modified() {
    header "Recently Modified /etc Files (last 7 days)"
    desc "Config files changed since initial setup may have been tampered with."
    local output
    output=$(find /etc -mtime -7 -type f 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c '.' 2>/dev/null || echo 0)
    info "$count file(s) in /etc modified in the last 7 days."

    # ── Provisioning window filter ───────────────────────────────────────────
    # Files modified within the first 10 minutes of system boot are almost
    # certainly written by cloud-init or the OS installer, not by an attacker.
    # We compare each file's mtime (seconds since epoch) against boot time
    # and skip files that fall inside the provisioning window.
    local boot_epoch
    boot_epoch=$(date -d "$(uptime -s)" +%s 2>/dev/null \
        || date -j -f "%Y-%m-%d %H:%M:%S" "$(uptime -s)" +%s 2>/dev/null \
        || echo 0)
    local provision_window=600   # 10 minutes after boot
    local provision_cutoff=$(( boot_epoch + provision_window ))

    # Files written by cloud-init regardless of timing
    local cloud_init_files=(
        "/etc/passwd" "/etc/shadow" "/etc/shadow-" "/etc/gshadow" "/etc/gshadow-"
        "/etc/group" "/etc/subuid" "/etc/subgid" "/etc/hostname" "/etc/machine-id"
        "/etc/ssh/ssh_host_rsa_key" "/etc/ssh/ssh_host_rsa_key.pub"
        "/etc/ssh/ssh_host_ecdsa_key" "/etc/ssh/ssh_host_ecdsa_key.pub"
        "/etc/ssh/ssh_host_ed25519_key" "/etc/ssh/ssh_host_ed25519_key.pub"
        "/etc/netplan/50-cloud-init.yaml"
        "/etc/apt/sources.list.d/ubuntu.sources"
        "/etc/udev/rules.d/90-cloud-init-hook-hotplug.rules"
        "/etc/ld.so.cache"
    )
    # PAM common-* files are written by pam packages on first boot
    local cloud_init_patterns=("/etc/pam.d/common-" "/etc/ssh/ssh_host_")

    _is_provisioning_write() {
        local f="$1"
        # Check explicit cloud-init file list
        for ci in "${cloud_init_files[@]}"; do
            [ "$f" = "$ci" ] && return 0
        done
        # Check pattern prefixes
        for pat in "${cloud_init_patterns[@]}"; do
            [[ "$f" == "$pat"* ]] && return 0
        done
        # Check if mtime falls within the boot provisioning window
        if [ "$boot_epoch" -gt 0 ]; then
            local mtime
            mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
            [ "$mtime" -le "$provision_cutoff" ] && return 0
        fi
        return 1
    }

    # ── Show suppressed provisioning files as a collapsed note ───────────────
    local suppressed=()
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        _is_provisioning_write "$f" && suppressed+=("$f")
    done <<< "$output"

    if [ "${#suppressed[@]}" -gt 0 ]; then
        ok "${#suppressed[@]} file(s) modified during initial provisioning (cloud-init / first boot) — suppressed as expected:"
        for f in "${suppressed[@]}"; do info "  $f"; done
        echo
    fi

    # ── Tier 1 — critical files ───────────────────────────────────────────────
    local tier1=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config"
        "/etc/ld.so.preload" "/etc/pam.d/sshd" "/etc/pam.d/sudo"
        "/etc/pam.d/common-auth" "/etc/profile" "/etc/bash.bashrc"
        "/etc/environment" "/etc/crontab")

    # ── Tier 2 — elevated concern files ──────────────────────────────────────
    local tier2=("/etc/hosts" "/etc/resolv.conf" "/etc/nsswitch.conf"
        "/etc/ssh/ssh_config" "/etc/sysctl.conf" "/etc/security/limits.conf"
        "/etc/apt/sources.list")

    local t1_hit=0 t2_hit=0
    for f in "${tier1[@]}"; do
        if echo "$output" | grep -qF "$f"; then
            # Skip if this was a provisioning write
            _is_provisioning_write "$f" && continue
            if [ "$f" = "/etc/ld.so.preload" ]; then
                flag "${BOLD}/etc/ld.so.preload${RESET} was modified — rootkits use this to inject malicious libraries at startup!"
                fix "Inspect immediately: cat /etc/ld.so.preload — it should be empty on a clean system."
            else
                local mtime_human
                mtime_human=$(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1 || echo "unknown time")
                flag "Critical config modified post-provisioning: ${BOLD}$f${RESET} (at $mtime_human)"
                fix "Show what changed: sudo diff <(dpkg-query -S $f 2>/dev/null) <(echo $f) || debsums -c"
                fix "Check who modified it: sudo ausearch -f $f 2>/dev/null | tail -20"
            fi
            t1_hit=1
        fi
    done

    for f in "${tier2[@]}"; do
        if echo "$output" | grep -qF "$f"; then
            _is_provisioning_write "$f" && continue
            local mtime_human
            mtime_human=$(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1 || echo "unknown time")
            warn "Sensitive config modified post-provisioning: ${BOLD}$f${RESET} (at $mtime_human)"
            t2_hit=1
        fi
    done

    [ "$t1_hit" -eq 0 ] && [ "$t2_hit" -eq 0 ] \
        && ok "No critical or sensitive config files were modified after provisioning."

    # Recent apt activity that could explain legitimate changes
    local last_apt
    last_apt=$(grep -E 'install|upgrade' /var/log/dpkg.log 2>/dev/null | tail -3 || true)
    [ -n "$last_apt" ] && info "Recent apt activity (may explain some modifications):" \
        && while IFS= read -r l; do info "  $l"; done <<< "$last_apt"

    pause
}

check_bin_modified() {
    header "Recently Modified System Binaries (last 30 days)"
    desc "Rootkits replace core binaries like ps, ls, and netstat to hide their activity."
    local output
    output=$(find /usr/bin /usr/sbin /bin /sbin -mtime -30 -type f 2>/dev/null)
    echo "$output"
    echo

    analysis_header
    local count
    count=$(echo "$output" | grep -c '.' 2>/dev/null || echo 0)

    if [ "$count" -eq 0 ]; then
        ok "No system binaries modified in the last 30 days."
        pause
        return
    fi

    info "$count binary/binaries modified in the last 30 days."

    # Cross-reference with dpkg log to distinguish upgrades from tampering
    local apt_dates
    apt_dates=$(grep -E 'upgrade|install' /var/log/dpkg.log 2>/dev/null | awk '{print $1}' | sort -u | tail -10)
    if [ -n "$apt_dates" ]; then
        ok "Recent package activity found — most binary changes are likely legitimate upgrades."
        info "Dates of recent apt operations: $(echo "$apt_dates" | tr '\n' ' ')"
    else
        warn "No recent apt/dpkg activity found but binaries were modified."
        fix "For every binary listed above, run: dpkg -S <path> to verify it belongs to a package"
        fix "Then verify the hash: debsums <package-name>"
    fi

    # High-risk binaries — the ones rootkits always replace
    local tier1_bins=("ps" "ls" "top" "netstat" "ss" "find" "who" "w" "last"
        "login" "sshd" "cron" "bash" "sh" "awk" "grep" "sed" "cat")
    local tier1_hit=0
    while IFS= read -r f; do
        local base; base=$(basename "$f")
        for r in "${tier1_bins[@]}"; do
            if [ "$base" = "$r" ]; then
                flag "High-value binary modified: ${BOLD}$f${RESET} — rootkits routinely replace this."
                fix "Verify hash: dpkg -S $f && debsums $(dpkg -S $f 2>/dev/null | cut -d: -f1)"
                tier1_hit=1
                break
            fi
        done
    done <<< "$output"
    [ "$tier1_hit" -eq 0 ] && ok "None of the highest-risk binaries (ps, ls, ss, sshd etc.) were modified."

    # Check debsums if available
    if command -v debsums &>/dev/null; then
        info "Running debsums integrity check on modified binaries..."
        local debsums_fail
        debsums_fail=$(sudo debsums -c 2>/dev/null | grep -v 'OK$' || true)
        if [ -n "$debsums_fail" ]; then
            flag "debsums found hash mismatches — these files differ from their package versions:"
            while IFS= read -r l; do flag "  $l"; done <<< "$debsums_fail"
            fix "Reinstall affected packages: sudo apt install --reinstall <package>"
        else
            ok "debsums: all checked binaries match their package hashes."
        fi
    else
        fix "Install debsums for hash verification: sudo apt install debsums && sudo debsums -c"
    fi

    pause
}

check_tmp_hidden() {
    header "Hidden Files in /tmp and /var/tmp"
    desc "/tmp and /dev/shm are world-writable — favourite malware staging areas."
    local hidden
    hidden=$(find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null)
    echo -e "${GREEN}\$ find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null${RESET}"
    [ -n "$hidden" ] && echo "$hidden" || echo "(none found)"
    echo
    run "ls -la /tmp /var/tmp"

    analysis_header

    if [ -z "$hidden" ]; then
        ok "No hidden dot-files in /tmp, /var/tmp, or /dev/shm."
    else
        flag "Hidden file(s) found:"
        while IFS= read -r f; do
            flag "  ${BOLD}$f${RESET}"
            [ -x "$f" ] && flag "  ↳ EXECUTABLE — strongly suspicious of malware." \
                && fix "  Investigate before deleting: file $f && strings $f | head -20"
        done <<< "$hidden"
    fi

    # Any executable (not a .sh script) sitting in /tmp
    local exec_tmp
    exec_tmp=$(find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null \
        | grep -vE '\.(sh|py|rb|pl)$' || true)
    if [ -n "$exec_tmp" ]; then
        flag "Executable binary/binaries in /tmp or /dev/shm — malware almost always lives here:"
        while IFS= read -r f; do
            flag "  ${BOLD}$f${RESET}"
            fix "  Identify: file $f && ls -la $f"
            fix "  If malicious: sudo rm -f $f"
        done <<< "$exec_tmp"
    else
        ok "No unexplained executable binaries in /tmp or /dev/shm."
    fi

    # Files larger than 1MB in /tmp (dropped payloads are often large)
    local large_files
    large_files=$(find /tmp /var/tmp /dev/shm -type f -size +1M 2>/dev/null || true)
    if [ -n "$large_files" ]; then
        warn "Large file(s) (>1MB) in /tmp — could be downloaded payloads:"
        while IFS= read -r f; do
            local size
            size=$(du -sh "$f" 2>/dev/null | awk '{print $1}')
            warn "  ${BOLD}$f${RESET} ($size)"
            fix "  Inspect: file $f && ls -la $f"
        done <<< "$large_files"
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
    warnings=$(echo "$output" | grep -c 'Warning' 2>/dev/null || echo 0)
    infections=$(echo "$output" | grep -c 'Infected' 2>/dev/null || echo 0)

    [ "$infections" -gt 0 ] && flag "$infections infection(s) found — treat this as a compromise until proven otherwise." \
        && fix "Full incident response: take a snapshot now, then investigate each finding." \
        || ok "No infections detected by rkhunter."

    if [ "$warnings" -gt 0 ]; then
        warn "$warnings warning(s) — rkhunter warnings are often false positives but must be checked:"
        echo "$output" | grep 'Warning' | while IFS= read -r l; do warn "  $l"; done
        fix "Investigate each warning: sudo rkhunter --check --sk --rwo (warnings only)"
    else
        ok "No warnings from rkhunter."
    fi
    pause
}

check_chkrootkit() {
    header "chkrootkit"
    desc "Second rootkit scanner with different detection signatures — use both."
    sudo apt install chkrootkit -y -q
    local output
    output=$(sudo chkrootkit 2>&1)
    echo "$output" | grep -v 'not found\|not tested'
    echo

    analysis_header
    local infected
    infected=$(echo "$output" | grep 'INFECTED' || true)
    if [ -n "$infected" ]; then
        flag "chkrootkit found INFECTED entries:"
        while IFS= read -r l; do
            flag "  $l"
            fix "  Cross-reference with rkhunter — if both agree, treat as confirmed compromise."
        done <<< "$infected"
    else
        ok "chkrootkit found no infections."
    fi

    # Some false positives to contextualise
    local suspicious
    suspicious=$(echo "$output" | grep -iE 'suspicious|warning' | grep -v 'not found' || true)
    [ -n "$suspicious" ] && warn "chkrootkit warnings (may be false positives — verify):" \
        && while IFS= read -r l; do warn "  $l"; done <<< "$suspicious"

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
    local infected scanned errors
    infected=$(echo "$output" | grep 'Infected files:' | awk '{print $3}')
    scanned=$(echo "$output" | grep 'Scanned files:' | awk '{print $3}')
    errors=$(echo "$output" | grep 'Errors:' | awk '{print $2}')

    info "Files scanned: ${scanned:-unknown}"
    if [ "$infected" = "0" ] || [ -z "$infected" ]; then
        ok "ClamAV found no infected files."
    else
        flag "ClamAV found ${BOLD}$infected${RESET} infected file(s) — they have been removed automatically."
        fix "Check what was removed: grep 'FOUND' above, then audit how those files got there."
        fix "Consider isolating the server: sudo ufw default deny outgoing && sudo ufw reload"
    fi
    [ -n "$errors" ] && [ "$errors" != "0" ] && warn "$errors scan error(s) — some files may not have been checked."

    pause
}

check_miners() {
    header "Crypto Miner Detection"
    desc "Targeted scan for miner processes, binaries, and network connections."
    echo -e "${GREEN}\$ ps aux --sort=-%cpu | head -20${RESET}"
    local ps_out
    ps_out=$(ps aux --sort=-%cpu | head -20)
    echo "$ps_out"
    echo

    desc "Scanning filesystem for known miner binaries..."
    local find_out
    find_out=$(find / \( -name 'xmrig' -o -name 'minerd' -o -name 'kdevtmpfsi' \
        -o -name 'kthreaddi' -o -name 'sysupdate' -o -name 'networkservice' \
        -o -name 'cryptonight' -o -name 'cpuminer' \) 2>/dev/null)
    [ -n "$find_out" ] && echo "$find_out" || echo "(none found)"
    echo

    desc "Checking for connections to known mining pool ports..."
    local net_out
    net_out=$(ss -tupn | grep -E ':3333[^0-9]|:4444[^0-9]|:14444[^0-9]|:45700[^0-9]|:5555[^0-9]|:7777[^0-9]|:3032[^0-9]' || true)
    [ -n "$net_out" ] && echo "$net_out" || echo "(none found)"
    echo

    analysis_header
    local flagged=0

    # Process name check
    local miner_names=("xmrig" "minerd" "kdevtmpfsi" "kthreaddi" "sysupdate"
        "cryptonight" "cpuminer" "ccminer" "bfgminer" "cgminer"
        "ethminer" "claymore" "phoenixminer" "lolminer" "nbminer")
    for name in "${miner_names[@]}"; do
        local match
        match=$(echo "$ps_out" | grep -v 'grep\|server_audit' | grep -i "$name" || true)
        if [ -n "$match" ]; then
            flag "Miner process ${BOLD}$name${RESET} is running!"
            fix "Kill: sudo pkill -9 -f $name"
            fix "Find and delete binary: sudo find / -name '$name' -delete 2>/dev/null"
            flagged=1
        fi
    done

    # Binary on disk
    if [ -n "$find_out" ]; then
        flag "Miner binary found on disk:"
        while IFS= read -r f; do
            flag "  ${BOLD}$f${RESET}"
            fix "  Delete: sudo rm -f $f"
        done <<< "$find_out"
        flagged=1
    fi

    # Mining pool connections
    if [ -n "$net_out" ]; then
        flag "Active connection to a known mining pool port!"
        echo "$net_out"
        fix "Find owning process: sudo ss -tulpn | grep <port>, then: sudo kill -9 <PID>"
        flagged=1
    fi

    # CPU spike — miners always consume maximum CPU
    local cpu_hogs
    cpu_hogs=$(echo "$ps_out" | awk 'NR>1 && $3>80 && $11!~/^\[/ {print $1, $3"%", $11}')
    if [ -n "$cpu_hogs" ]; then
        warn "Process(es) using >80% CPU — miners maximise CPU by design:"
        while IFS= read -r l; do
            warn "  $l"
            local proc_name
            proc_name=$(echo "$l" | awk '{print $NF}')
            fix "  Investigate: sudo lsof -p $(pgrep -f "$proc_name" | head -1) 2>/dev/null | head -20"
        done <<< "$cpu_hogs"
    fi

    # Check /proc for deleted executables (fileless miners)
    local deleted
    deleted=$(ls -la /proc/*/exe 2>/dev/null | grep deleted | awk '{print $NF}' | sed 's/ (deleted)//' || true)
    if [ -n "$deleted" ]; then
        flag "Process(es) with deleted executables — sign of fileless malware (common miner technique):"
        while IFS= read -r d; do flag "  $d"; done <<< "$deleted"
        fix "Reboot to clear fileless malware from memory, then audit startup scripts immediately."
    fi

    [ "$flagged" -eq 0 ] && ok "No crypto miner indicators detected — clean."

    pause
}

# ─── Run all with risk summary ────────────────

run_all() {
    RISK_FLAGS=0; RISK_WARNS=0

    check_active_sessions;    check_login_history;     check_failed_logins
    check_accepted_logins;    check_ssh_keys;          check_ssh_config
    check_processes;          check_ports;             check_outbound
    check_enabled_services;   check_running_services;  check_crontabs
    check_startup_scripts;    check_shell_users;       check_root_uid
    check_sudoers;            check_suid;              check_etc_modified
    check_bin_modified;       check_tmp_hidden;        check_miners

    clear
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  Full Audit Complete — Risk Summary${RESET}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}\n"

    if [ "$RISK_FLAGS" -eq 0 ] && [ "$RISK_WARNS" -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}✓ No issues found. Server appears clean.${RESET}\n"
    else
        [ "$RISK_FLAGS" -gt 0 ] && echo -e "  ${RED}${BOLD}[!] $RISK_FLAGS critical finding(s) require immediate attention.${RESET}"
        [ "$RISK_WARNS" -gt 0 ] && echo -e "  ${AMBER}${BOLD}[~] $RISK_WARNS warning(s) should be reviewed.${RESET}"
        echo

        if [ "$RISK_FLAGS" -gt 5 ]; then
            echo -e "  ${RED}${BOLD}High risk — consider this server potentially compromised.${RESET}"
            echo -e "  ${RED}Take a snapshot before making changes, and review all [!] findings above.${RESET}"
        elif [ "$RISK_FLAGS" -gt 0 ]; then
            echo -e "  ${AMBER}Moderate risk — address all [!] items before this server handles sensitive data.${RESET}"
        else
            echo -e "  ${GREEN}Low risk — no critical findings, but review the [~] warnings above.${RESET}"
        fi
    fi

    echo -e "\n  ${DIM}Run individual checks above to see findings and remediation steps.${RESET}"
    echo -e "  ${DIM}Run options 21–23 to install and run malware scanners.${RESET}\n"
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
