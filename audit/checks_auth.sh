#!/usr/bin/env bash
# audit/checks_auth.sh — SSH & Authentication checks (options 1–6)
# Sourced by server_audit.sh. Requires lib.sh to be sourced first.

check_active_sessions() {
    header "Active Sessions"
    desc "Shows who is currently logged in, from which IP, and what they are running."
    local output
    output=$(w)
    echo "$output"
    echo

    analysis_header
    local sessions
    sessions=$(echo "$output" | tail -n +3 | grep -v '^$' || true)

    # Root sessions
    local root_sessions
    root_sessions=$(echo "$sessions" | awk '$1=="root"' || true)
    if [ -n "$root_sessions" ]; then
        flag "Root is directly logged in — root should not have interactive SSH sessions."
        fix "Disable root SSH: set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: sudo systemctl restart ssh"
    else
        ok "No direct root sessions."
    fi

    # Unexpected users
    local current_user; current_user=$(whoami)
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

    # Multiple simultaneous source IPs
    local active_ips
    active_ips=$(echo "$sessions" | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
    local ip_count; ip_count=$(echo "$active_ips" | grep -c '.' 2>/dev/null || echo 0)
    if [ "$ip_count" -gt 1 ]; then
        warn "$ip_count different IPs have active sessions simultaneously:"
        while IFS= read -r ip; do warn "  ${BOLD}$ip${RESET}"; done <<< "$active_ips"
        fix "If any IP is unrecognised, kill their session: sudo pkill -9 -u <user>"
    elif [ "$ip_count" -eq 1 ]; then
        ok "All active sessions from a single IP: ${BOLD}$(echo "$active_ips")${RESET}"
    fi

    # Long-idle sessions
    local idle_sessions
    idle_sessions=$(echo "$sessions" | awk '$5 ~ /^[0-9]+:[0-9]+/ && substr($5,1,2)+0 >= 1 {print $1, $3, "idle", $5}' || true)
    [ -n "$idle_sessions" ] && warn "Long-idle session(s) — may be a forgotten open connection:" \
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
    local login_lines
    login_lines=$(echo "$output" | grep -v 'reboot\|wtmp\|^$' | head -20)

    local unique_ips
    unique_ips=$(echo "$login_lines" | awk '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
    local ip_count; ip_count=$(echo "$unique_ips" | grep -c '.' 2>/dev/null || echo 0)

    # Off-hours logins (midnight–5am)
    local odd_hour_logins
    odd_hour_logins=$(echo "$login_lines" | awk '{
        for(i=1;i<=NF;i++) if($i ~ /^[0-2][0-9]:[0-5][0-9]$/) {
            h=substr($i,1,2)+0; if(h>=0 && h<5) print $0
        }
    }' || true)

    if [ "$ip_count" -eq 0 ]; then
        ok "No external IP logins in this sample."
    elif [ "$ip_count" -eq 1 ]; then
        ok "All logins from a single IP: ${BOLD}$(echo "$unique_ips")${RESET} — consistent with one admin location."
    elif [ "$ip_count" -le 3 ]; then
        warn "$ip_count distinct source IPs — expected if you connect from multiple locations:"
        while IFS= read -r ip; do info "  ${BOLD}$ip${RESET}"; done <<< "$unique_ips"
    else
        flag "$ip_count distinct source IPs in recent login history — unusually high."
        fix "Review each IP. Block unknowns with: sudo ufw deny from <ip>"
        while IFS= read -r ip; do info "  ${BOLD}$ip${RESET}"; done <<< "$unique_ips"
    fi

    if [ -n "$odd_hour_logins" ]; then
        warn "Login(s) detected between midnight and 5am — verify these were you:"
        while IFS= read -r l; do warn "  $l"; done <<< "$odd_hour_logins"
        fix "If unexpected: grep 'Accepted' /var/log/auth.log"
    else
        ok "No logins during unusual hours (midnight–5am)."
    fi

    local reboot_count; reboot_count=$(echo "$output" | grep -c 'reboot' || echo 0)
    if [ "$reboot_count" -ge 5 ]; then
        warn "$reboot_count reboots in recent history — could indicate crashes or an attacker clearing state."
        fix "Check kernel logs: sudo journalctl -k -b -1 | tail -30"
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
    local total; total=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0)

    local top_ips
    top_ips=$(grep 'Failed password' /var/log/auth.log 2>/dev/null \
        | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
        | awk '{print $2}' | sort | uniq -c | sort -rn | head -5)

    local top_users
    top_users=$(grep 'Failed password' /var/log/auth.log 2>/dev/null \
        | grep -oP '(?<=for (invalid user )?)\S+(?= from)' \
        | sort | uniq -c | sort -rn | head -5)

    if [ "$total" -eq 0 ]; then
        ok "No failed login attempts on record."
    elif [ "$total" -lt 50 ]; then
        ok "$total failed attempt(s) — low noise, likely background internet scanning."
    elif [ "$total" -lt 500 ]; then
        warn "$total failed attempts — your server is being probed."
        fix "Install fail2ban: sudo apt install fail2ban -y"
    else
        flag "$total failed attempts — sustained brute-force attack in progress."
        fix "sudo apt install fail2ban -y && sudo systemctl enable --now fail2ban"
        fix "Also set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
    fi

    if [ -n "$top_ips" ]; then
        info "Top attacking IPs:"
        while IFS= read -r line; do
            local count ip
            count=$(echo "$line" | awk '{print $1}'); ip=$(echo "$line" | awk '{print $2}')
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

    if [ -n "$top_users" ]; then
        local invalid_count; invalid_count=$(grep -c 'invalid user' /var/log/auth.log 2>/dev/null || echo 0)
        [ "$invalid_count" -gt 10 ] && warn "$invalid_count attempts for non-existent usernames — credential stuffing."
        info "Most targeted usernames:"
        while IFS= read -r line; do
            info "  $(echo "$line" | awk '{print $1}') attempts → '$(echo "$line" | awk '{print $2}')'"
        done <<< "$top_users"
    fi

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        ok "fail2ban is active — repeat offenders are being automatically blocked."
        local banned; banned=$(sudo fail2ban-client status sshd 2>/dev/null | grep 'Banned IP' | awk -F: '{print $2}' | xargs)
        [ -n "$banned" ] && info "Currently banned IPs: $banned"
    else
        warn "fail2ban is not running — failed logins are not being auto-blocked."
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
    local total; total=$(grep -c 'Accepted' /var/log/auth.log 2>/dev/null || echo 0)
    local pw_logins; pw_logins=$(grep -c 'Accepted password' /var/log/auth.log 2>/dev/null || echo 0)
    local key_logins; key_logins=$(grep -c 'Accepted publickey' /var/log/auth.log 2>/dev/null || echo 0)
    local root_logins; root_logins=$(grep 'Accepted' /var/log/auth.log 2>/dev/null | grep 'for root' || true)

    [ "$key_logins" -gt 0 ] && ok "$key_logins login(s) via SSH public key (most secure)."
    if [ "$pw_logins" -gt 0 ]; then
        flag "$pw_logins login(s) via password — vulnerable to brute-force."
        fix "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config, then restart ssh"
    fi

    if [ -n "$root_logins" ]; then
        flag "Direct root login(s) detected."
        fix "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: sudo systemctl restart ssh"
        while IFS= read -r l; do flag "  $l"; done <<< "$root_logins"
    else
        ok "No direct root logins on record."
    fi

    local all_ips
    all_ips=$(grep 'Accepted' /var/log/auth.log 2>/dev/null \
        | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort -u)
    local ip_count; ip_count=$(echo "$all_ips" | grep -c '.' 2>/dev/null || echo 0)

    if [ "$ip_count" -eq 0 ]; then
        [ "$total" -gt 0 ] && info "No external IPs found — logins may be from internal network."
    elif [ "$ip_count" -eq 1 ]; then
        ok "All successful logins from a single IP: ${BOLD}$(echo "$all_ips")${RESET}"
    else
        warn "$ip_count distinct IPs have successfully logged in — verify each one:"
        while IFS= read -r ip; do
            warn "  ${BOLD}$ip${RESET}"
            fix "  Restrict SSH: sudo ufw allow from $ip to any port 22"
        done <<< "$all_ips"
        fix "After allowlisting your IP, block all others: sudo ufw deny 22"
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

    _analyse_keys() {
        local label="$1" keys="$2"
        local count; count=$(echo "$keys" | grep -cE '^(ssh-|ecdsa-|sk-)' 2>/dev/null || echo 0)
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
                    ok "  ${BOLD}$comment${RESET} — Ed25519 (modern, strong)" ;;
                ecdsa-sha2-*|sk-ecdsa-*)
                    ok "  ${BOLD}$comment${RESET} — ECDSA (good)" ;;
                ssh-rsa)
                    local bits
                    bits=$(echo "$keyline" | ssh-keygen -l -f /dev/stdin 2>/dev/null | awk '{print $1}' || echo "?")
                    if [ "$bits" != "?" ] && [ "$bits" -lt 2048 ] 2>/dev/null; then
                        flag "  ${BOLD}$comment${RESET} — RSA ${bits}-bit (too weak, must be ≥2048)"
                        fix "  Regenerate: ssh-keygen -t ed25519 -C 'your@email'"
                    elif [ "$bits" != "?" ] && [ "$bits" -lt 4096 ] 2>/dev/null; then
                        warn "  ${BOLD}$comment${RESET} — RSA ${bits}-bit (Ed25519 preferred)"
                    else
                        ok "  ${BOLD}$comment${RESET} — RSA key"
                    fi ;;
                ssh-dss)
                    flag "  ${BOLD}$comment${RESET} — DSA key (obsolete and broken — remove immediately)"
                    fix "  ssh-keygen -t ed25519 -C 'your@email'" ;;
                *)  warn "  ${BOLD}$comment${RESET} — unknown key type: $keytype" ;;
            esac
        done <<< "$keys"

        local no_comment; no_comment=$(echo "$keys" | grep -cE '^(ssh-|ecdsa-|sk-)[^ ]+ [^ ]+$' 2>/dev/null || echo 0)
        [ "$no_comment" -gt 0 ] && warn "  $no_comment key(s) have no comment — add comments to identify each device."
    }

    _analyse_keys "current user ($(whoami))" "$user_keys"
    echo
    if [ -n "$root_keys" ]; then
        flag "Root has authorized SSH keys — direct root key login is possible."
        fix "Remove root keys: sudo rm /root/.ssh/authorized_keys"
        _analyse_keys "root" "$root_keys"
    else
        ok "No authorized keys for root."
    fi

    local other_keys
    other_keys=$(sudo find /home -name authorized_keys 2>/dev/null | grep -v "$(whoami)" || true)
    if [ -n "$other_keys" ]; then
        info "authorized_keys files found for other users:"
        while IFS= read -r f; do
            local kcount; kcount=$(sudo grep -cE '^(ssh-|ecdsa-|sk-)' "$f" 2>/dev/null || echo 0)
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

    local root_login pw_auth port pubkey max_tries grace empty_pw x11 tcp_fwd alive banner
    root_login=$(_val permitrootlogin);   pw_auth=$(_val passwordauthentication)
    port=$(_val port);                    pubkey=$(_val pubkeyauthentication)
    max_tries=$(_val maxauthtries);       grace=$(_val logingracetime)
    empty_pw=$(_val permitemptypasswords); x11=$(_val x11forwarding)
    tcp_fwd=$(_val allowtcpforwarding);   alive=$(_val clientaliveinterval)
    banner=$(_val banner)

    case "$root_login" in
        no)                  ok "PermitRootLogin no — root cannot log in over SSH." ;;
        yes)                 flag "PermitRootLogin yes — root can log in with a password."
                             fix "Set 'PermitRootLogin no' in /etc/ssh/sshd_config" ;;
        prohibit-password)   warn "PermitRootLogin prohibit-password — root can log in with a key."
                             fix "Set 'PermitRootLogin no' unless you specifically need root key access." ;;
        forced-commands-only) info "PermitRootLogin forced-commands-only — limited to specific commands." ;;
    esac

    case "$pw_auth" in
        no)  ok "PasswordAuthentication no — key-only login enforced." ;;
        yes) flag "PasswordAuthentication yes — password logins allowed, enabling brute-force."
             fix "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config" ;;
    esac

    [ "$empty_pw" = "yes" ] && flag "PermitEmptyPasswords yes — passwordless accounts can log in!" \
        && fix "Set 'PermitEmptyPasswords no' immediately."

    [ "$pubkey" = "no" ] && flag "PubkeyAuthentication disabled — SSH key login won't work." \
        && fix "Set 'PubkeyAuthentication yes'" \
        || ok "PubkeyAuthentication yes — SSH key login enabled."

    [ "$port" = "22" ] \
        && warn "SSH on default port 22 — bots constantly scan this port." \
        && fix "Change port in /etc/ssh/sshd_config to reduce scan noise (e.g. 2222). Update firewall too." \
        || ok "SSH on non-default port $port — reduces automated scan traffic."

    if [ -n "$max_tries" ] && [ "$max_tries" -gt 3 ] 2>/dev/null; then
        warn "MaxAuthTries $max_tries — allows $max_tries password attempts per connection."
        fix "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config"
    else
        ok "MaxAuthTries ${max_tries:-default} — acceptable."
    fi

    if [ -n "$grace" ] && [ "$grace" -gt 30 ] 2>/dev/null; then
        warn "LoginGraceTime ${grace}s — long window for unauthenticated connections."
        fix "Set 'LoginGraceTime 20' in /etc/ssh/sshd_config"
    else
        ok "LoginGraceTime ${grace:-default} — acceptable."
    fi

    [ "$x11" = "yes" ] && warn "X11Forwarding yes — unnecessary attack surface if you don't use GUI forwarding." \
        && fix "Set 'X11Forwarding no'"

    [ "$tcp_fwd" = "yes" ] && warn "AllowTcpForwarding yes — SSH tunnelling enabled, can bypass firewall rules." \
        && fix "Set 'AllowTcpForwarding no' if you don't use port forwarding."

    if [ -z "$alive" ] || [ "$alive" -eq 0 ] 2>/dev/null; then
        warn "ClientAliveInterval not set — idle sessions stay open indefinitely."
        fix "Add 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' to /etc/ssh/sshd_config"
    else
        ok "ClientAliveInterval ${alive}s — idle sessions will time out."
    fi

    [ -z "$banner" ] || [ "$banner" = "none" ] && info "No SSH login banner configured." \
        || ok "SSH login banner set: $banner"

    pause
}
