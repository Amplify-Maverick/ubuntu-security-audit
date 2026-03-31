#!/usr/bin/env bash
# audit/checks_system.sh — Processes, network, persistence, users, filesystem (options 7–20)
# Sourced by server_audit.sh. Requires lib.sh to be sourced first.

check_processes() {
    header "All Running Processes"
    desc "Full process tree with CPU and memory usage."
    local output; output=$(ps auxf)
    echo "$output"; echo

    analysis_header

    local miner_names=("xmrig" "minerd" "kdevtmpfsi" "kthreaddi" "sysupdate"
        "networkservice" "cryptonight" "cpuminer" "ccminer" "bfgminer"
        "cgminer" "ethminer" "claymore" "phoenixminer" "lolminer")
    local found_miner=0
    for name in "${miner_names[@]}"; do
        local match
        match=$(echo "$output" | grep -v 'grep\|server_audit' | grep -i "$name" | grep -v '\[' || true)
        if [ -n "$match" ]; then
            flag "Known miner process name: ${BOLD}$name${RESET}"
            echo "$match"
            fix "Kill it: sudo pkill -f $name && sudo find / -name '$name' -delete 2>/dev/null"
            found_miner=1
        fi
    done
    [ "$found_miner" -eq 0 ] && ok "No known crypto miner process names found."

    # Processes with deleted executables — fileless malware indicator
    local deleted_exes
    deleted_exes=$(ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | awk '{print $NF}' | sed 's/ (deleted)//' || true)
    if [ -n "$deleted_exes" ]; then
        flag "Process(es) running from deleted executables — strong indicator of fileless malware:"
        while IFS= read -r d; do
            local pid; pid=$(echo "$d" | grep -oE '/proc/[0-9]+' | grep -oE '[0-9]+')
            local pname; pname=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            flag "  PID $pid ($pname)"
            fix "  Investigate: cat /proc/$pid/cmdline | tr '\\0' ' '"
        done <<< "$deleted_exes"
    else
        ok "No processes running from deleted executables."
    fi

    # High CPU (>50%) by non-kernel processes
    local high_cpu
    high_cpu=$(echo "$output" | awk 'NR>1 && $3>50 && $11!~/^\[/ {printf "  PID %-6s  CPU %-6s  User %-10s  %s\n", $2, $3"%", $1, $11}')
    if [ -n "$high_cpu" ]; then
        warn "Process(es) consuming >50% CPU — miners always appear here:"
        echo "$high_cpu"
        fix "Investigate: sudo lsof -p <PID> && cat /proc/<PID>/cmdline | tr '\\0' ' '"
    else
        ok "No non-kernel processes with >50% CPU usage."
    fi

    # Unknown root processes
    local known_root=("systemd" "sshd" "cron" "nginx" "rsyslogd" "agetty" "multipathd"
        "snapd" "amazon-ssm" "udisksd" "ModemManager" "polkitd" "irqbalance"
        "chronyd" "unattended" "networkd-dispatcher" "python3" "udevd" "journald"
        "logind" "acpid" "dbus-daemon" "init" "bash" "sh" "ps" "grep" "awk")
    local suspicious_root
    suspicious_root=$(echo "$output" | awk 'NR>1 && $1=="root" && $11!~/^\[/ {print $2, $11}' | while read -r pid cmd; do
        base=$(basename "$cmd" 2>/dev/null || echo "$cmd"); known=0
        for k in "${known_root[@]}"; do [[ "$base" == *"$k"* ]] && known=1 && break; done
        [ "$known" -eq 0 ] && echo "  PID $pid: $cmd"
    done || true)
    if [ -n "$suspicious_root" ]; then
        warn "Root processes not in the known-legitimate list (review these):"
        echo "$suspicious_root"
        fix "Investigate: sudo lsof -p <PID>"
    fi

    pause
}

check_ports() {
    header "Listening Ports"
    desc "Shows all ports the server is listening on, correlated with the owning process."
    local output; output=$(ss -tulpn)
    echo "$output"; echo

    analysis_header
    local public; public=$(echo "$output" | grep -E '(0\.0\.0\.0|:::| \*:)' | grep LISTEN)
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

    local local_count; local_count=$(echo "$output" | grep -c '127\.' || echo 0)
    [ "$local_count" -gt 0 ] && ok "$local_count port(s) on localhost only — not reachable externally."

    local high_public; high_public=$(echo "$public" | grep -oE ':[0-9]+' | tr -d ':' | awk '$1>10000')
    if [ -n "$high_public" ]; then
        warn "High port(s) exposed publicly: $high_public"
        fix "Confirm these belong to legitimate services: sudo ss -tulpn | grep <port>"
    fi

    pause
}

check_outbound() {
    header "Established Outbound Connections"
    desc "Active connections this server has opened to external hosts."
    local output; output=$(ss -tupn state established 2>/dev/null)
    echo "$output"; echo

    analysis_header
    local conn_count; conn_count=$(echo "$output" | grep -c 'ESTAB' 2>/dev/null || echo 0)

    if [ "$conn_count" -eq 0 ]; then
        ok "No established outbound connections — clean."
        pause; return
    fi

    info "$conn_count established connection(s) found."

    local miner_ports=(3333 4444 14444 45700 5555 7777 9999 3032 14433 45560)
    for p in "${miner_ports[@]}"; do
        local hit; hit=$(echo "$output" | grep ":$p[^0-9]" || true)
        if [ -n "$hit" ]; then
            flag "Connection on port $p — known crypto mining pool port!"
            echo "$hit"
            fix "Kill it: sudo ss -tulpn | grep $p, then: sudo kill -9 <PID>"
        fi
    done

    local remote_ips
    remote_ips=$(echo "$output" | grep ESTAB | awk '{print $6}' \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | grep -v '127\.' || true)

    if [ -n "$remote_ips" ]; then
        info "Unique remote IPs with active connections:"
        while IFS= read -r ip; do
            local proc; proc=$(echo "$output" | grep "$ip" | grep -oP '(?<=\(\(")[^"]+' | head -1 || echo "unknown")
            if echo "$ip" | grep -qE '^(169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)'; then
                ok "  ${BOLD}$ip${RESET} ($proc) — AWS link-local/metadata, expected."
            else
                info "  ${BOLD}$ip${RESET} ($proc)"
                fix "  Verify: whois $ip  or  curl -s https://ipinfo.io/$ip"
            fi
        done <<< "$remote_ips"
    fi

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

check_firewall() {
    header "Firewall (UFW)"
    desc "Audits UFW status, default policies, active rules, and cross-references open ports."

    # ── Raw output ────────────────────────────────────────────────────────────
    echo -e "${GREEN}\$ sudo ufw status verbose${RESET}"
    local ufw_output
    ufw_output=$(sudo ufw status verbose 2>/dev/null)
    echo "$ufw_output"
    echo

    analysis_header

    # ── UFW installed? ────────────────────────────────────────────────────────
    if ! command -v ufw &>/dev/null; then
        flag "UFW is not installed — no firewall is protecting this server."
        fix "Install and enable: sudo apt install ufw -y && sudo ufw default deny incoming && sudo ufw allow 22 && sudo ufw enable"
        pause; return
    fi

    # ── UFW active? ───────────────────────────────────────────────────────────
    local status
    status=$(sudo ufw status 2>/dev/null | head -1)
    if echo "$status" | grep -qi "inactive"; then
        flag "UFW is installed but ${BOLD}inactive${RESET} — the firewall is off and all ports are unprotected."
        fix "Enable UFW: sudo ufw enable"
        fix "Before enabling, ensure port 22 is allowed: sudo ufw allow 22"
        pause; return
    fi
    ok "UFW is active."

    # ── Default policies ──────────────────────────────────────────────────────
    local default_in default_out default_fwd
    default_in=$(echo  "$ufw_output" | grep -i 'default.*incoming' | grep -oiE 'deny|allow|reject' | head -1)
    default_out=$(echo "$ufw_output" | grep -i 'default.*outgoing' | grep -oiE 'deny|allow|reject' | head -1)
    default_fwd=$(echo "$ufw_output" | grep -i 'default.*forward'  | grep -oiE 'deny|allow|reject' | head -1)

    case "${default_in,,}" in
        deny|reject) ok "Default incoming policy: ${BOLD}${default_in}${RESET} — only explicitly allowed ports are reachable." ;;
        allow)       flag "Default incoming policy: ${BOLD}ALLOW${RESET} — all ports are open unless explicitly blocked."
                     fix "Set a safe default: sudo ufw default deny incoming" ;;
        *)           warn "Could not determine default incoming policy — verify manually: sudo ufw status verbose" ;;
    esac

    case "${default_out,,}" in
        allow)       ok "Default outgoing policy: ${BOLD}ALLOW${RESET} — normal for most servers." ;;
        deny|reject) warn "Default outgoing policy: ${BOLD}${default_out}${RESET} — legitimate services may be blocked."
                     info "Ensure DNS (53), HTTP (80), HTTPS (443), and NTP (123) are explicitly allowed out." ;;
        *)           info "Default outgoing policy: ${default_out:-unknown}" ;;
    esac

    [ -n "$default_fwd" ] && info "Default forwarding policy: ${BOLD}$default_fwd${RESET}"

    # ── Parse active rules ────────────────────────────────────────────────────
    local rules
    rules=$(sudo ufw status numbered 2>/dev/null | grep '^\[')

    if [ -z "$rules" ]; then
        warn "No UFW rules defined — UFW is active but allowing nothing in by default."
        fix "At minimum allow SSH: sudo ufw allow 22/tcp"
        pause; return
    fi

    # ── SSH rule check — must exist or you risk lockout ──────────────────────
    local ssh_port
    ssh_port=$(sudo sshd -T 2>/dev/null | grep '^port ' | awk '{print $2}')
    ssh_port="${ssh_port:-22}"

    local ssh_rule_found=0
    echo "$rules" | grep -qE "(${ssh_port}[^0-9]|OpenSSH|ssh)" && ssh_rule_found=1
    if [ "$ssh_rule_found" -eq 0 ]; then
        flag "No UFW rule found for SSH (port ${ssh_port}) — you may be locked out after a reconnect."
        fix "Add rule immediately: sudo ufw allow ${ssh_port}/tcp"
    else
        ok "SSH (port ${ssh_port}) has an allow rule — remote access is protected."
    fi

    # ── Overly permissive rules ───────────────────────────────────────────────
    # Rules allowing ANY source on sensitive ports
    local any_rules
    any_rules=$(echo "$rules" | grep -v '^\[.*\].*Anywhere.*DENY\|REJECT'         | grep -E 'ALLOW\s+Anywhere|ALLOW IN\s+Anywhere' || true)

    local dangerous_ports=(21 23 25 53 110 135 139 143 445 1433 1521 2375 2376 3306 3389 5432 5900 6379 8080 27017)
    local found_dangerous=0
    while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        for p in "${dangerous_ports[@]}"; do
            if echo "$rule" | grep -qE "(^|[^0-9])${p}([^0-9]|$)"; then
                flag "Port ${BOLD}$p${RESET} is allowed from ${BOLD}Anywhere${RESET} — this is a high-risk service port."
                echo "  $rule"
                fix "  Restrict to a specific IP: sudo ufw delete <rule_number> && sudo ufw allow from <your-ip> to any port $p"
                found_dangerous=1
            fi
        done
    done <<< "$any_rules"
    [ "$found_dangerous" -eq 0 ] && ok "No high-risk service ports are open to the world."

    # ── Rules allowing all traffic from Anywhere (no port restriction) ────────
    local wildcard_rules
    wildcard_rules=$(echo "$rules" | grep -E 'ALLOW\s+Anywhere$|ALLOW IN\s+Anywhere$'         | grep -v '/\|port\|[0-9]' || true)
    if [ -n "$wildcard_rules" ]; then
        flag "Rule(s) allowing ALL traffic from Anywhere — no port restriction:"
        while IFS= read -r r; do flag "  $r"; done <<< "$wildcard_rules"
        fix "Replace with specific port rules and delete the wildcard: sudo ufw status numbered, then sudo ufw delete <n>"
    fi

    # ── IPv6 rules ────────────────────────────────────────────────────────────
    local ipv6_rules; ipv6_rules=$(echo "$rules" | grep -c 'v6' || echo 0)
    local ipv4_rules; ipv4_rules=$(echo "$rules" | grep -cv 'v6' || echo 0)
    if [ "$ipv6_rules" -gt 0 ]; then
        ok "IPv6 rules present ($ipv6_rules rule(s)) — both IPv4 and IPv6 are covered."
    else
        warn "No IPv6 rules found — if IPv6 is enabled on this server, it may be unfiltered."
        fix "Check: ip -6 addr show. If IPv6 is active, mirror your IPv4 rules for IPv6."
    fi

    # ── Cross-reference: open ports vs firewall rules ─────────────────────────
    info "Cross-referencing listening ports against firewall rules..."
    local listening_ports
    listening_ports=$(ss -tulpn 2>/dev/null         | grep -E '0\.0\.0\.0:|:::' | grep LISTEN         | grep -oE ':[0-9]+\s' | tr -d ': ' | sort -un)

    local unprotected=0
    while IFS= read -r port; do
        [ -z "$port" ] && continue
        # Check if this port has a UFW allow rule
        local covered=0
        echo "$rules" | grep -qE "(^|[^0-9])${port}([^0-9]|$|/)" && covered=1
        # Also consider it covered if default incoming is deny (all not-allowed = blocked)
        [ "${default_in,,}" = "deny" ] || [ "${default_in,,}" = "reject" ] && covered=1

        if [ "$covered" -eq 0 ] && [ "${default_in,,}" = "allow" ]; then
            warn "Port ${BOLD}$port${RESET} is listening publicly but has no explicit UFW rule."
            fix "  Add a rule or block it: sudo ufw allow $port  or  sudo ufw deny $port"
            unprotected=$(( unprotected + 1 ))
        fi
    done <<< "$listening_ports"
    [ "$unprotected" -eq 0 ] && ok "All publicly listening ports are accounted for by the firewall policy."

    # ── Logging ───────────────────────────────────────────────────────────────
    local logging
    logging=$(echo "$ufw_output" | grep -i 'logging' | head -1 || true)
    if echo "$logging" | grep -qi 'off\|disabled'; then
        warn "UFW logging is off — blocked connection attempts are not being recorded."
        fix "Enable logging: sudo ufw logging on"
    elif [ -n "$logging" ]; then
        ok "UFW logging is enabled: $logging"
    fi

    pause
}

check_enabled_services() {
    header "Enabled Systemd Services"
    desc "Services configured to start automatically at boot."
    local output; output=$(systemctl list-unit-files --state=enabled 2>/dev/null)
    echo "$output"; echo

    analysis_header
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
        local svc; svc=$(echo "$line" | awk '{print $1}')
        [[ -z "$svc" || "$svc" == "UNIT" || "$svc" == "systemd-"* ]] && continue
        local k=0
        for kn in "${known[@]}"; do [[ "$svc" == *"$kn"* ]] && k=1 && break; done
        [ "$k" -eq 0 ] && unknown_services+=("$svc")
    done <<< "$(echo "$output" | grep 'enabled')"

    if [ "${#unknown_services[@]}" -eq 0 ]; then
        ok "All enabled services match known Ubuntu/AWS service patterns."
    else
        warn "${#unknown_services[@]} service(s) not in the known-legitimate list — review:"
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
    local output; output=$(systemctl list-units --type=service --state=running 2>/dev/null)
    echo "$output"; echo

    analysis_header
    local count; count=$(echo "$output" | grep -c 'running' 2>/dev/null || echo 0)
    ok "$count service(s) currently running."

    local failed; failed=$(systemctl list-units --type=service --state=failed 2>/dev/null | grep 'failed' || true)
    if [ -n "$failed" ]; then
        warn "Failed service(s) — a crashed service can open security gaps:"
        while IFS= read -r l; do
            warn "  $l"
            local svc; svc=$(echo "$l" | awk '{print $1}')
            fix "  Inspect: sudo journalctl -u $svc -n 20"
        done <<< "$failed"
    else
        ok "No failed services."
    fi

    pause
}

check_crontabs() {
    header "Crontabs (All Users)"
    desc "Scheduled tasks for all users — a common malware persistence mechanism."
    local all_crons="" found=0

    for u in $(cut -f1 -d: /etc/passwd); do
        local cron; cron=$(crontab -u "$u" -l 2>/dev/null | grep -v '^#' || true)
        if [ -n "$cron" ]; then
            echo -e "${GREEN}[user: $u]${RESET}"; echo "$cron"; echo
            all_crons="${all_crons}
${cron}"; found=1
        fi
    done
    [ "$found" -eq 0 ] && echo "(no user crontabs found)"; echo

    desc "System cron directories:"
    ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ 2>/dev/null; echo

    analysis_header
    if [ "$found" -eq 0 ]; then
        ok "No user crontabs — clean."
    else
        declare -A CRON_PATTERNS
        CRON_PATTERNS["curl .* | bash"]="downloads and immediately executes remote code"
        CRON_PATTERNS["wget .* | bash"]="downloads and immediately executes remote code"
        CRON_PATTERNS["wget .* -O .* && bash"]="downloads a file then executes it"
        CRON_PATTERNS["curl .* -o .* && bash"]="downloads a file then executes it"
        CRON_PATTERNS["/tmp/"]="executes from /tmp — common malware location"
        CRON_PATTERNS["/dev/shm"]="executes from /dev/shm — common malware location"
        CRON_PATTERNS["base64 -d"]="decodes and possibly executes a base64-encoded payload"
        CRON_PATTERNS["\$(.*curl\|.*wget"]="command substitution fetching remote content"
        CRON_PATTERNS["python.*-c"]="inline Python — can hide obfuscated commands"
        CRON_PATTERNS["perl.*-e"]="inline Perl — can hide obfuscated commands"
        CRON_PATTERNS["bash -i"]="interactive shell in cron — classic reverse shell setup"
        CRON_PATTERNS["nc .*-e"]="netcat with -e — classic reverse shell"
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
        [ "$clean" -eq 1 ] && ok "No high-risk patterns in user crontabs."
    fi

    local sys_cron; sys_cron=$(cat /etc/cron.d/* /etc/crontab 2>/dev/null || true)
    if echo "$sys_cron" | grep -qE '/tmp/|/dev/shm|base64|curl.*\|.*sh|wget.*\|.*sh'; then
        flag "Suspicious pattern in system cron files (/etc/cron.d or /etc/crontab)."
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
        warn "${#unknown_scripts[@]} unfamiliar init.d script(s):"
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
    local output; output=$(grep -v '/nologin\|/false' /etc/passwd)
    echo "$output"; echo

    analysis_header
    local human_users
    human_users=$(echo "$output" | awk -F: '$3>=1000 && $1!="nobody" {print $1, $3, $7}')
    if [ -n "$human_users" ]; then
        ok "Human account(s) with shell access (UID ≥ 1000):"
        while IFS= read -r line; do
            local user uid shell
            user=$(echo "$line" | awk '{print $1}'); uid=$(echo "$line" | awk '{print $2}')
            shell=$(echo "$line" | awk '{print $3}')
            ok "  ${BOLD}$user${RESET} (UID $uid, shell: $shell)"
            local pw_status; pw_status=$(sudo passwd -S "$user" 2>/dev/null | awk '{print $2}')
            case "$pw_status" in
                P)  warn "  ↳ $user has a password set — SSH key-only login is more secure." ;;
                NP) flag "  ↳ $user has NO PASSWORD — account accessible without credentials!"
                    fix "  sudo passwd $user" ;;
                L)  ok "  ↳ $user's password is locked (key-only — good)." ;;
            esac
        done <<< "$human_users"
    fi

    local system_with_shell
    system_with_shell=$(echo "$output" | awk -F: '$3>0 && $3<1000 && ($7=="/bin/bash" || $7=="/bin/sh") {print $1, $3}')
    if [ -n "$system_with_shell" ]; then
        flag "System account(s) with an interactive shell — should use /usr/sbin/nologin:"
        while IFS= read -r line; do
            flag "  ${BOLD}$(echo "$line" | awk '{print $1}')${RESET} (UID $(echo "$line" | awk '{print $2}'))"
            fix "  sudo usermod -s /usr/sbin/nologin $(echo "$line" | awk '{print $1}')"
        done <<< "$system_with_shell"
    else
        ok "No system accounts have an interactive shell."
    fi

    pause
}

check_root_uid() {
    header "Users With UID 0 (root-level)"
    desc "Every account with UID 0 has full system control."
    local output; output=$(awk -F: '$3==0' /etc/passwd)
    echo "$output"; echo

    analysis_header
    local count; count=$(echo "$output" | grep -c '.' 2>/dev/null || echo 0)

    if [ "$count" -eq 1 ] && echo "$output" | grep -q '^root:'; then
        ok "Only 'root' has UID 0 — expected."
    elif [ "$count" -eq 0 ]; then
        warn "No UID 0 account found — root may have been renamed."
    else
        flag "$count accounts with UID 0 — only 'root' should have UID 0!"
        flag "Extra UID 0 accounts are the oldest attacker backdoor trick."
        echo "$output" | grep -v '^root:' | while IFS= read -r line; do
            local extra_user; extra_user=$(echo "$line" | cut -d: -f1)
            flag "  Backdoor account: ${BOLD}$extra_user${RESET}"
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
    sudo ls /etc/sudoers.d/ 2>/dev/null; echo

    analysis_header
    local sudoers; sudoers=$(sudo cat /etc/sudoers 2>/dev/null)

    local nopasswd_all; nopasswd_all=$(echo "$sudoers" | grep -v '^#' | grep 'NOPASSWD' | grep 'ALL' || true)
    local nopasswd_limited; nopasswd_limited=$(echo "$sudoers" | grep -v '^#' | grep 'NOPASSWD' | grep -v 'ALL' || true)

    if [ -n "$nopasswd_all" ]; then
        flag "NOPASSWD ALL — these entries can run any command as root without a password:"
        while IFS= read -r l; do flag "  $l"; done <<< "$nopasswd_all"
        fix "Remove NOPASSWD from /etc/sudoers or restrict to specific commands"
    elif [ -n "$nopasswd_limited" ]; then
        warn "NOPASSWD entries for specific commands (review):"
        while IFS= read -r l; do warn "  $l"; done <<< "$nopasswd_limited"
    else
        ok "No NOPASSWD entries — sudo always requires a password."
    fi

    local unrestricted; unrestricted=$(echo "$sudoers" | grep -v '^#' | grep 'ALL=(ALL.*) ALL' | grep -v 'NOPASSWD' || true)
    [ -n "$unrestricted" ] && info "Full sudo access (with password) granted to:" \
        && while IFS= read -r l; do info "  $l"; done <<< "$unrestricted"

    local sudod_files; sudod_files=$(sudo ls /etc/sudoers.d/ 2>/dev/null | grep -v README || true)
    if [ -n "$sudod_files" ]; then
        info "Additional sudoers.d files:"
        while IFS= read -r f; do
            local content; content=$(sudo cat "/etc/sudoers.d/$f" 2>/dev/null | grep -v '^#' | grep -v '^$' || true)
            info "  ${BOLD}$f${RESET}:"
            [ -n "$content" ] && while IFS= read -r l; do info "    $l"; done <<< "$content"
            echo "$content" | grep -q 'NOPASSWD.*ALL' \
                && flag "  /etc/sudoers.d/$f grants NOPASSWD ALL — high risk!" \
                && fix "  sudo rm /etc/sudoers.d/$f  (after verifying it is not needed)"
        done <<< "$sudod_files"
    else
        ok "No additional files in /etc/sudoers.d/."
    fi

    pause
}

check_suid() {
    header "SUID Binaries"
    desc "Executables that run as their owner (often root) regardless of who launches them."
    spinner_start "Scanning filesystem for SUID binaries..."
    local output; output=$(find / -perm -4000 -type f 2>/dev/null)
    spinner_stop
    echo "$output"; echo

    analysis_header

    # Cross-reference against dpkg — unpackaged SUID binaries are suspicious
    spinner_start "Verifying SUID binaries against installed packages..."
    local unpackaged=() pkg_count=0
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        local pkg; pkg=$(dpkg -S "$path" 2>/dev/null | cut -d: -f1 || true)
        [ -z "$pkg" ] && unpackaged+=("$path") || pkg_count=$(( pkg_count + 1 ))
    done <<< "$output"

    spinner_stop
    ok "$pkg_count SUID binaries owned by installed packages — expected."
    if [ "${#unpackaged[@]}" -gt 0 ]; then
        flag "${#unpackaged[@]} SUID binary/binaries NOT owned by any package:"
        for f in "${unpackaged[@]}"; do
            flag "  ${BOLD}$f${RESET}"
            fix "  Check: ls -la $f && file $f && strings $f | head -20"
            fix "  Remove SUID if not needed: sudo chmod u-s $f"
        done
    else
        ok "All SUID binaries are owned by installed packages."
    fi

    # Shells or interpreters with SUID — instant root escalation
    local suid_shells; suid_shells=$(echo "$output" | grep -E '/(bash|sh|dash|zsh|python|perl|ruby|node|php)$' || true)
    if [ -n "$suid_shells" ]; then
        flag "SUID set on a shell or interpreter — grants instant root to anyone who runs it!"
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
    spinner_start "Scanning /etc for recently modified files..."
    local output; output=$(find /etc -mtime -7 -type f 2>/dev/null)
    spinner_stop
    echo "$output"; echo

    analysis_header
    local count; count=$(echo "$output" | grep -c '.' 2>/dev/null || echo 0)
    info "$count file(s) in /etc modified in the last 7 days."

    # ── Provisioning window filter ──────────────────────────────────────────
    local boot_epoch
    boot_epoch=$(date -d "$(uptime -s)" +%s 2>/dev/null \
        || date -j -f "%Y-%m-%d %H:%M:%S" "$(uptime -s)" +%s 2>/dev/null \
        || echo 0)
    local provision_cutoff=$(( boot_epoch + 600 ))  # 10 min after boot

    local cloud_init_files=(
        "/etc/passwd" "/etc/shadow" "/etc/shadow-" "/etc/gshadow" "/etc/gshadow-"
        "/etc/group" "/etc/subuid" "/etc/subgid" "/etc/hostname" "/etc/machine-id"
        "/etc/ssh/ssh_host_rsa_key" "/etc/ssh/ssh_host_rsa_key.pub"
        "/etc/ssh/ssh_host_ecdsa_key" "/etc/ssh/ssh_host_ecdsa_key.pub"
        "/etc/ssh/ssh_host_ed25519_key" "/etc/ssh/ssh_host_ed25519_key.pub"
        "/etc/netplan/50-cloud-init.yaml" "/etc/apt/sources.list.d/ubuntu.sources"
        "/etc/udev/rules.d/90-cloud-init-hook-hotplug.rules" "/etc/ld.so.cache"
    )
    local cloud_init_patterns=("/etc/pam.d/common-" "/etc/ssh/ssh_host_")

    _is_provisioning_write() {
        local f="$1"
        for ci in "${cloud_init_files[@]}"; do [ "$f" = "$ci" ] && return 0; done
        for pat in "${cloud_init_patterns[@]}"; do [[ "$f" == "$pat"* ]] && return 0; done
        if [ "$boot_epoch" -gt 0 ]; then
            local mtime; mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
            [ "$mtime" -le "$provision_cutoff" ] && return 0
        fi
        return 1
    }

    local suppressed=()
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        _is_provisioning_write "$f" && suppressed+=("$f")
    done <<< "$output"

    if [ "${#suppressed[@]}" -gt 0 ]; then
        ok "${#suppressed[@]} file(s) modified during provisioning (cloud-init/first boot) — suppressed as expected:"
        for f in "${suppressed[@]}"; do info "  $f"; done; echo
    fi

    local tier1=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config"
        "/etc/ld.so.preload" "/etc/pam.d/sshd" "/etc/pam.d/sudo"
        "/etc/pam.d/common-auth" "/etc/profile" "/etc/bash.bashrc"
        "/etc/environment" "/etc/crontab")
    local tier2=("/etc/hosts" "/etc/resolv.conf" "/etc/nsswitch.conf"
        "/etc/ssh/ssh_config" "/etc/sysctl.conf" "/etc/security/limits.conf"
        "/etc/apt/sources.list")

    local t1_hit=0 t2_hit=0
    for f in "${tier1[@]}"; do
        echo "$output" | grep -qF "$f" || continue
        _is_provisioning_write "$f" && continue
        if [ "$f" = "/etc/ld.so.preload" ]; then
            flag "${BOLD}/etc/ld.so.preload${RESET} was modified — rootkits inject malicious libraries via this file!"
            fix "Inspect immediately: cat /etc/ld.so.preload — should be empty on a clean system."
        else
            local mtime_human; mtime_human=$(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1 || echo "unknown")
            flag "Critical config modified post-provisioning: ${BOLD}$f${RESET} (at $mtime_human)"
            fix "Verify: debsums -c && sudo ausearch -f $f 2>/dev/null | tail -20"
        fi
        t1_hit=1
    done

    for f in "${tier2[@]}"; do
        echo "$output" | grep -qF "$f" || continue
        _is_provisioning_write "$f" && continue
        local mtime_human; mtime_human=$(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1 || echo "unknown")
        warn "Sensitive config modified post-provisioning: ${BOLD}$f${RESET} (at $mtime_human)"
        t2_hit=1
    done

    [ "$t1_hit" -eq 0 ] && [ "$t2_hit" -eq 0 ] \
        && ok "No critical config files were modified after provisioning."

    local last_apt; last_apt=$(grep -E 'install|upgrade' /var/log/dpkg.log 2>/dev/null | tail -3 || true)
    [ -n "$last_apt" ] && info "Recent apt activity (may explain some modifications):" \
        && while IFS= read -r l; do info "  $l"; done <<< "$last_apt"

    pause
}

check_bin_modified() {
    header "Recently Modified System Binaries (last 30 days)"
    desc "Rootkits replace core binaries like ps, ls, and netstat to hide their activity."
    spinner_start "Scanning system binaries for recent modifications..."
    local output; output=$(find /usr/bin /usr/sbin /bin /sbin -mtime -30 -type f 2>/dev/null)
    spinner_stop
    echo "$output"; echo

    analysis_header
    local count; count=$(echo "$output" | grep -c '.' 2>/dev/null || echo 0)

    if [ "$count" -eq 0 ]; then
        ok "No system binaries modified in the last 30 days."
        pause; return
    fi

    info "$count binary/binaries modified in the last 30 days."

    local apt_dates; apt_dates=$(grep -E 'upgrade|install' /var/log/dpkg.log 2>/dev/null | awk '{print $1}' | sort -u | tail -10)
    if [ -n "$apt_dates" ]; then
        ok "Recent package activity found — changes are likely legitimate upgrades."
        info "Dates of recent apt operations: $(echo "$apt_dates" | tr '\n' ' ')"
    else
        warn "No recent apt/dpkg activity found but binaries were modified."
        fix "Verify each binary: dpkg -S <path> then: debsums <package-name>"
    fi

    local tier1_bins=("ps" "ls" "top" "netstat" "ss" "find" "who" "w" "last"
        "login" "sshd" "cron" "bash" "sh" "awk" "grep" "sed" "cat")
    local tier1_hit=0
    while IFS= read -r f; do
        local base; base=$(basename "$f")
        for r in "${tier1_bins[@]}"; do
            if [ "$base" = "$r" ]; then
                flag "High-value binary modified: ${BOLD}$f${RESET} — rootkits routinely replace this."
                fix "Verify: dpkg -S $f && debsums $(dpkg -S $f 2>/dev/null | cut -d: -f1)"
                tier1_hit=1; break
            fi
        done
    done <<< "$output"
    [ "$tier1_hit" -eq 0 ] && ok "None of the highest-risk binaries (ps, ls, ss, sshd etc.) were modified."

    if command -v debsums &>/dev/null; then
        spinner_start "Running debsums integrity check (this may take a while)..."
        local debsums_fail; debsums_fail=$(sudo debsums -c 2>/dev/null | grep -v 'OK$' || true)
        spinner_stop
        if [ -n "$debsums_fail" ]; then
            flag "debsums found hash mismatches:"
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
    local hidden; hidden=$(find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null)
    echo -e "${GREEN}\$ find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null${RESET}"
    [ -n "$hidden" ] && echo "$hidden" || echo "(none found)"; echo
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

    local exec_tmp
    exec_tmp=$(find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null | grep -vE '\.(sh|py|rb|pl)$' || true)
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

    local large_files; large_files=$(find /tmp /var/tmp /dev/shm -type f -size +1M 2>/dev/null || true)
    if [ -n "$large_files" ]; then
        warn "Large file(s) (>1MB) in /tmp — could be downloaded payloads:"
        while IFS= read -r f; do
            local size; size=$(du -sh "$f" 2>/dev/null | awk '{print $1}')
            warn "  ${BOLD}$f${RESET} ($size)"
            fix "  Inspect: file $f && ls -la $f"
        done <<< "$large_files"
    fi

    pause
}
