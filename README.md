# Ubuntu Server Security Audit

An interactive terminal tool for auditing the security of an Ubuntu server. It runs diagnostic commands, analyses the output for red flags, and tells you exactly what to fix and how.

---

## Installation

Clone the repository directly onto your server:

```bash
git clone https://github.com/Amplify-Maverick/ubuntu-security-audit.git
cd ubuntu-security-audit
chmod +x server_audit.sh
```

If `git` isn't installed:

```bash
sudo apt install git -y
```

To update to the latest version later:

```bash
cd ubuntu-security-audit
git pull
```

---

## Usage

Run with `sudo` — several checks require root access to read auth logs, SSH config, and system files:

```bash
sudo ./server_audit.sh
```

### Navigating the menu

- **Arrow keys** — move the cursor up and down
- **Type a number** — jump directly to that option (e.g. type `3` to go to option 3)
- **Enter** — run the selected check
- **Backspace** — clear a typed number
- **q** — quit

---

## What it checks

Each check prints the raw command output followed by an **Analysis** section that interprets the results. Every finding includes a `↳ fix:` line with the exact command to remediate it.

### Analysis markers

| Marker | Meaning |
|--------|---------|
| `[!]` red | Critical — investigate or fix immediately |
| `[~]` amber | Warning — review and consider acting |
| `[✓]` green | Looks good |
| `[-]` cyan | Informational |

### SSH & Authentication (options 1–6)

| # | Check | What it looks for |
|---|-------|-------------------|
| 1 | Active sessions | Unexpected users, simultaneous logins from multiple IPs, long-idle sessions |
| 2 | Recent login history | Off-hours logins (midnight–5am), unusual number of source IPs, frequent reboots |
| 3 | Failed login attempts | Brute-force attack severity, top offending IPs with block commands, credential stuffing |
| 4 | Successful logins | Password vs key-based auth, direct root logins, logins from unexpected IPs |
| 5 | Authorized SSH keys | Key type and strength (Ed25519/ECDSA/RSA/DSA), weak or missing key comments, root keys |
| 6 | SSH daemon config | PermitRootLogin, PasswordAuthentication, port, MaxAuthTries, X11Forwarding, idle timeout |

### Processes & Network (options 7–9)

| # | Check | What it looks for |
|---|-------|-------------------|
| 7 | Running processes | Known miner process names, processes running from deleted executables (fileless malware), high CPU usage |
| 8 | Listening ports | Unexpected publicly exposed ports correlated with their owning process |
| 9 | Outbound connections | Connections to known mining pool ports, C2 beaconing patterns, unexpected remote IPs |

### Persistence & Startup (options 10–13)

| # | Check | What it looks for |
|---|-------|-------------------|
| 10 | Enabled services | Services configured to start at boot that aren't in the known-legitimate set |
| 11 | Running services | Currently active services, any failed services |
| 12 | Crontabs | 14 high-risk patterns (curl\|bash, base64 decode, reverse shells, /tmp execution, etc.) across all user and system crontabs |
| 13 | Startup scripts | Unfamiliar scripts in `/etc/init.d/` and `rc*.d/` |

### Users & Permissions (options 14–17)

| # | Check | What it looks for |
|---|-------|-------------------|
| 14 | Shell users | Human accounts with no password, system accounts with interactive shells |
| 15 | UID 0 accounts | Any account other than `root` with UID 0 (classic attacker backdoor) |
| 16 | Sudoers | NOPASSWD ALL entries, unexpected sudoers.d files granting escalated privileges |
| 17 | SUID binaries | Unpackaged SUID binaries (verified via `dpkg`), shells or interpreters with SUID set |

### File System (options 18–20)

| # | Check | What it looks for |
|---|-------|-------------------|
| 18 | Modified /etc files | Critical configs changed after provisioning — suppresses expected cloud-init writes to avoid false positives |
| 19 | Modified system binaries | Changes to `/bin`, `/usr/bin`, etc. — cross-references `dpkg` log and runs `debsums` hash verification if available |
| 20 | Hidden files in /tmp | Hidden dot-files, executable binaries, and large files (>1MB) in world-writable directories |

### Malware Scanning (options 21–24)

These options install tools if not already present, then run them.

| # | Check | What it does |
|---|-------|--------------|
| 21 | rkhunter | Scans for known rootkits, backdoors, and suspicious file properties |
| 22 | chkrootkit | Second rootkit scanner with different signatures — running both gives higher confidence |
| 23 | ClamAV | Scans `/home`, `/var/www`, and `/tmp` for known malware signatures |
| 24 | Crypto miner detection | Checks process names, filesystem, mining pool ports, high CPU usage, and deleted-executable processes |

### Bulk (option 25)

Runs all 20 non-scanner checks in sequence, then displays an aggregate **risk summary** showing the total number of critical findings and warnings with an overall verdict (clean / moderate risk / high risk).

---

## File structure

```
server_audit.sh          # Entry point — sources modules and launches the menu
audit/
  lib.sh                 # Colours, output helpers (flag/warn/ok/info/fix), risk counters
  menu.sh                # Menu items, box drawing, arrow key / number input, dispatch
  checks_auth.sh         # SSH & authentication checks (options 1–6)
  checks_system.sh       # System, network, persistence, users, filesystem (options 7–20)
  checks_malware.sh      # Malware scanners, miner detection, run_all (options 21–25)
```

---

## Notes

- The script does not make any changes to your system on its own. Every remediation step requires you to run the suggested command manually.
- Malware scanner options (21–23) will run `apt install` if the tool is not already present.
- The modified `/etc` files check (option 18) automatically suppresses files written by cloud-init during provisioning so you don't get false positives on a freshly launched instance.
- Tested on Ubuntu 22.04 and 24.04 on AWS EC2. Most checks will work on any Debian-based system.
