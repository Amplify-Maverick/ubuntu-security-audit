#!/usr/bin/env bash
# server_audit.sh — Ubuntu Server Security Audit
# Usage: chmod +x server_audit.sh && sudo ./server_audit.sh
# ─────────────────────────────────────────────────────────────────────────────

# Resolve the directory this script lives in so sourcing works from any cwd
AUDIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/audit"

if [ ! -d "$AUDIT_DIR" ]; then
    echo "Error: audit/ directory not found alongside server_audit.sh"
    echo "Expected: $AUDIT_DIR"
    exit 1
fi

# Source modules in dependency order
source "$AUDIT_DIR/lib.sh"
source "$AUDIT_DIR/checks_auth.sh"
source "$AUDIT_DIR/checks_system.sh"
source "$AUDIT_DIR/checks_malware.sh"
source "$AUDIT_DIR/menu.sh"   # defines MENU_ITEMS, draw_menu, dispatch, run_menu

# Launch
run_menu
