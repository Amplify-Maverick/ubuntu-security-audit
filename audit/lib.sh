#!/usr/bin/env bash
# audit/lib.sh — Shared colors, output helpers, and risk counters
# Sourced by all other modules. Do not execute directly.

AMBER='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Output helpers ────────────────────────────────────────────────────────────

divider()         { echo -e "${CYAN}────────────────────────────────────────────────────${RESET}"; }
header()          { clear; echo -e "\n${BOLD}${CYAN}$1${RESET}"; divider; }
desc()            { echo -e "${AMBER}▸ $1${RESET}"; }
run()             { echo -e "${GREEN}\$ $1${RESET}"; eval "$1"; echo; }
pause()           { echo -e "\n${DIM}Press Enter to return to menu...${RESET}"; read -r; }
analysis_header() { echo -e "\n${BOLD}${CYAN}── Analysis ────────────────────────────────────────${RESET}"; }

# ── Analysis markers — flag/warn also increment risk counters ─────────────────

RISK_FLAGS=0
RISK_WARNS=0

flag() { echo -e "  ${RED}${BOLD}[!]${RESET} $1";   RISK_FLAGS=$(( RISK_FLAGS + 1 )); }
warn() { echo -e "  ${AMBER}${BOLD}[~]${RESET} $1"; RISK_WARNS=$(( RISK_WARNS + 1 )); }
ok()   { echo -e "  ${GREEN}${BOLD}[✓]${RESET} $1"; }
info() { echo -e "  ${CYAN}[-]${RESET} $1"; }
fix()  { echo -e "    ${DIM}↳ fix: $1${RESET}"; }

# ── Spinner ───────────────────────────────────────────────────────────────────
# Usage:
#   spinner_start "Scanning filesystem..."
#   result=$(slow_command)
#   spinner_stop
#
# spinner_start launches an animated indicator in the background.
# spinner_stop kills it and erases the spinner line cleanly.
# The command whose output you need must run in a subshell $() as normal —
# the spinner runs independently in the background.

_SPINNER_PID=""

spinner_start() {
    local label="${1:-Working...}"
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    # Run the animation loop as a background job
    (
        while true; do
            printf "\r  ${CYAN}%s${RESET}  %s  " "${frames[$i]}" "$label"
            i=$(( (i + 1) % ${#frames[@]} ))
            sleep 0.1
        done
    ) &
    _SPINNER_PID=$!
    # Prevent the shell from printing "[1] <pid>" job notifications
    disown "$_SPINNER_PID" 2>/dev/null || true
}

spinner_stop() {
    if [ -n "$_SPINNER_PID" ]; then
        kill "$_SPINNER_PID" 2>/dev/null
        wait "$_SPINNER_PID" 2>/dev/null || true
        _SPINNER_PID=""
    fi
    # Erase the spinner line completely
    printf "\r\033[2K"
}
