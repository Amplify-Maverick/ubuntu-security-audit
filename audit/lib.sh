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
