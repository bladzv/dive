#!/usr/bin/env bash
# dev.sh — manage the DIVE local dev server.
#
# Run with no arguments for an interactive menu.
# Or pass a command directly:
#
#   ./scripts/dev.sh run     — start on dummy (test) data   ← shorthand
#   ./scripts/dev.sh stop    — stop the server
#   ./scripts/dev.sh test    — start on dummy data (alias for run)
#   ./scripts/dev.sh real    — start on real data
#   ./scripts/dev.sh reset   — wipe + re-seed dummy data, restart
#   ./scripts/dev.sh logs    — stream server logs
#   ./scripts/dev.sh status  — show what's running

set -euo pipefail

PORT=8766
HOST=127.0.0.1
REAL_DB="data/dive.db"
TEST_DB="data/dev.db"
LOG_FILE="logs/dev-server.log"
MODE_FILE=".dive-db-mode"

# ---------------------------------------------------------------------------
# Colors (disabled when not writing to a terminal, e.g. piped output)
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

_info()    { echo -e "  ${CYAN}→${RESET}  $*"; }
_ok()      { echo -e "  ${GREEN}✓${RESET}  $*"; }
_warn()    { echo -e "  ${YELLOW}!${RESET}  $*"; }
_err()     { echo -e "  ${RED}✗${RESET}  $*" >&2; }
_step()    { echo -e "\n${BOLD}$*${RESET}"; }
_divider() { echo -e "${DIM}────────────────────────────────────────${RESET}"; }

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

_pid() {
  lsof -ti TCP:"$PORT" 2>/dev/null | head -1 || true
}

_mode() {
  cat "$MODE_FILE" 2>/dev/null || echo ""
}

_db_label() {
  case "$(_mode)" in
    test) echo "$TEST_DB  ${DIM}(dummy data)${RESET}" ;;
    real) echo "$REAL_DB" ;;
    *)    echo "${DIM}unknown${RESET}" ;;
  esac
}

_status_line() {
  local pid
  pid=$(_pid)
  if [[ -n "$pid" ]]; then
    echo -e "  ${GREEN}●${RESET} Running   ${BOLD}http://$HOST:$PORT${RESET}   DB: $(_db_label)"
  else
    echo -e "  ${RED}●${RESET} ${DIM}Not running${RESET}"
  fi
}

_require_uvicorn() {
  if ! python3 -m uvicorn --version > /dev/null 2>&1; then
    _err "uvicorn not found. Activate your virtual environment first:"
    echo ""
    echo "       source .venv/bin/activate"
    echo ""
    exit 1
  fi
}

_stop_server() {
  local pid
  pid=$(_pid)
  if [[ -n "$pid" ]]; then
    _info "Stopping server (PID $pid)…"
    kill "$pid" 2>/dev/null || true
    local i=0
    while [[ $i -lt 12 ]] && kill -0 "$pid" 2>/dev/null; do
      sleep 0.25; i=$((i + 1))
    done
    _ok "Server stopped"
  fi
}

_start_server() {
  local db_path="$1" mode="$2"
  mkdir -p logs
  : > "$LOG_FILE"
  DB_PATH="$db_path" python3 -m uvicorn dive.main:app \
    --host "$HOST" --port "$PORT" --reload \
    >> "$LOG_FILE" 2>&1 &
  echo "$mode" > "$MODE_FILE"
  _info "Starting server…"
  local i=0
  while [[ $i -lt 16 ]] && ! _pid > /dev/null 2>&1; do
    sleep 0.25; i=$((i + 1))
  done
  if _pid > /dev/null 2>&1; then
    _ok "Server is up"
    echo ""
    echo -e "  ${BOLD}Open:${RESET}  http://$HOST:$PORT"
    echo -e "  ${BOLD}DB:${RESET}    $db_path"
    echo -e "  ${BOLD}Logs:${RESET}  ./scripts/dev.sh logs"
  else
    _err "Server failed to start. Check the logs:"
    echo ""
    echo "       ./scripts/dev.sh logs"
    echo ""
    exit 1
  fi
}

_seed_test_db() {
  _info "Creating dummy database…"
  if ! DB_PATH="$TEST_DB" python3 scripts/seed_dev.py; then
    _err "Seeding failed — see output above."
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_status() {
  echo ""
  _status_line
  echo ""
}

cmd_test() {
  _require_uvicorn
  _step "Switching to test database (dummy data)"
  _divider
  if [[ ! -f "$TEST_DB" ]]; then
    _seed_test_db
  else
    _ok "Dummy database already exists (use 'reset' to re-seed)"
  fi
  _stop_server
  _start_server "$TEST_DB" "test"
  echo ""
}

cmd_real() {
  _require_uvicorn
  _step "Switching to real database"
  _divider
  if [[ ! -f "$REAL_DB" ]]; then
    _warn "Real database not found at $REAL_DB"
    _warn "Run the pipeline at least once to create it."
    exit 1
  fi
  _stop_server
  _start_server "$REAL_DB" "real"
  echo ""
}

cmd_reset() {
  _require_uvicorn
  _step "Reset test database"
  _divider
  if [[ -f "$TEST_DB" ]]; then
    _warn "This will delete $TEST_DB and re-seed it with fresh dummy data."
    echo ""
    read -rp "  Continue? [y/N] " confirm
    echo ""
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      _info "Cancelled."
      echo ""; exit 0
    fi
  fi
  _stop_server
  rm -f "$TEST_DB"
  _seed_test_db
  _start_server "$TEST_DB" "test"
  echo ""
}

cmd_stop() {
  _step "Stopping server"
  _divider
  if [[ -z "$(_pid)" ]]; then
    _warn "Server is not running."
  else
    _stop_server
  fi
  echo ""
}

cmd_logs() {
  if [[ ! -f "$LOG_FILE" ]]; then
    echo ""
    _warn "No log file yet — start the server first."
    echo ""; exit 1
  fi
  echo -e "\n${DIM}Streaming $LOG_FILE — press Ctrl+C to stop${RESET}\n"
  tail -f "$LOG_FILE"
}

# ---------------------------------------------------------------------------
# Interactive menu (no arguments)
# ---------------------------------------------------------------------------

_menu() {
  while true; do
    clear 2>/dev/null || true
    echo ""
    echo -e "  ${BOLD}DIVE — Dev Server${RESET}"
    _divider
    _status_line
    _divider
    echo ""
    echo -e "  ${BOLD}1${RESET}  ${GREEN}Run${RESET} test server      — start on dummy data (safe)"
    echo -e "  ${BOLD}2${RESET}  ${RED}Stop${RESET} server"
    echo -e "  ${BOLD}3${RESET}  Switch to ${YELLOW}real data${RESET}   — your actual GitHub repos"
    echo -e "  ${BOLD}4${RESET}  Reset test data     — wipe & re-seed dummy database"
    echo -e "  ${BOLD}5${RESET}  View logs"
    echo -e "  ${BOLD}0${RESET}  Exit"
    echo ""
    read -rp "  Pick an option [0-5]: " choice
    echo ""

    case "$choice" in
      1) cmd_test;  read -rp "  Press Enter to return to menu…" _ ;;
      2) cmd_stop;  read -rp "  Press Enter to return to menu…" _ ;;
      3) cmd_real;  read -rp "  Press Enter to return to menu…" _ ;;
      4) cmd_reset; read -rp "  Press Enter to return to menu…" _ ;;
      5) cmd_logs ;;   # Ctrl+C to exit tail and return here
      0|q|Q) echo ""; exit 0 ;;
      *) _warn "Invalid choice — enter a number from 0 to 5." ; sleep 1 ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# Must run from the repo root so relative paths (data/, scripts/) work.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
if [[ "$(pwd)" != "$REPO_ROOT" ]]; then
  cd "$REPO_ROOT"
fi

CMD="${1:-menu}"

case "$CMD" in
  menu)         _menu ;;
  status)       cmd_status ;;
  run|test)     cmd_test ;;    # "run" is the shorthand for test/dummy mode
  real)         cmd_real ;;
  reset)        cmd_reset ;;
  stop)         cmd_stop ;;
  logs)         cmd_logs ;;
  -h|--help|help)
    echo ""
    echo -e "  ${BOLD}Usage:${RESET}  ./scripts/dev.sh [command]"
    echo ""
    echo "  No command   open the interactive menu"
    echo "  run          start server on dummy (test) data  ← most common"
    echo "  stop         stop the server"
    echo "  test         alias for run"
    echo "  real         start server on real data"
    echo "  reset        wipe + re-seed dummy data, restart"
    echo "  logs         stream server logs"
    echo "  status       show current status"
    echo ""
    ;;
  *)
    _err "Unknown command: $CMD"
    echo "  Run ./scripts/dev.sh --help for usage."
    echo ""; exit 1 ;;
esac
