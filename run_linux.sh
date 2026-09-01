#!/usr/bin/env sh

# First-run UI language: explicit override wins; otherwise follow the host locale.
if [ -z "${VULNFLOW_UI_LANG:-}" ]; then
  case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
    ko*|KO*|Korean*|korean*) VULNFLOW_UI_LANG=ko ;;
    *) VULNFLOW_UI_LANG=en ;;
  esac
fi
export VULNFLOW_UI_LANG

vulnflow_ui_text() {
  if [ "${VULNFLOW_UI_LANG}" = "ko" ]; then
    printf '%s' "$1"
  else
    printf '%s' "$2"
  fi
}

set -eu
cd "$(dirname "$0")"
: "${VULNFLOW_COORDINATION_DB:=$PWD/data/vulnflow-coordination.db}"
export VULNFLOW_COORDINATION_DB


command -v python3 >/dev/null 2>&1 || {
  echo "Python 3.12 or 3.13 is required." >&2
  exit 1
}
python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] in {(3,12),(3,13)} else 1)' \
  || { echo "VulnFlow supports Python 3.12 or 3.13 only." >&2; exit 1; }

[ -f requirements.lock ] || {
  echo "The verified runtime dependency lock requirements.lock is missing." >&2
  exit 1
}

[ -d .venv ] || python3 -m venv .venv
VENV_PYTHON="$PWD/.venv/bin/python"
[ -x "$VENV_PYTHON" ] || {
  echo "The VulnFlow virtual-environment interpreter is unavailable." >&2
  exit 1
}

if [ -n "${VULNFLOW_WHEELHOUSE:-}" ]; then
  "$VENV_PYTHON" -m pip --disable-pip-version-check install \
    --requirement "$PWD/requirements.lock" \
    --no-index --find-links "$VULNFLOW_WHEELHOUSE"
else
  "$VENV_PYTHON" -m pip --disable-pip-version-check install \
    --requirement "$PWD/requirements.lock"
fi

: "${VULNFLOW_RUNTIME_DEPENDENCY_POLICY:=enforce}"
: "${VULNFLOW_DEMO_MODE:=0}"
: "${VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK:=0}"
: "${VULNFLOW_CONTROL_DB:=$PWD/data/control.db}"
: "${VULNFLOW_DEFAULT_PROJECT_DB:=$PWD/data/projects/default/vulnflow.db}"
export VULNFLOW_RUNTIME_DEPENDENCY_POLICY VULNFLOW_DEMO_MODE VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK
export VULNFLOW_CONTROL_DB VULNFLOW_DEFAULT_PROJECT_DB

if [ "${VULNFLOW_INSTALL_ONLY:-0}" = "1" ]; then
  "$VENV_PYTHON" -c 'from app.services.runtime_dependency_policy import enforce_runtime_dependencies; report=enforce_runtime_dependencies(policy="enforce"); print(f"LOCKED_RUNTIME_PACKAGES={report.expected_packages}")'
  printf '%s
' 'LOCKED_RUNTIME_INSTALLATION=PASS'
  printf '%s
' "LOCKED_RUNTIME_PYTHON=$VENV_PYTHON"
  exit 0
fi

"$VENV_PYTHON" -m scripts.prepare_storage >/dev/null
if [ "$VULNFLOW_DEMO_MODE" != "1" ] && [ -z "${VULNFLOW_API_TOKENS_JSON:-}" ]; then
  active_users="$("$VENV_PYTHON" -c 'from app.core.database_schema import init_db; from app.services.accounts import count_active_users; from pathlib import Path; import os; p=Path(os.environ["VULNFLOW_CONTROL_DB"]); init_db(p); print(count_active_users(p))')"
  if [ "$active_users" -eq 0 ]; then
    printf '\n%s\n' "$(vulnflow_ui_text '최초 관리자 계정을 만듭니다.' 'Creating the first administrator account.')"
    "$VENV_PYTHON" -m scripts.manage_users --db "$VULNFLOW_CONTROL_DB" create --username admin --role admin
  fi
fi
printf '%s\n' 'VulnFlow: http://127.0.0.1:8000/login'
exec "$VENV_PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
