#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
command -v python3 >/dev/null 2>&1 || { echo "Python 3.12 or later is required." >&2; exit 1; }
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
printf '%s\n' 'VulnFlow: http://127.0.0.1:8000'
: "${VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK:=1}"
export VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
