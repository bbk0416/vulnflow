@echo off
setlocal
cd /d %~dp0
where python >nul 2>nul || (echo Python 3.12 or later is required. & exit /b 1)
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
python -m pip install --upgrade pip || exit /b 1
pip install -r requirements.txt || exit /b 1
start "" http://127.0.0.1:8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
endlocal
