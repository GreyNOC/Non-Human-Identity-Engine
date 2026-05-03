@echo off
setlocal

cd /d "%~dp0"

if "%~1"=="" (
    python -m greynoc_nhi --gui
) else (
    python -m greynoc_nhi %*
)

endlocal
