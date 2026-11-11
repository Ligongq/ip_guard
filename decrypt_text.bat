@echo off
rem ============================================================
rem  Batch wrapper for decrypt_text.py
rem  Usage: double-click to process the folder this .bat lives in,
rem         or drag a folder onto this .bat.
rem ============================================================
setlocal EnableExtensions
title Decrypt IP-Guard encrypted text files

set "TARGET=%~1"
if not defined TARGET set "TARGET=%~dp0"
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"

if not exist "%TARGET%" (
  echo [ERROR] Folder not found: %TARGET%
  pause
  exit /b 1
)

set "SCRIPT=%~dp0decrypt_text.py"
if not exist "%SCRIPT%" (
  echo [ERROR] decrypt_text.py was not found next to this .bat file.
  echo         Keep both files in the same folder.
  pause
  exit /b 1
)

rem ---- locate a Python 3 interpreter -------------------------
set "PY="
for %%I in (python.exe) do set "PY=%%~$PATH:I"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
if not defined PY if exist "%ProgramFiles%\Python310\python.exe" set "PY=%ProgramFiles%\Python310\python.exe"
if not defined PY if exist "%ProgramFiles(x86)%\Python310\python.exe" set "PY=%ProgramFiles(x86)%\Python310\python.exe"

if not defined PY (
  echo [ERROR] python.exe not found.
  echo         Install Python 3 or edit the PY line in this file.
  pause
  exit /b 1
)

chcp 65001 >nul
echo.
echo Target : %TARGET%
echo Python : %PY%
echo.

"%PY%" "%SCRIPT%" "%TARGET%" %2 %3 %4
set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" echo Finished with errors. Exit code: %RC%
echo Press any key to close this window . . .
pause >nul
exit /b %RC%
