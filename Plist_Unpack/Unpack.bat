@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Usage: double-click or run: Unpack.bat [root_folder]
set "ROOT=%~1"
if "%ROOT%"=="" set "ROOT=."

rem Choose your Python launcher
set "PYTHON=python"

rem Resolve this .bat's directory (where the .py files live)
set "HERE=%~dp0"

echo [INFO] Root: %ROOT%
echo [INFO] Using Python: %PYTHON%
echo [INFO] Script dir: %HERE%
echo.

set "OUTFLAG="

:ASK_CUSTOM_OUT
choice /C YN /M "Do you want to specify an output folder? (Y/N)"
if errorlevel 2 goto NOOUT
if errorlevel 1 goto ASKOUT

:ASKOUT
set /P OUTPATH="Enter output folder path: "
if "%OUTPATH%"=="" (
  echo [WARN] Empty path. Try again or press N next time.
  goto ASK_CUSTOM_OUT
)
set "OUTFLAG=--out \"%OUTPATH%\""
echo [INFO] Output folder set to: %OUTPATH%
goto RUN

:NOOUT
echo [INFO] Using default output (next to sources).

:RUN
echo.
echo --- Pass 1: plist/json (unpacker.py) ---
"%PYTHON%" "%HERE%unpacker.py" "%ROOT%" --ext auto %OUTFLAG%
set "EC=%ERRORLEVEL%"
if not "%EC%"=="0" (
  echo [ERROR] unpacker.py exit code: %EC%
  echo (continuing to next pass)
)

echo.
echo --- Pass 2: legacy plist only (UnpackPlist.py) ---
"%PYTHON%" "%HERE%UnpackPlist.py" "%ROOT%" %OUTFLAG%
set "EC=%ERRORLEVEL%"
if not "%EC%"=="0" (
  echo [ERROR] UnpackPlist.py exit code: %EC%
)

echo.
echo [DONE] All passes finished.
echo Press any key to exit . . .
pause >nul

endlocal
