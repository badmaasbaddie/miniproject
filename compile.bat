@echo off
echo ========================================================
echo   Compiling Password Security Suite (web edition)
echo ========================================================
if exist "bin" rmdir /s /q bin
mkdir bin
dir /s /b src\*.java > sources.txt
javac -d bin @sources.txt
set RESULT=%errorlevel%
del sources.txt
if %RESULT% equ 0 (
    echo.
    echo [SUCCESS] Compiled into 'bin'. Run 'run.bat' to start the website.
) else (
    echo.
    echo [ERROR] Compilation failed. Please check your JDK installation.
)
pause
