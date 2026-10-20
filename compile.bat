@echo off
cd /d "%~dp0"
echo ========================================================
echo   Compiling Password Security Suite (web edition)
echo ========================================================
where javac >nul 2>nul
if errorlevel 1 goto nojdk
if exist bin rmdir /s /q bin
mkdir bin
javac -d bin src\passwordsecurity\*.java src\passwordsecurity\core\*.java src\passwordsecurity\web\*.java
if errorlevel 1 goto failed
echo.
echo [SUCCESS] Compiled into 'bin'. Now double-click run.bat to start the website.
goto end
:nojdk
echo.
echo [ERROR] 'javac' was not found. Install a JDK (11 or newer) and make sure it is on your PATH.
goto end
:failed
echo.
echo [ERROR] Compilation failed - see the messages above.
:end
pause
