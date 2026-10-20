@echo off
cd /d "%~dp0"
if not exist bin\passwordsecurity\Main.class (
  echo The project is not compiled yet. Running compile.bat first...
  call compile.bat
)
echo Starting Password Security Suite...
echo Your browser should open automatically. If not, open http://localhost:8080/
echo Keep this window open while you use the site. Press Ctrl+C to stop.
java -cp bin passwordsecurity.Main %*
pause
