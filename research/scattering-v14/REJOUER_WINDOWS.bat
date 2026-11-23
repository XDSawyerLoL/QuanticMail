@echo off
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 22 ou plus recent est necessaire : https://nodejs.org/
  pause
  exit /b 1
)
echo Verification Quantic Scattering V1.4 - banc de recherche hors ligne
node --test tests\v14.test.mjs
if errorlevel 1 (echo ECHEC DES TESTS & pause & exit /b 1)
node scripts\run-audit.mjs 5000
if errorlevel 1 (echo ECHEC AUDIT & pause & exit /b 1)
echo Audit termine. Lire results\v14-benchmark.json et README.md
pause
