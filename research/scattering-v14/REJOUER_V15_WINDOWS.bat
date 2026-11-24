@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
 echo Node.js 22 ou superieur est requis pour les essais V1.5.
 pause
 exit /b 1
)
echo Verification anti-rejeu et authentification V1.4 + V1.5
node --test tests\v14.test.mjs tests\v15.test.mjs
if errorlevel 1 (
 echo ECHEC DES TESTS
 pause
 exit /b 1
)
echo Demonstration UDP locale V1.5
node scripts\demo-udp-v15.mjs
if errorlevel 1 (
 echo ECHEC DEMO UDP
 pause
 exit /b 1
)
echo VALIDATION LOCALE TERMINEE
pause