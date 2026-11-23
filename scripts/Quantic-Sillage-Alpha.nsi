Unicode true
Name "Quantic Sillage - Alpha native"
OutFile "${OUTPUT_EXE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\QuanticSillage\Alpha-${BUILD_ID}"
SetCompressor /SOLID lzma
ShowInstDetails show
Page instfiles

Section "Quantic Sillage laboratory"
 SetShellVarContext current
 StrCpy $INSTDIR "$LOCALAPPDATA\QuanticSillage\Alpha-${BUILD_ID}"
 ; This installer cannot update an existing installation or touch any vault.
 IfFileExists "$INSTDIR\." 0 fresh
 SetErrorLevel 1
 Abort "A build directory already exists. No files were replaced."
 fresh:
 SetOverwrite off
 SetOutPath "$INSTDIR\app"
 File /r "${PACKAGE_DIR}\*"
 IfErrors failed
 CreateDirectory "$SMPROGRAMS\Quantic Sillage"
 ; Windows Forms dashboard is local-only; Start Menu and Desktop shortcuts
 ; use checked SHA-256 pins with dedicated native bootstrap, not PowerShell.
 ClearErrors
 CreateShortCut "$SMPROGRAMS\Quantic Sillage\Alpha-${BUILD_ID}.lnk" "$INSTDIR\app\bin\Quantic-Sillage-Launcher.exe" "${MANIFEST_PIN} ${VAULT_PIN}" "$INSTDIR\app\bin\Vault-PQ-lab.exe" 0 SW_SHOWNORMAL
 IfErrors failed
 ClearErrors
 CreateShortCut "$DESKTOP\Quantic Sillage Alpha-${BUILD_ID}.lnk" "$INSTDIR\app\bin\Quantic-Sillage-Launcher.exe" "${MANIFEST_PIN} ${VAULT_PIN}" "$INSTDIR\app\bin\Vault-PQ-lab.exe" 0 SW_SHOWNORMAL
 IfErrors failed
 SetErrorLevel 0
 Goto done
 failed:
 SetErrorLevel 1
 Abort "Installation incomplete. Original identity data was not modified."
 done:
SectionEnd
