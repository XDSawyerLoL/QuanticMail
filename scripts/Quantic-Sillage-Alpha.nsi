Unicode true
Name "Quantic Sillage - Laboratoire Alpha"
OutFile "${OUTPUT_EXE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\QuanticSillage\Alpha-${BUILD_ID}"
SetCompressor /SOLID lzma
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
 CreateShortCut "$SMPROGRAMS\Quantic Sillage\Alpha-${BUILD_ID}.lnk" "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" '-NoProfile -STA -File "$INSTDIR\app\Start-Windows-PQ-Lab.ps1" -Operation Dashboard -ExpectedManifestSha256 ${MANIFEST_PIN} -TrustedBinarySha256 ${VAULT_PIN}' "$INSTDIR\app\bin\Vault-PQ-lab.exe" 0 SW_SHOWNORMAL
 IfErrors failed
 SetErrorLevel 0
 Goto done
 failed:
 SetErrorLevel 1
 Abort "Installation incomplete. Original identity data was not modified."
 done:
SectionEnd
