Unicode true
Name "Quantic Sillage - Alpha native"
OutFile "${OUTPUT_EXE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\QuanticSillage\Alpha-${BUILD_ID}"
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show
Page instfiles
UninstPage instfiles

Section "Quantic Sillage laboratory"
 SetShellVarContext current
 StrCpy $INSTDIR "$LOCALAPPDATA\QuanticSillage\Alpha-${BUILD_ID}"
 ; This installer cannot update an existing installation or touch any vault.
 IfFileExists "$INSTDIR\." 0 fresh
 SetErrorLevel 1
 Abort "A build directory already exists. No files were replaced."
 fresh:
 ; Do not overwrite unrelated user shortcuts either.
 IfFileExists "$SMPROGRAMS\Quantic Sillage\Alpha-${BUILD_ID}.lnk" 0 check_desktop
 SetErrorLevel 1
 Abort "A shortcut with this build name already exists."
 check_desktop:
 IfFileExists "$DESKTOP\Quantic Sillage Alpha-${BUILD_ID}.lnk" 0 install
 SetErrorLevel 1
 Abort "A desktop shortcut with this build name already exists."
 install:
 SetOverwrite off
 SetOutPath "$INSTDIR\app"
 File /r "${PACKAGE_DIR}\*"
 IfErrors failed
 ; Write the uninstaller inside this build's directory only.
 WriteUninstaller "$INSTDIR\Uninstall-Quantic-Sillage-Alpha.exe"
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
 ClearErrors
 CreateShortCut "$SMPROGRAMS\Quantic Sillage\Uninstall Alpha-${BUILD_ID}.lnk" "$INSTDIR\Uninstall-Quantic-Sillage-Alpha.exe"
 IfErrors failed
 SetErrorLevel 0
 Goto done
 failed:
 SetErrorLevel 1
 Abort "Installation incomplete. Original identity data was not modified."
 done:
SectionEnd

Section "Uninstall"
 SetShellVarContext current
 ; Never accept a caller-supplied install path or delete an adjacent Alpha.
 StrCpy $INSTDIR "$LOCALAPPDATA\QuanticSillage\Alpha-${BUILD_ID}"
 IfFileExists "$INSTDIR\Uninstall-Quantic-Sillage-Alpha.exe" found
 SetErrorLevel 2
 Abort "The expected build uninstaller does not exist. No files removed."
 found:
 ; A separately installed resident agent retains its own executable,
 ; locks and audit log. Never silently remove the UI while it is registered.
 ClearErrors
 ReadRegStr $2 HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "QuanticSentinelUserAgent"
 IfErrors noagent
 StrCmp $2 "" noagent
 MessageBox MB_OK|MB_ICONEXCLAMATION "Desactivez d'abord Sentinel dans Protection. Aucun fichier de cette version n'a ete supprime." /SD IDOK
 SetErrorLevel 3
 Quit
 noagent:
 ; Compiler-generated explicit inventory: checks all junctions first,
 ; then deletes known build files only, and removes only empty folders.
 !include "${UNINSTALL_NSH}"
 Delete "$SMPROGRAMS\Quantic Sillage\Alpha-${BUILD_ID}.lnk"
 Delete "$DESKTOP\Quantic Sillage Alpha-${BUILD_ID}.lnk"
 Delete "$SMPROGRAMS\Quantic Sillage\Uninstall Alpha-${BUILD_ID}.lnk"
 RMDir "$SMPROGRAMS\Quantic Sillage"
 Delete "$INSTDIR\Uninstall-Quantic-Sillage-Alpha.exe"
 RMDir "$INSTDIR"
 RMDir "$LOCALAPPDATA\QuanticSillage"
 SetErrorLevel 0
SectionEnd
