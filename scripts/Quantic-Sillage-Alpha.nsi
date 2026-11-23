Unicode true
Name "Quantic Sillage - Laboratoire Alpha"
OutFile "${OUTPUT_EXE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\QuanticSillage\Alpha-${BUILD_ID}"
SetCompressor /SOLID lzma
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
 SetOverwrite off
 SetOutPath "$INSTDIR\app"
 File /r "${PACKAGE_DIR}\*"
 IfErrors failed
 ; Native double-clickable application, built after the package digest
 ; is frozen. The binary embeds both expected SHA256 pins, so there is
 ; no editable command-line hash on the desktop shortcut.
 SetOutPath "$INSTDIR"
 File /oname=Quantic-Sillage-Alpha.exe "${LAUNCHER_EXE}"
 IfErrors failed
 WriteUninstaller "$INSTDIR\Uninstall-Quantic-Sillage-Alpha.exe"
 IfErrors failed
 ; Registration is user-scoped and build-scoped, NEVER a system-wide updater.
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSillageAlpha-${BUILD_ID}" "DisplayName" "Quantic Sillage Alpha - build ${BUILD_ID} (laboratory)"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSillageAlpha-${BUILD_ID}" "UninstallString" '"$INSTDIR\Uninstall-Quantic-Sillage-Alpha.exe"'
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSillageAlpha-${BUILD_ID}" "InstallLocation" "$INSTDIR"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSillageAlpha-${BUILD_ID}" "Publisher" "Quantic Sillage - laboratoire"
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSillageAlpha-${BUILD_ID}" "NoModify" 1
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSillageAlpha-${BUILD_ID}" "NoRepair" 1
 CreateDirectory "$SMPROGRAMS\Quantic Sillage"
 CreateShortCut "$SMPROGRAMS\Quantic Sillage\Alpha-${BUILD_ID}.lnk" "$INSTDIR\Quantic-Sillage-Alpha.exe" "" "$INSTDIR\Quantic-Sillage-Alpha.exe" 0 SW_SHOWNORMAL
 IfErrors failed
 ; Do not overwrite another build's desktop shortcut.
 IfFileExists "$DESKTOP\Quantic Sillage Alpha-${BUILD_ID}.lnk" keepdesktop 0
 CreateShortCut "$DESKTOP\Quantic Sillage Alpha-${BUILD_ID}.lnk" "$INSTDIR\Quantic-Sillage-Alpha.exe" "" "$INSTDIR\Quantic-Sillage-Alpha.exe" 0 SW_SHOWNORMAL
 IfErrors failed
 keepdesktop:
 IfErrors failed
 SetErrorLevel 0
 Goto done
 failed:
 SetErrorLevel 1
 Abort "Installation incomplete. Original identity data was not modified."
 done:
SectionEnd

; The exact uninstall list is generated from the FINAL integrity-verified
; SHA256SUMS.txt and compiled into this self-contained NSIS binary.
; Unknown files NEVER enter the list. No recursive delete is allowed.
Section "Uninstall"
 SetShellVarContext current
 StrCpy $INSTDIR "$LOCALAPPDATA\QuanticSillage\Alpha-${BUILD_ID}"
 IfFileExists "$INSTDIR\Uninstall-Quantic-Sillage-Alpha.exe" +3
  MessageBox MB_ICONEXCLAMATION|MB_OK "This exact Alpha build is not installed. Nothing was deleted." /SD IDOK
  SetErrorLevel 2
  Quit
 !include "${UNINSTALL_LIST_NSH}"
 ClearErrors
 RMDir "$INSTDIR\app"
 IfErrors preserved
 Delete "$INSTDIR\Quantic-Sillage-Alpha.exe"
 Delete "$INSTDIR\Uninstall-Quantic-Sillage-Alpha.exe"
 ClearErrors
 RMDir "$INSTDIR"
 IfErrors preserved
 Delete "$SMPROGRAMS\Quantic Sillage\Alpha-${BUILD_ID}.lnk"
 RMDir "$SMPROGRAMS\Quantic Sillage"
 Delete "$DESKTOP\Quantic Sillage Alpha-${BUILD_ID}.lnk"
 DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSillageAlpha-${BUILD_ID}"
 SetErrorLevel 0
 Goto done
 preserved:
  ; Refuse to delete anything unexpected, including user-created files,
  ; private directories and manually placed migration records.
  MessageBox MB_ICONEXCLAMATION|MB_OK "Unknown files remain in the Alpha folder. They were preserved. Inspect the version directory before trying again." /SD IDOK
  SetErrorLevel 2
  Quit
 done:
SectionEnd
