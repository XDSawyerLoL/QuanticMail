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
 ; Native double-clickable application, built after the package digest
 ; is frozen. The binary embeds both expected SHA256 pins, so there is
 ; no editable command-line hash on the desktop shortcut.
 SetOutPath "$INSTDIR"
 File /oname=Quantic-Sillage-Alpha.exe "${LAUNCHER_EXE}"
 IfErrors failed
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
