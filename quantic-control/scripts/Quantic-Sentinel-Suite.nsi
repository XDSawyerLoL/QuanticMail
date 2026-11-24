Unicode true
Name "Quantic Sillage - Sentinel et Identity Vault (Alpha)"
OutFile "${OUTPUT_EXE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\QuanticSillage\SentinelSuite-${BUILD_ID}"
SetCompressor /SOLID lzma
Page instfiles
UninstPage instfiles

; No recursive uninstall, no existing build overwrite.
!macro CheckDir PATH FAILURE
 System::Call 'kernel32::GetFileAttributesW(w "${PATH}") i .r0'
 IntCmp $0 -1 ${FAILURE} 0 0
 IntOp $1 $0 & 0x410
 IntCmp $1 0x10 +1 ${FAILURE} ${FAILURE}
!macroend

Section "Installation native"
 SetShellVarContext current
 StrCpy $INSTDIR "$LOCALAPPDATA\QuanticSillage\SentinelSuite-${BUILD_ID}"
 !insertmacro CheckDir "$LOCALAPPDATA" failed
 IfFileExists "$LOCALAPPDATA\QuanticSillage\." parent 0
 CreateDirectory "$LOCALAPPDATA\QuanticSillage"
 parent:
 !insertmacro CheckDir "$LOCALAPPDATA\QuanticSillage" failed
 System::Call 'kernel32::GetFileAttributesW(w "$INSTDIR") i .r0'
 IntCmp $0 -1 fresh refused refused
 fresh:
 SetOverwrite off
 SetOutPath "$INSTDIR"
 IfErrors failed
 File /r "${PACKAGE_DIR}\*"
 IfErrors failed
 WriteUninstaller "$INSTDIR\Uninstall-QuanticSentinelSuite.exe"
 IfErrors failed
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSentinelSuite-${BUILD_ID}" "DisplayName" "Quantic Sillage - Sentinel et Identity Vault Alpha ${BUILD_ID}"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSentinelSuite-${BUILD_ID}" "UninstallString" '"$INSTDIR\Uninstall-QuanticSentinelSuite.exe"'
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSentinelSuite-${BUILD_ID}" "InstallLocation" "$INSTDIR"
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSentinelSuite-${BUILD_ID}" "NoModify" 1
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSentinelSuite-${BUILD_ID}" "NoRepair" 1
 IfErrors failed
 IfFileExists "$SMPROGRAMS\Quantic Sentinel Alpha ${BUILD_ID}.lnk" complete 0
 CreateShortCut "$SMPROGRAMS\Quantic Sentinel Alpha ${BUILD_ID}.lnk" "$INSTDIR\QuanticSentinel.exe" "" "$INSTDIR\QuanticSentinel.exe"
 IfErrors failed
 complete:
 SetErrorLevel 0
 Goto done
 refused:
 SetErrorLevel 2
 Abort "Cette version existe deja. Aucun fichier remplace."
 failed:
 SetErrorLevel 1
 Abort "Installation refusee ou incomplete. Les coffres existants sont conserves."
 done:
SectionEnd

Section "Uninstall"
 SetShellVarContext current
 StrCpy $INSTDIR "$LOCALAPPDATA\QuanticSillage\SentinelSuite-${BUILD_ID}"
 !insertmacro CheckDir "$LOCALAPPDATA" refused
 !insertmacro CheckDir "$LOCALAPPDATA\QuanticSillage" refused
 !insertmacro CheckDir "$INSTDIR" refused
 ; Do not silently disable or remove an existing resident agent.
 ClearErrors
 ReadRegStr $2 HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "QuanticSentinelUserAgent"
 IfErrors noagent 0
 StrCmp $2 "" noagent agent
 noagent:
 IfFileExists "$INSTDIR\Uninstall-QuanticSentinelSuite.exe" 0 refused
 !include "${UNINSTALL_CHECKS_NSH}"
 !include "${UNINSTALL_LIST_NSH}"
 ClearErrors
 FindFirst $3 $4 "$INSTDIR\*"
 inspect:
 StrCmp $4 "" clean
 StrCmp $4 "." next
 StrCmp $4 ".." next
 StrCmp $4 "Uninstall-QuanticSentinelSuite.exe" next
 FindClose $3
 Goto preserved
 next:
 FindNext $3 $4
 IfErrors clean inspect
 clean:
 FindClose $3
 Delete "$INSTDIR\Uninstall-QuanticSentinelSuite.exe"
 ClearErrors
 RMDir "$INSTDIR"
 IfErrors preserved
 Delete "$SMPROGRAMS\Quantic Sentinel Alpha ${BUILD_ID}.lnk"
 DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\QuanticSentinelSuite-${BUILD_ID}"
 SetErrorLevel 0
 Goto done
 agent:
 MessageBox MB_OK|MB_ICONEXCLAMATION "Desinstallez d'abord l'agent resident depuis Sentinel." /SD IDOK
 SetErrorLevel 3
 Quit
 refused:
 MessageBox MB_OK|MB_ICONEXCLAMATION "Dossier de version absent ou non sur. Aucun fichier supprime." /SD IDOK
 SetErrorLevel 2
 Quit
 preserved:
 MessageBox MB_OK|MB_ICONEXCLAMATION "Des fichiers inconnus ou utilises sont conserves. Verifiez le dossier avant de relancer." /SD IDOK
 SetErrorLevel 2
 Quit
 done:
SectionEnd
