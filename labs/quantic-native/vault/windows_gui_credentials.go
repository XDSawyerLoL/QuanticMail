//go:build windows && cgo && pqopenssl

package main

/*
#cgo LDFLAGS: -lcredui -luser32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincred.h>
#include <credui.h>

static int qv_gui_password(const WCHAR *label, WCHAR *dst, DWORD capacity) {
    CREDUI_INFOW ui;
    WCHAR user[80] = L"Quantic Alpha Test";
    ZeroMemory(&ui, sizeof(ui));
    ui.cbSize = sizeof(ui);
    ui.pszCaptionText = L"Quantic Sillage - coffre de laboratoire";
    ui.pszMessageText = label;
    SecureZeroMemory(dst, capacity * sizeof(WCHAR));
    // Never enumerate credentials or save them to Windows Credential Manager.
    DWORD flags = CREDUI_FLAGS_GENERIC_CREDENTIALS |
                  CREDUI_FLAGS_ALWAYS_SHOW_UI |
                  CREDUI_FLAGS_DO_NOT_PERSIST |
                  CREDUI_FLAGS_EXCLUDE_CERTIFICATES;
    DWORD result = CredUIPromptForCredentialsW(
        &ui, L"QuanticSillageAlphaSyntheticOnly", NULL, 0,
        user, 80, dst, capacity, NULL, flags
    );
    SecureZeroMemory(user, sizeof(user));
    if (result != NO_ERROR) {
        SecureZeroMemory(dst, capacity * sizeof(WCHAR));
        return 0;
    }
    return 1;
}
static int qv_gui_approval(const WCHAR *message) {
    int r = MessageBoxW(NULL, message,
        L"Quantic Sillage Alpha - autorisation explicite",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND);
    return r == IDYES;
}
*/
import "C"

import (
    "errors"
    "unsafe"
)

// The GUI path never copies vault passphrases into Node, PowerShell,
// standard input, command arguments or the environment.
// The Win32 credential dialog is hosted in the native Go vault process.
func winGUIPassphrase(label string, secret bool) ([]byte, error) {
    if !secret { return nil, portableRefusal }
    var wide [1027]C.WCHAR
    defer C.SecureZeroMemory(unsafe.Pointer(&wide[0]), C.SIZE_T(len(wide)*2))
    if C.qv_gui_password(winWide(label), &wide[0], C.DWORD(len(wide))) == 0 {
        return nil, errors.New("local Windows credential dialog cancelled")
    }
    length := 0
    for length < len(wide) && wide[length] != 0 { length++ }
    if length == 0 || length > 1024 || length >= len(wide) {
        return nil, portableRefusal
    }
    password := make([]byte, length)
    for i := 0; i < length; i++ {
        ch := uint16(wide[i])
        if ch < 32 || ch > 126 { clear(password); return nil, portableRefusal }
        password[i] = byte(ch)
    }
    return password, nil
}

func winGUIApprove(text string) bool {
    if len(text) == 0 || len(text) > 512 { return false }
    for _, r := range text {
        if r < 32 || r > 126 { return false }
    }
    return C.qv_gui_approval(winWide(text)) != 0
}
