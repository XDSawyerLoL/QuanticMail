#!/usr/bin/env bash
set -euo pipefail
src="$(cygpath -u "$1")"
dst="$(cygpath -u "$2")"
test -f "$src"
test ! -e "$dst"
mkdir -p "$dst/bin" "$dst/desktop" "$dst/lib/quantic" "$dst/scripts" "$dst/licenses" "$dst/runtime"
node_src="$(cygpath -u "$4")"
test -f "$node_src"
test -f "$(dirname "$node_src")/LICENSE"
cp "$node_src" "$dst/runtime/node.exe"
cp "$(dirname "$node_src")/LICENSE" "$dst/licenses/Node-LICENSE.txt"
cp "$src" "$dst/bin/Vault-PQ-lab.exe"
# Native first-party bootstrap: no PowerShell or web link in the installed shortcut.
launcher_src="$(cygpath -u "$5")"
test -s "$launcher_src"
cp "$launcher_src" "$dst/bin/Quantic-Sillage-Launcher.exe"
# Copy Windows non-system DLL imports recursively from the build toolchain.
for pass in $(seq 1 16); do
  changed=0
  for f in "$dst/bin/"*; do
    imports="$(objdump -p "$f" | awk '/DLL Name:/ {print $3}' | tr -d '\r')"
    while IFS= read -r dll; do
      [[ -n "$dll" ]] || continue
      [[ "$dll" =~ ^[A-Za-z0-9_.-]+[.][dD][lL][lL]$ ]] || exit 1
      if [[ -f "/ucrt64/bin/$dll" && ! -f "$dst/bin/$dll" ]]; then
        cp "/ucrt64/bin/$dll" "$dst/bin/$dll"
        changed=1
      fi
    done <<< "$imports"
  done
  if [[ "$changed" == 0 ]]; then break; fi
done
test "$changed" == 0
cp desktop/native-*.mjs "$dst/desktop/"
cp desktop/windows-two-party-provision-lab.mjs "$dst/desktop/"
cp lib/quantic/*.mjs lib/quantic/pqc-runtime-node.ts lib/quantic/pqc-runtime.ts lib/quantic/migration-archive.ts "$dst/lib/quantic/"
cp scripts/migration-windows-16mib-smoke-lab.mjs scripts/migration-windows-smoke-lab.mjs scripts/migration-windows-readback-lab.mjs scripts/native-vault-windows-local.mjs scripts/provision-windows-two-party-lab.mjs scripts/native-windows-mail-readiness.mjs scripts/scattering-physical-probe.mjs scripts/verify-migration-local.mjs scripts/quantic-pay-lab.mjs scripts/quantic-pay-native.mjs scripts/quantic-pay-quorum-demo.mjs scripts/quantic-pay-quorum-local.mjs scripts/quantic-pay-native-quorum.mjs scripts/quantic-pay-remote-check.mjs scripts/quantic-pay-operator.mjs scripts/quantic-pay-circulation.mjs "$dst/scripts/"
cp scripts/Start-Windows-PQ-Lab.ps1 scripts/Test-Windows-PQ-Package.ps1 scripts/Quantic-Sillage-Alpha.ps1 scripts/Quantic-Sillage-GUI-Check.ps1 scripts/Quantic-Sillage-Compose.ps1 scripts/Quantic-Sillage-Advanced.ps1 "$dst/"
mkdir -p "$dst/standalone-relay" "$dst/labs/quantic-native/scattering"
cp standalone-relay/native-scattering-mailbox.mjs "$dst/standalone-relay/"
cp labs/quantic-native/scattering/scattering-{cell,reliable-lab}.mjs "$dst/labs/quantic-native/scattering/"
cp scripts/serve-native-scattering-windows.mjs scripts/native-vault-windows-mailbox.mjs scripts/native-windows-compose-draft.mjs "$dst/scripts/"
cp docs/PHYSICAL_SCATTERING_TEST.md docs/AUDIT_WINDOWS_SCATTERING.md docs/AUDIT_WINDOWS_SCATTERING_MAIL_FLOW.md docs/WINDOWS_TWO_HOST_MAIL_READINESS.md "$dst/"
cp "$(cygpath -u "$3")" "$dst/bin/Scattering-Pacer.exe"
cp docs/AUDIT_WINDOWS_DESKTOP_BRIDGE.md "$dst/"
cp docs/WINDOWS_PQ_LAB_README.md "$dst/README.md"
for p in /ucrt64/share/licenses/openssl /ucrt64/share/licenses/gcc /ucrt64/share/licenses/gcc-libs /ucrt64/share/licenses/libwinpthread /ucrt64/share/licenses/zlib /ucrt64/share/licenses/zstd /ucrt64/share/licenses/libffi; do
  if [[ -d "$p" ]]; then cp -R "$p" "$dst/licenses/"; fi
done
if compgen -G "$dst/bin/libcrypto*.dll" > /dev/null; then
  test -d "$dst/licenses/openssl"
fi
(
 cd "$dst"
 find . -type f ! -name SHA256SUMS.txt -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --binary > SHA256SUMS.txt
 sha256sum -c SHA256SUMS.txt
)
