#!/usr/bin/env bash
# Alpha distribution, no installer, no credentials, no network service.
set -euo pipefail
sentinel="$1"
vault="$2"
dst="$3"
test -f "$sentinel"
test -f "$vault"
test ! -e "$dst"
mkdir -p "$dst/licenses"
cp "$sentinel" "$dst/QuanticSentinel.exe"
cp "$vault" "$dst/IdentityVault.exe"
# Only resolve non-system imports from the selected UCRT64 build toolchain.
# Unknown imports are fatal, not silently satisfied by the runner's PATH.
for pass in $(seq 1 16); do
 changed=0
 for bin in "$dst/"*.exe "$dst/"*.dll; do
  [[ -f "$bin" ]] || continue
  imports="$(objdump -p "$bin" | awk '/DLL Name:/ {print $3}' | tr -d '\r')"
  while IFS= read -r dll; do
   [[ -n "$dll" ]] || continue
   [[ "$dll" =~ ^[A-Za-z0-9_.-]+[.][dD][lL][lL]$ ]] || exit 1
   lower="$(printf '%s' "$dll" | tr A-Z a-z)"
   case "$lower" in
    api-ms-win-*|ext-ms-win-*) continue ;;
   esac
   if [[ -f "$dst/$dll" ]]; then continue; fi
   if [[ -f "/ucrt64/bin/$dll" ]]; then
    cp "/ucrt64/bin/$dll" "$dst/$dll"
    changed=1
   elif [[ -f "/c/Windows/System32/$dll" ]]; then
    # Operating system dependencies are not redistributed.
    continue
   else
    echo "Unresolved import $dll in $bin" >&2
    exit 1
   fi
  done <<< "$imports"
 done
 [[ "$changed" == 1 ]] || break
done
test "$changed" == 0
for p in openssl gcc gcc-libs libwinpthread zlib zstd libffi; do
 if [[ -d "/ucrt64/share/licenses/$p" ]]; then
  cp -R "/ucrt64/share/licenses/$p" "$dst/licenses/"
 fi
done
test -d "$dst/licenses/openssl"
# Package provenance, no user files or private keys.
printf 'Sentinel commit: %s\nIdentity Vault commit: %s\n' "$4" "$5" > "$dst/BUILD.txt"
pacman -Q mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-gcc >> "$dst/BUILD.txt"
cat > "$dst/README.txt" <<'EOF'
Quantic Sentinel / Identity Vault - Alpha Windows x64 non signee.
Extraire ensemble tous les fichiers dans un dossier local prive.
Ne pas lancer depuis le ZIP. Ne pas remplacer un antivirus existant.
La consultation via Identity Vault exige un enrôlement laboratoire
prealablement valide, un coffre et son controleur existants, ainsi que
les autorites de quorum configurees. Aucun secret n'est inclus.
Le fichier SHA256SUMS.txt est un inventaire, pas une signature editeur.
Ne pas utiliser ce paquet pour des donnees de production.
EOF
(
 cd "$dst"
 find . -type f ! -name SHA256SUMS.txt -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --binary > SHA256SUMS.txt
 sha256sum -c SHA256SUMS.txt
)
