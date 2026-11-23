# Run a trusted copy of this verifier independently of the downloaded package.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$PackageDirectory,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256
)
$ErrorActionPreference="Stop"
$root=[IO.Path]::GetFullPath($PackageDirectory).TrimEnd('\')
if ($root -notmatch '^[A-Za-z]:\\' -or $root.Contains('~')) { throw "Canonical local path required." }
$drive=[IO.DriveInfo]::new($root.Substring(0,3))
if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -ne 'NTFS') { throw "Fixed NTFS required." }
function Check-Item([string]$Path, [bool]$Directory) {
 $i=Get-Item -LiteralPath $Path -Force
 if ($i.PSIsContainer -ne $Directory -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Unexpected filesystem object." }
 return $i
}
# Check each ancestor, including the root directory.
$ancestor=$root
while ($ancestor) {
 $null=Check-Item $ancestor $true
 $next=[IO.Path]::GetDirectoryName($ancestor)
 if (-not $next -or $next -eq $ancestor) { break }
 $ancestor=$next
}
$manifest=Join-Path $root "SHA256SUMS.txt"
$m=Check-Item $manifest $false
if ($m.Length -lt 1 -or $m.Length -gt 262144) { throw "Unexpected manifest size." }
if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256) { throw "Untrusted package manifest." }
$expected=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($line in [IO.File]::ReadAllLines($manifest)) {
 if ($line -cnotmatch '^([a-f0-9]{64}) \*\./([A-Za-z0-9_. -]+(?:/[A-Za-z0-9_. -]+)*)$') { throw "Invalid package manifest line." }
 $digest=$Matches[1]; $rel=$Matches[2]
 foreach ($part in $rel.Split('/')) {
  if ($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.|$)') { throw "Ambiguous package path." }
 }
 if ($rel -ieq 'SHA256SUMS.txt' -or $expected.ContainsKey($rel)) { throw "Duplicate or self-referential manifest." }
 $expected.Add($rel,$digest)
 if ($expected.Count -gt 2000) { throw "Package inventory too large." }
}
foreach ($critical in @('bin/Quantic-Sillage-Launcher.exe','bin/Vault-PQ-lab.exe','bin/Scattering-Pacer.exe','runtime/node.exe','Start-Windows-PQ-Lab.ps1','Test-Windows-PQ-Package.ps1','Quantic-Sillage-Alpha.ps1','scripts/native-vault-windows-local.mjs','scripts/native-vault-windows-mailbox.mjs','scripts/provision-windows-two-party-lab.mjs','desktop/windows-two-party-provision-lab.mjs','scripts/native-windows-mail-readiness.mjs','desktop/native-windows-mail-readiness.mjs','scripts/serve-native-scattering-windows.mjs','scripts/verify-migration-local.mjs','scripts/quantic-pay-lab.mjs','scripts/quantic-pay-native.mjs','lib/quantic/pay-sandbox.mjs','lib/quantic/pay-demo-authorization.mjs','lib/quantic/pay-lab-checkpoint.mjs','lib/quantic/pay-quorum-flow.mjs','scripts/quantic-pay-quorum-demo.mjs','scripts/quantic-pay-quorum-local.mjs','scripts/quantic-pay-native-quorum.mjs','scripts/quantic-pay-remote-check.mjs','scripts/quantic-pay-operator.mjs','scripts/quantic-pay-circulation.mjs','lib/quantic/pay-circulation-session.mjs','lib/quantic/pay-circulation-lab.mjs','lib/quantic/pay-circulation-recovery.mjs','lib/quantic/pay-operator-config.mjs','lib/quantic/pay-eu-readiness.mjs','lib/quantic/pay-native-remote-flow.mjs','lib/quantic/pay-witness-quorum-client.mjs','lib/quantic/pay-scattering-client.mjs')) {
 if (-not $expected.ContainsKey($critical)) { throw "Required component missing." }
}
# Walk without following junctions or links, reject unlisted files, hash all bytes.
$todo=[Collections.Generic.Stack[string]]::new()
$todo.Push($root)
$count=0
while($todo.Count -gt 0) {
 $d=$todo.Pop()
 foreach($entry in Get-ChildItem -LiteralPath $d -Force) {
  if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point refused." }
  if ($entry.PSIsContainer) { $todo.Push($entry.FullName); continue }
  $rel=$entry.FullName.Substring($root.Length+1).Replace('\','/')
  if ($rel -ceq 'SHA256SUMS.txt') { continue }
  if (-not $expected.ContainsKey($rel)) { throw "Unlisted package file." }
  if ((Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash -ine $expected[$rel]) { throw "Package file integrity failure." }
  $null=$expected.Remove($rel)
  $count++
 }
}
if ($expected.Count -ne 0) { throw "Missing package files." }
if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256) { throw "Manifest changed during verification." }
Write-Output ("Verified files: "+$count)
