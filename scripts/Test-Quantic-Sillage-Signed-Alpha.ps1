# Operator-side release verification. NEVER signs an unsigned binary and
# NEVER treats a synthetic laboratory test as physical two-PC delivery.
# Run only from an independently trusted source checkout.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$Installer,
 [Parameter(Mandatory=$true)][string]$InstalledLauncher,
 [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedPublisherSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedVaultSha256
)
$ErrorActionPreference="Stop"
$exe=Get-Item -LiteralPath $InstalledLauncher -ErrorAction Stop
if ($exe.PSIsContainer -or $exe.Extension -ine ".exe" -or
    ($exe.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $exe.Name -cne "Quantic-Sillage-Alpha.exe") {
 throw "Native application executable required."
}
# Both outer installer and the installed app must bear the *same*
# independently pinned publisher certificate and valid timestamp.
& (Join-Path $PSScriptRoot "Test-Native-Installer-Signature.ps1") -Installer $Installer -ExpectedPublisherSha256 $ExpectedPublisherSha256
& (Join-Path $PSScriptRoot "Test-Native-Installer-Signature.ps1") -Installer $exe.FullName -ExpectedPublisherSha256 $ExpectedPublisherSha256
$root=$exe.DirectoryName
$app=Join-Path $root "app"
& (Join-Path $PSScriptRoot "Test-Windows-PQ-Package.ps1") -PackageDirectory $app -ExpectedManifestSha256 $ExpectedManifestSha256
$vault=Join-Path $app "bin\Vault-PQ-lab.exe"
if ((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $ExpectedVaultSha256) {
 throw "Pinned native vault binary mismatch."
}
# Native GUI EXE only. One test startup cannot prove network delivery.
$process=Start-Process -FilePath $exe.FullName -ArgumentList "--self-test" -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Signed native Alpha EXE failed installed health check." }
Write-Output "Signed Alpha EXE and installer verified. NOT a two-host network or production-readiness approval."
