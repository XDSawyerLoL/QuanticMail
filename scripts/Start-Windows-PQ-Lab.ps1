# Explicit laboratory launcher. No installation, firewall changes or production login.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet("Providers","Open","RecoverOpen","Seal","RecoverSeal","ProbeLoopback")][string]$Operation,
 [string]$TrustedBinarySha256,
 [string]$PrivateDirectory,
 [string]$InputFile,
 [string]$OutputFile
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$vault = Join-Path $root "bin\Vault-PQ-lab.exe"
$pacer = Join-Path $root "bin\Scattering-Pacer.exe"
$node = (Get-Command node.exe -CommandType Application -ErrorAction Stop).Source
$version = (& $node --version)
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v24\.') { throw "Node.js 24 required." }
if ($Operation -eq "ProbeLoopback") {
 & $node (Join-Path $root "scripts\scattering-physical-probe.mjs") loopback $pacer 5
 exit $LASTEXITCODE
}
if ($TrustedBinarySha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Independently supplied executable SHA256 required." }
if ((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256) { throw "Unexpected vault binary." }
if ($Operation -eq "Providers") { & $vault --providers; exit $LASTEXITCODE }
if (-not $PrivateDirectory -or -not $InputFile) { throw "PrivateDirectory and InputFile required." }
$ops = @{Open="open";RecoverOpen="recover-open";Seal="seal";RecoverSeal="recover-seal"}
$argsList=@($vault,$TrustedBinarySha256.ToLowerInvariant(),$PrivateDirectory,$ops[$Operation],$InputFile)
if ($Operation -in @("Seal","RecoverSeal")) {
 if (-not $OutputFile) { throw "New private wire output required." }
 $argsList += $OutputFile
}
& $node --experimental-transform-types (Join-Path $root "scripts\native-vault-windows-local.mjs") @argsList
exit $LASTEXITCODE
