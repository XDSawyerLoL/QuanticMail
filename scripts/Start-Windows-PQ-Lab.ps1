# Explicit laboratory launcher. No installation, firewall changes or production login.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet("Providers","Open","RecoverOpen","Seal","RecoverSeal","ProbeLoopback")][string]$Operation,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}
 [string]$PrivateDirectory,
 [string]$InputFile,
 [string]$OutputFile
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
# The launcher itself must already be trusted; external verification is mandatory
# before initial execution. Verify again before running any bundled executable.
if ((Get-FileHash -LiteralPath (Join-Path $root "SHA256SUMS.txt") -Algorithm SHA256).Hash -ine $ExpectedManifestSha256) { throw "Unexpected manifest." }
$verifier = Join-Path $root "Test-Windows-PQ-Package.ps1"
$line = @(Get-Content -LiteralPath (Join-Path $root "SHA256SUMS.txt") | Where-Object { $_ -cmatch '^[a-f0-9]{64}  \./Test-Windows-PQ-Package\.ps1
$vault = Join-Path $root "bin\Vault-PQ-lab.exe"
$pacer = Join-Path $root "bin\Scattering-Pacer.exe"
$node = Join-Path $root "runtime\node.exe"
if (-not (Test-Path -LiteralPath $node -PathType Leaf)) { throw "Bundled Node runtime missing." }
$version = (& $node --version)
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v24\.') { throw "Bundled Node.js 24 runtime required." }
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
)][string]$ExpectedManifestSha256,
 [string]$TrustedBinarySha256,
 [string]$PrivateDirectory,
 [string]$InputFile,
 [string]$OutputFile
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$vault = Join-Path $root "bin\Vault-PQ-lab.exe"
$pacer = Join-Path $root "bin\Scattering-Pacer.exe"
$node = Join-Path $root "runtime\node.exe"
if (-not (Test-Path -LiteralPath $node -PathType Leaf)) { throw "Bundled Node runtime missing." }
$version = (& $node --version)
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v24\.') { throw "Bundled Node.js 24 runtime required." }
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
 })
if ($line.Count -ne 1 -or (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash -ine $line[0].Substring(0,64)) { throw "Verifier integrity failure." }
& $verifier -PackageDirectory $root -ExpectedManifestSha256 $ExpectedManifestSha256
$env:PATH = "$(Join-Path $root "bin");$env:SystemRoot\System32"
foreach ($v in @("NODE_OPTIONS","NODE_PATH","OPENSSL_CONF","OPENSSL_MODULES","OPENSSL_ENGINES")) { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }

$vault = Join-Path $root "bin\Vault-PQ-lab.exe"
$pacer = Join-Path $root "bin\Scattering-Pacer.exe"
$node = Join-Path $root "runtime\node.exe"
if (-not (Test-Path -LiteralPath $node -PathType Leaf)) { throw "Bundled Node runtime missing." }
$version = (& $node --version)
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v24\.') { throw "Bundled Node.js 24 runtime required." }
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
)][string]$ExpectedManifestSha256,
 [string]$TrustedBinarySha256,
 [string]$PrivateDirectory,
 [string]$InputFile,
 [string]$OutputFile
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$vault = Join-Path $root "bin\Vault-PQ-lab.exe"
$pacer = Join-Path $root "bin\Scattering-Pacer.exe"
$node = Join-Path $root "runtime\node.exe"
if (-not (Test-Path -LiteralPath $node -PathType Leaf)) { throw "Bundled Node runtime missing." }
$version = (& $node --version)
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v24\.') { throw "Bundled Node.js 24 runtime required." }
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
