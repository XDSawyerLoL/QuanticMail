#requires -Version 7
param(
  [Parameter(Mandatory=$true)][string]$InputExecutable,
  [Parameter(Mandatory=$true)][string]$SignedExecutable,
  [Parameter(Mandatory=$true)][string]$PfxPath,
  [Parameter(Mandatory=$true)][string]$ExpectedPublisherSubject
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InputExecutable -PathType Leaf)) { throw 'Input binary missing' }
if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) { throw 'Certificate file missing' }
if ([string]::IsNullOrWhiteSpace($env:QUANTIC_SIGNING_PFX_PASSWORD)) { throw 'Signing certificate password not configured' }
if ([string]::IsNullOrWhiteSpace($ExpectedPublisherSubject)) { throw 'Expected publisher certificate subject required' }

# Always sign a copy. Never mutate the audited and already tested input build.
$src = (Resolve-Path -LiteralPath $InputExecutable).Path
$dst = [IO.Path]::GetFullPath($SignedExecutable)
if ($src -eq $dst) { throw 'Signed output must differ from unsigned input' }
if (Test-Path -LiteralPath $dst) { throw 'Signed output already exists; refusing overwrite' }

$kits = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Windows Kits\10\bin'
$tool = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
  Sort-Object FullName -Descending | Select-Object -First 1
if (-not $tool) { throw 'SignTool not found in Windows SDK' }

$securePassword = ConvertTo-SecureString $env:QUANTIC_SIGNING_PFX_PASSWORD -AsPlainText -Force
$cert = $null
$imported = $false
try {
  # Inspect the file before importing; never alter another user's installed
  # certificate, and never export or put signing secrets in build artifacts.
  $candidate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PfxPath).Path),
    $env:QUANTIC_SIGNING_PFX_PASSWORD,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
  )
  if ($candidate.Subject -ne $ExpectedPublisherSubject) {
    throw 'Certificate publisher subject does not match the configured publisher'
  }
  if (-not $candidate.HasPrivateKey) { throw 'Code-signing private key missing' }
  if (Test-Path "Cert:\CurrentUser\My\$($candidate.Thumbprint)") {
    throw 'Certificate already exists in CurrentUser store; refusing to modify it'
  }
  $cert = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword
  $imported = $true
  if (-not $cert -or $cert.Thumbprint -ne $candidate.Thumbprint) { throw 'Wrong signing certificate imported' }
  if ($cert.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'Signing certificate expired' }

  Copy-Item -LiteralPath $src -Destination $dst -ErrorAction Stop
  & $tool.FullName sign /sha1 $cert.Thumbprint /s My /fd SHA256 /tr 'http://timestamp.digicert.com' /td SHA256 $dst
  if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing command failed' }
  & $tool.FullName verify /pa /v $dst
  if ($LASTEXITCODE -ne 0) { throw 'Authenticode signature failed Windows trust verification' }
  $signature = Get-AuthenticodeSignature -LiteralPath $dst
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Windows does not trust the code signature: $($signature.Status)"
  }
  if ($signature.SignerCertificate.Subject -ne $ExpectedPublisherSubject) {
    throw 'Signed binary publisher does not match expected certificate'
  }
  Write-Output 'Authenticode signed and trusted by Windows. The signed binary is ready for independent acceptance tests.'
}
catch {
  if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Force }
  throw
}
finally {
  if ($imported -and $cert) {
    Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction Stop
  }
  $securePassword.Dispose()
}
