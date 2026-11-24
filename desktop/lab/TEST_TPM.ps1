# Windows-only isolated TPM capability test. Does not migrate or access Quantic identities.
# Requires Windows PowerShell/.NET with Microsoft Platform Crypto Provider.
$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "Windows requis." }
$name = "QuanticVault-Lab-" + [Guid]::NewGuid().ToString("N")
$provider = New-Object System.Security.Cryptography.CngProvider("Microsoft Platform Crypto Provider")
$params = New-Object System.Security.Cryptography.CngKeyCreationParameters
$params.Provider = $provider
$params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
$params.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
$key = $null
$signer = $null
try {
  $key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::ECDsaP256, $name, $params)
  $signer = New-Object System.Security.Cryptography.ECDsaCng($key)
  $challenge = [Text.Encoding]::UTF8.GetBytes("quantic-vault-tpm-lab:" + [Guid]::NewGuid())
  $signature = $signer.SignData($challenge, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
  if (-not $signer.VerifyData($challenge, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) { throw "Signature invalide." }
  $blocked = $false
  try { $null = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob) }
  catch [System.Security.Cryptography.CryptographicException] { $blocked = $true }
  if (-not $blocked) { throw "Export privé autorisé : test en échec." }
  Write-Output "PASS : signature locale et refus d'export PKCS8 sur le fournisseur TPM."
} finally {
  if ($signer) { $signer.Dispose() }
  if ($key) { $key.Dispose() }
  if ([System.Security.Cryptography.CngKey]::Exists($name, $provider)) {
    $cleanup = [System.Security.Cryptography.CngKey]::Open($name, $provider)
    try { $cleanup.Delete() } finally { $cleanup.Dispose() }
  }
}
