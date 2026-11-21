# Release gate only. An unsigned laboratory installer never passes this gate.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$Installer,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedPublisherSha256
)
$ErrorActionPreference="Stop"
$signature=Get-AuthenticodeSignature -LiteralPath $Installer
if($signature.Status -ne "Valid" -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate){throw "Valid timestamped publisher signature required."}
$sha=[Security.Cryptography.SHA256]::Create()
try{$actual=([BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace("-","")}finally{$sha.Dispose()}
if($actual -ine $ExpectedPublisherSha256){throw "Unexpected publisher certificate."}
Write-Output "Native installer signature and independent publisher pin verified."
