# Explicit operator-only signing. No certificate creation, import or trust changes.
# Run from a trusted source checkout using an authorized Windows SDK SignTool.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
param(
 [Parameter(Mandatory=$true)][string]$UnsignedInstaller,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedUnsignedSha256,
 [Parameter(Mandatory=$true)][string]$OutputInstaller,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedPublisherSha256,
 [Parameter(Mandatory=$true)][string]$SignToolPath,
 [Parameter(Mandatory=$true)][uri]$TimestampUrl
)
$ErrorActionPreference="Stop"
if($TimestampUrl.Scheme -ne "https" -or $TimestampUrl.UserInfo -or $TimestampUrl.Fragment){throw "Explicit HTTPS timestamp service required."}
$source=Get-Item -LiteralPath $UnsignedInstaller
if($source.PSIsContainer -or $source.Extension -ine ".exe" -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Regular installer required."}
if((Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash -ine $ExpectedUnsignedSha256){throw "Unsigned artifact provenance mismatch."}
if((Get-AuthenticodeSignature -LiteralPath $source.FullName).Status -ne "NotSigned"){throw "Expected unsigned source."}
$tool=Get-Item -LiteralPath $SignToolPath
if($tool.Name -ine "signtool.exe" -or ($tool.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-AuthenticodeSignature -LiteralPath $tool.FullName).Status -ne "Valid"){throw "Trusted signed Windows SDK SignTool required."}
$toolSigner=(Get-AuthenticodeSignature -LiteralPath $tool.FullName).SignerCertificate
if($toolSigner.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw "Microsoft SDK publisher required."}
$sha=[Security.Cryptography.SHA256]::Create()
try{
 $certs=@(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
  $_.HasPrivateKey -and $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date) -and
  (($_.EnhancedKeyUsageList | ForEach-Object {$_.ObjectId.Value}) -contains "1.3.6.1.5.5.7.3.3") -and
  ([BitConverter]::ToString($sha.ComputeHash($_.RawData)).Replace("-","") -ieq $ExpectedPublisherSha256)
 })
}finally{$sha.Dispose()}
if($certs.Count -ne 1){throw "Exactly one authorized code-signing certificate with private key is required."}
$dest=[IO.Path]::GetFullPath($OutputInstaller)
if([IO.Path]::GetExtension($dest) -ine ".exe" -or (Test-Path -LiteralPath $dest)){throw "New output EXE required; no replacement."}
if(-not $PSCmdlet.ShouldProcess($dest,"Sign laboratory installer with pinned publisher certificate")){return}
# Copy new file without overwriting. Sign only the new copy, never original.
[IO.File]::Copy($source.FullName,$dest,$false)
if((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ine $ExpectedUnsignedSha256){throw "Copied artifact mismatch. Do not distribute."}
& $tool.FullName sign /sha1 $certs[0].Thumbprint /s My /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 $dest
if($LASTEXITCODE -ne 0){throw "Signing failed; output is not releasable."}
& $tool.FullName verify /pa /all /tw $dest
if($LASTEXITCODE -ne 0){throw "Signature verification failed; output is not releasable."}
& (Join-Path $PSScriptRoot "Test-Native-Installer-Signature.ps1") -Installer $dest -ExpectedPublisherSha256 $ExpectedPublisherSha256
Write-Output ("Signed laboratory installer SHA256: "+(Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash)
