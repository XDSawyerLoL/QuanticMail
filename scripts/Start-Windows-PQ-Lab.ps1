# Explicit laboratory launcher. No installation or production login.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet("Providers","Open","RecoverOpen","Seal","RecoverSeal","ProbeLoopback","ProbeLanSend","ProbeLanReceive","Send","SealAndSend","RecoverSealAndSend","Receive","RecoverReceive","ConfirmReceipt","StartBridge","Provision","ProvisionGui","VerifyGui","ImportMailKitGui","ImportSessionKitGui","SendGui","ReceiveGui","ComposeGui","RecoverComposeGui","ProvisionPair","MailPreflight","MailAttest","Dashboard","DashboardCheck","MigrationCheck","MigrationHistory","MigrationSmoke","MigrationFullSmoke","PayLab","PayLabCheck","PayProvision","PayNative","PayQuorumDemo","PayQuorumCheck","PayNativeQuorum","PayHistoryCheck","PayOperator","PayOperatorConfigure","StartPayBridge","PayCirculation","PayCirculationCheck")][string]$Operation,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
 [string]$TrustedBinarySha256,
 [string]$PrivateDirectory,
 [string]$InputFile,
 [string]$OutputFile,
 [string]$ControllerPublicKey,
 [string]$QuorumPin,
 [string]$CanonicalAddress,
 [string]$SecondCanonicalAddress,
 [string]$SecondQuorumPin,
 [string]$CarrierDirectory,
 [string]$ProbeAddress,
 [string]$TrustFile,
 [string]$ExpectedTrustSha256,
 [string]$TrustedRootPin,
 [string]$PaySigningPin,
 [string]$PayPQPin,
 [string]$PayConfigPin
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
# This launcher and its installation directory must already be independently trusted.
$manifest = Join-Path $root "SHA256SUMS.txt"
if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256) { throw "Unexpected manifest." }
$verifier = Join-Path $root "Test-Windows-PQ-Package.ps1"
$line = @(Get-Content -LiteralPath $manifest | Where-Object { $_ -cmatch '^[a-f0-9]{64} \*\./Test-Windows-PQ-Package\.ps1$' })
if ($line.Count -ne 1 -or (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash -ine $line[0].Substring(0,64)) { throw "Verifier integrity failure." }
& $verifier -PackageDirectory $root -ExpectedManifestSha256 $ExpectedManifestSha256
$env:PATH = (Join-Path $root "bin") + ";" + (Join-Path $env:SystemRoot "System32")
foreach ($v in @("NODE_OPTIONS","NODE_PATH","OPENSSL_CONF","OPENSSL_MODULES","OPENSSL_ENGINES")) { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
Set-Location -LiteralPath $root
$vault = Join-Path $root "bin\Vault-PQ-lab.exe"
$pacer = Join-Path $root "bin\Scattering-Pacer.exe"
$node = Join-Path $root "runtime\node.exe"
$version = (& $node --version)
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v24\.') { throw "Bundled Node.js 24 runtime required." }
if ($Operation -eq "ProbeLoopback") {
 & $node (Join-Path $root "scripts\scattering-physical-probe.mjs") loopback $pacer 5
 exit $LASTEXITCODE
}
if ($Operation -in @("ProbeLanSend","ProbeLanReceive")) {
 # Explicitly confined to an authorized private LAN. No firewall changes.
 if($ProbeAddress -cnotmatch '^(?:10|172|192)\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})$'){throw "Adresse IPv4 privee requise."}
 $octets=@($ProbeAddress.Split('.')|ForEach-Object {[int]$_})
 if(($octets|Where-Object {$_ -gt 255}).Count -gt 0 -or -not ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168)) -or $octets[3] -in @(0,255)){throw "Adresse privee unicast requise."}
 if($Operation -eq "ProbeLanReceive"){
  if(-not @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop|Where-Object {$_.IPAddress -ceq $ProbeAddress}).Count){throw "Cette adresse ne correspond pas a un adaptateur local."}
  & $node (Join-Path $root "scripts\scattering-physical-probe.mjs") receive $pacer $ProbeAddress 49001 60
 }else{
  & $node (Join-Path $root "scripts\scattering-physical-probe.mjs") send $pacer $ProbeAddress 49001 30
 }
 exit $LASTEXITCODE
}
if ($TrustedBinarySha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Independently supplied executable SHA256 required." }
if ((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256) { throw "Unexpected vault binary." }
if ($Operation -eq "Providers") { & $vault --providers; exit $LASTEXITCODE }
if ($Operation -in @("Dashboard","DashboardCheck")) {
 $ui = Join-Path $root "Quantic-Sillage-Alpha.ps1"
 $shell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
 $uiArgs = @("-NoProfile","-STA","-File",$ui,"-ExpectedManifestSha256",$ExpectedManifestSha256,"-TrustedBinarySha256",$TrustedBinarySha256)
 if ($Operation -eq "DashboardCheck") { $uiArgs += "-SelfTest" }
 & $shell @uiArgs
 exit $LASTEXITCODE
}
if ($Operation -in @("PayOperator","PayOperatorConfigure")) {
 if (-not $PrivateDirectory -or $PayConfigPin -cnotmatch '^[a-f0-9]{64}$') { throw "Private Pay directory and independent configuration pin required." }
 $payArgs=@((Join-Path $root "scripts\quantic-pay-operator.mjs"),$vault,$TrustedBinarySha256.ToLowerInvariant(),$PrivateDirectory,$PayConfigPin)
 if ($Operation -eq "PayOperatorConfigure") {
  if (-not $InputFile) { throw "Protected configuration source required." }
  $payArgs+=@("configure",$InputFile)
 }else{$payArgs+="run"}
 & $node @payArgs
 exit $LASTEXITCODE
}
if ($Operation -eq "StartPayBridge") {
 if (-not $PrivateDirectory) { throw "Separate Pay carrier directory required." }
 & $node --experimental-transform-types (Join-Path $root "scripts\serve-native-scattering-windows.mjs") $vault $TrustedBinarySha256.ToLowerInvariant() $PrivateDirectory pay-lab
 exit $LASTEXITCODE
}
if ($Operation -in @("PayCirculation","PayCirculationCheck")) {
 $payArgs=@((Join-Path $root "scripts\quantic-pay-circulation.mjs"))
 if ($Operation -eq "PayCirculationCheck") { $payArgs+="--self-test" }
 & $node @payArgs
 exit $LASTEXITCODE
}
if ($Operation -eq "PayNativeQuorum") {
 if (-not $PrivateDirectory) { throw "New private Pay laboratory directory required." }
 & $node (Join-Path $root "scripts\quantic-pay-native-quorum.mjs") $vault $PrivateDirectory
 exit $LASTEXITCODE
}
if ($Operation -eq "PayHistoryCheck") {
 if (-not $PrivateDirectory -or $PaySigningPin -cnotmatch '^[a-f0-9]{64}$' -or $PayPQPin -cnotmatch '^[a-f0-9]{64}$') { throw "Independent Pay laboratory public pins required." }
 & $node (Join-Path $root "scripts\quantic-pay-remote-check.mjs") $vault $PrivateDirectory $PaySigningPin $PayPQPin
 exit $LASTEXITCODE
}
if ($Operation -eq "PayProvision") {
 if (-not $PrivateDirectory) { throw "New private Pay directory required." }
 & $vault --provision-windows-pay-lab $PrivateDirectory
 exit $LASTEXITCODE
}
if ($Operation -eq "PayNative") {
 if (-not $PrivateDirectory -or $PaySigningPin -cnotmatch '^[a-f0-9]{64}$' -or $PayPQPin -cnotmatch '^[a-f0-9]{64}$') { throw "Independent Pay laboratory public pins required." }
 & $node (Join-Path $root "scripts\quantic-pay-native.mjs") $vault $PrivateDirectory $PaySigningPin $PayPQPin
 exit $LASTEXITCODE
}
if ($Operation -in @("PayQuorumDemo","PayQuorumCheck")) {
 $payArgs=@((Join-Path $root "scripts\quantic-pay-quorum-local.mjs"))
 if ($Operation -eq "PayQuorumCheck") { $payArgs+="--self-test" }
 & $node @payArgs
 exit $LASTEXITCODE
}
if ($Operation -in @("PayLab","PayLabCheck")) {
 $payArgs=@((Join-Path $root "scripts\quantic-pay-lab.mjs"))
 if ($Operation -eq "PayLabCheck") { $payArgs+="--self-test" }
 & $node @payArgs
 exit $LASTEXITCODE
}
if ($Operation -eq "MigrationFullSmoke") {
 if (-not $PrivateDirectory) { throw "NEW synthetic full-capacity migration laboratory directory required." }
 & $node (Join-Path $root "scripts\migration-windows-16mib-smoke-lab.mjs") $vault $TrustedBinarySha256.ToLowerInvariant() $PrivateDirectory "--synthetic-only"
 exit $LASTEXITCODE
}
if ($Operation -eq "MigrationSmoke") {
 if (-not $PrivateDirectory) { throw "NEW isolated synthetic migration lab directory required." }
 & $node (Join-Path $root "scripts\migration-windows-smoke-lab.mjs") $vault $TrustedBinarySha256.ToLowerInvariant() $PrivateDirectory "--synthetic-only"
 exit $LASTEXITCODE
}
if ($Operation -in @("MigrationCheck","MigrationHistory")) {
 if ($TrustedRootPin -notmatch '^[a-f0-9]{64}$' -or $CanonicalAddress -notmatch '^[a-z0-9][a-z0-9._-]{2,31}~(?:[a-f0-9]{10}|[a-f0-9]{32})@quantic$' -or $InputFile -notmatch '^[A-Za-z]:\\[^\r\n]+\.qma$') { throw "Archive and independent public identity pin required." }
 $migrationArgs=@($InputFile,$CanonicalAddress,$TrustedRootPin)
 if ($Operation -eq "MigrationHistory") { $migrationArgs+="history" }
 & $node --experimental-transform-types (Join-Path $root "scripts\verify-migration-local.mjs") @migrationArgs
 exit $LASTEXITCODE
}
if (-not $PrivateDirectory) { throw "PrivateDirectory required." }
if ($Operation -in @("MailPreflight","MailAttest")) {
 # The trusted native broker reads protected desktop, contact and carrier files.
 if (-not $PrivateDirectory -or -not $CarrierDirectory -or -not $TrustFile -or $ExpectedTrustSha256 -cnotmatch '^[a-f0-9]{64}$') { throw "Independent trust-file digest and separate vault/carrier paths required." }
 $probeMode="offline"
 if ($Operation -eq "MailAttest") { $probeMode="live" }
 & $node (Join-Path $root "scripts\native-windows-mail-readiness.mjs") $vault $TrustedBinarySha256.ToLowerInvariant() $PrivateDirectory $CarrierDirectory $TrustFile $ExpectedTrustSha256 $probeMode
 exit $LASTEXITCODE
}
if ($Operation -eq "ProvisionPair") {
 # Public metadata only; native broker keeps two private passphrases.
 if ($QuorumPin -cnotmatch '^[a-f0-9]{64}$' -or $SecondQuorumPin -cnotmatch '^[a-f0-9]{64}$' -or $CanonicalAddress -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$' -or $SecondCanonicalAddress -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$' -or $CanonicalAddress -ceq $SecondCanonicalAddress) {
  throw "Two different synthetic identities and independently trusted quorum pins required."
 }
 & $node (Join-Path $root "scripts\provision-windows-two-party-lab.mjs") $vault $TrustedBinarySha256.ToLowerInvariant() $PrivateDirectory $CanonicalAddress $QuorumPin $SecondCanonicalAddress $SecondQuorumPin "--synthetic-only"
 exit $LASTEXITCODE
}
if ($Operation -eq "ImportSessionKitGui") {
 if(-not $InputFile -or $ExpectedTrustSha256 -cnotmatch '^[a-f0-9]{64}$'){throw "Protected session kit and independent digest required."}
 & $vault --import-windows-session-kit-gui-lab $PrivateDirectory $InputFile $ExpectedTrustSha256
 exit $LASTEXITCODE
}
if ($Operation -eq "ImportMailKitGui") {
 if(-not $InputFile -or $ExpectedTrustSha256 -cnotmatch '^[a-f0-9]{64}$'){throw "Protected onboarding kit and independent digest required."}
 & $vault --import-windows-mail-kit-gui-lab $PrivateDirectory $InputFile $ExpectedTrustSha256 $TrustedBinarySha256.ToLowerInvariant()
 exit $LASTEXITCODE
}
if ($Operation -eq "VerifyGui") {
 & $vault --verify-windows-controller-gui-lab $PrivateDirectory
 exit $LASTEXITCODE
}
if ($Operation -eq "ProvisionGui") {
 if ($ControllerPublicKey -or $QuorumPin -cnotmatch '^[a-f0-9]{64}$' -or $CanonicalAddress -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$') { throw "Independent public identity parameters required." }
 & $vault --provision-windows-controller-gui-lab $PrivateDirectory $QuorumPin $CanonicalAddress
 exit $LASTEXITCODE
}
if ($Operation -eq "Provision") {
 if (-not $ControllerPublicKey) {
  if ($QuorumPin -notmatch '^[a-f0-9]{64}$' -or $CanonicalAddress -notmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$') { throw "Independent public identity parameters required." }
  & $vault --provision-windows-controller-lab $PrivateDirectory $QuorumPin $CanonicalAddress
  exit $LASTEXITCODE
 }
 if ($ControllerPublicKey -notmatch '^[A-Za-z0-9_-]{43}$' -or $QuorumPin -notmatch '^[a-f0-9]{64}$' -or $CanonicalAddress -notmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$') { throw "Independently provisioned synthetic identity parameters required." }
 & $vault --provision-windows-pq-storage-lab $PrivateDirectory $ControllerPublicKey $QuorumPin $CanonicalAddress
 exit $LASTEXITCODE
}
if ($Operation -eq "StartBridge") {
 & $node --experimental-transform-types (Join-Path $root "scripts\serve-native-scattering-windows.mjs") $vault $TrustedBinarySha256.ToLowerInvariant() $PrivateDirectory
 exit $LASTEXITCODE
}
if ($Operation -eq "ComposeGui") {
 # The dashboard sends an ASCII-escaped JSON object over redirected stdin.
 # Never put plaintext in an argument, file, environment variable or log.
 $buffer=New-Object char[] 65537
 $length=0
 try {
  while($length -lt $buffer.Length){
   $n=[Console]::In.Read($buffer,$length,$buffer.Length-$length)
   if($n -eq 0){break};$length+=$n
  }
  if($length -lt 1 -or $length -gt 65536){throw "Compose input bounds"}
  $json=[string]::new($buffer,0,$length)
  if($json -match '[^\x00-\x7f]'){throw "Compose encoding refused"}
  if($PrivateDirectory -notmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw "Invalid private directory"}
  $psi=New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName=$node
  $script=Join-Path $root "scripts\native-vault-windows-mailbox.mjs"
  $psi.Arguments='--experimental-transform-types "'+$script+'" "'+$vault+'" '+$TrustedBinarySha256.ToLowerInvariant()+' "'+$PrivateDirectory+'" compose-gui --gui'
  $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
  $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true
  $child=[System.Diagnostics.Process]::Start($psi)
  try{
   $child.StandardInput.Write($json);$child.StandardInput.Close()
   $result=$child.StandardOutput.ReadToEnd();$child.WaitForExit()
   if($child.ExitCode -ne 0){exit $child.ExitCode}
   Write-Output $result
  }finally{$child.Dispose()}
 }finally{[Array]::Clear($buffer,0,$buffer.Length);$json=$null}
 exit 0
}
if ($Operation -eq "RecoverComposeGui") {
 if(-not $InputFile -or -not $OutputFile){throw "Protected recovery paths required."}
 & $node --experimental-transform-types (Join-Path $root "scripts\native-vault-windows-mailbox.mjs") $vault $TrustedBinarySha256.ToLowerInvariant() $PrivateDirectory "recover-seal-and-send" $InputFile $OutputFile "--gui"
 exit $LASTEXITCODE
}
if ($Operation -in @("SendGui","ReceiveGui")) {
 if (-not $InputFile) { throw "Protected native file path required." }
 $mailOp=if($Operation -eq "SendGui"){"send"}else{"receive"}
 & $node --experimental-transform-types (Join-Path $root "scripts\native-vault-windows-mailbox.mjs") $vault $TrustedBinarySha256.ToLowerInvariant() $PrivateDirectory $mailOp $InputFile "--gui"
 exit $LASTEXITCODE
}
if ($Operation -in @("Send","SealAndSend","RecoverSealAndSend","Receive","RecoverReceive","ConfirmReceipt")) {
 if (-not $InputFile) { throw "Private wire, draft or receipt path required." }
 $mailOps=@{Send="send";SealAndSend="seal-and-send";RecoverSealAndSend="recover-seal-and-send";Receive="receive";RecoverReceive="recover-receive";ConfirmReceipt="confirm-receipt"}
 $mailArgs=@($vault,$TrustedBinarySha256.ToLowerInvariant(),$PrivateDirectory,$mailOps[$Operation],$InputFile)
 if ($Operation -in @("SealAndSend","RecoverSealAndSend")) {
  if (-not $OutputFile) { throw "New durable wire output path required. Do not overwrite an existing wire." }
  $mailArgs += $OutputFile
 }
 & $node --experimental-transform-types (Join-Path $root "scripts\native-vault-windows-mailbox.mjs") @mailArgs
 exit $LASTEXITCODE
}
if (-not $PrivateDirectory -or -not $InputFile) { throw "PrivateDirectory and InputFile required." }
$ops = @{Open="open";RecoverOpen="recover-open";Seal="seal";RecoverSeal="recover-seal"}
$argsList=@($vault,$TrustedBinarySha256.ToLowerInvariant(),$PrivateDirectory,$ops[$Operation],$InputFile)
if ($Operation -in @("Seal","RecoverSeal")) {
 if (-not $OutputFile) { throw "New private wire output required." }
 $argsList += $OutputFile
}
& $node --experimental-transform-types (Join-Path $root "scripts\native-vault-windows-local.mjs") @argsList
exit $LASTEXITCODE
