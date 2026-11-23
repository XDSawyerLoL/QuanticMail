# Explicit advanced lab console; never launched on normal GUI startup.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$TrustedBinarySha256,
 [string]$Operation,
 [string]$Directory,
 [string]$InputName,
 [string]$OutputName,
 [switch]$SelfTest
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$launcher=Join-Path $root 'Start-Windows-PQ-Lab.ps1'
$shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
Add-Type -AssemblyName System.Windows.Forms
$allowed=@('SealAndSend','RecoverSealAndSend','Seal','Send','Receive','Open','RecoverSeal','RecoverOpen','RecoverReceive','ConfirmReceipt','Provision','ProvisionPair','StartBridge','Providers','ProbeLoopback','MigrationCheck','MigrationHistory','PayLab','PayProvision','PayNative','PayQuorumDemo','PayNativeQuorum','PayHistoryCheck','PayOperator','StartPayBridge','PayOperatorConfigure','PayCirculation','MailPreflight','MailAttest')
$inputs=@{SealAndSend='draft';RecoverSealAndSend='draft';Seal='draft';Send='wire';Receive='receipt';Open='wire';RecoverSeal='draft';RecoverOpen='wire';RecoverReceive='receipt';ConfirmReceipt='receipt'}
$outputs=@('SealAndSend','RecoverSealAndSend','Seal','RecoverSeal')
$noScope=@('Providers','ProbeLoopback','MigrationCheck','MigrationHistory','PayLab','PayQuorumDemo','PayCirculation')
function New-OperationArguments($Action,[string]$Directory,[string]$InputName,[string]$OutputName) {
 $a=@("-Operation",$Action.Id,"-ExpectedManifestSha256",$ExpectedManifestSha256,"-TrustedBinarySha256",$TrustedBinarySha256.ToLowerInvariant())
 if ($Action.Scope) {
  if ($Directory -notmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$') { throw "Dossier absolu local requis (chemin ASCII canonique)." }
  foreach ($part in $Directory.Substring(3).Split('\')) { if ($part -in @(".","..") -or $part.EndsWith(".") -or $part.EndsWith(" ")) { throw "Chemin ambigu refuse." } }
  $a+=@("-PrivateDirectory",$Directory)
 }
 if ($Action.Input) {
  $rx="^"+[Regex]::Escape($Action.Input)+"-[a-z0-9-]{1,48}\.json$"
  if ($InputName -cnotmatch $rx) { throw ("Nom requis: "+$Action.Input+"-nom.json") }
  $a+=@("-InputFile",[IO.Path]::Combine($Directory,$InputName))
 }
 if ($Action.Output) {
  if ($OutputName -cnotmatch '^wire-[a-z0-9-]{1,48}\.json$') { throw "Nouvelle enveloppe wire-nom.json requise." }
  $a+=@("-OutputFile",[IO.Path]::Combine($Directory,$OutputName))
 }
 return ,$a
}

if($SelfTest){
 if($allowed.Count -ne 29 -or $inputs.Count -ne 10 -or $outputs.Count -ne 4){throw 'Advanced action contract changed'}
 Write-Output 'Advanced console contract passed'
 return
}
if($Operation -notin $allowed){throw 'Unsupported advanced operation'}
$action=@{Id=$Operation;Scope=($Operation -notin $noScope);Input=$inputs[$Operation];Output=($Operation -in $outputs)}
$script:selectedAction=$Operation
$operationArgs=New-OperationArguments $action $Directory $InputName $OutputName
Write-Host 'Quantic Sillage - outils avances de laboratoire. Identites fictives exclusivement.'
  if ($script:selectedAction -in @("PayOperator","PayOperatorConfigure")) {
   $configPin=Read-Host "Empreinte SHA256 independante de la configuration Pay"
   $operationArgs+=@("-PayConfigPin",$configPin)
   if ($script:selectedAction -eq "PayOperatorConfigure") {
    $configSource=Read-Host "Chemin absolu de la configuration privee"
    $operationArgs+=@("-InputFile",$configSource)
   }
  }
  if ($script:selectedAction -in @("PayNative","PayHistoryCheck")) {
   $signPin=Read-Host "Empreinte SHA256 P-256 du coffre Pay"
   $pqPin=Read-Host "Empreinte SHA256 ML-DSA-65 du coffre Pay"
   $operationArgs+=@("-PaySigningPin",$signPin,"-PayPQPin",$pqPin)
  }
  if ($script:selectedAction -in @("MailPreflight","MailAttest")) {
   Write-Host "Precontrole lecture seule: aucun compte ni cle historique n'est modifie."
   $carrier=Read-Host "Dossier prive du transport Scattering deja provisionne"
   $trust=Read-Host "Fichier JSON public de confiance approuve independamment"
   $pin=Read-Host "Empreinte SHA256 verifiee independamment de ce fichier de confiance"
   $operationArgs+=@("-CarrierDirectory",$carrier,"-TrustFile",$trust,"-ExpectedTrustSha256",$pin)
  }
  if ($script:selectedAction -eq "ProvisionPair") {
   Write-Host "DEMONSTRATION FICTIVE : deux coffres locaux distincts, sans inscription distante."
   Write-Host "Le dossier parent doit exister et participant-a / participant-b doivent etre ABSENTS."
   $addrA=Read-Host "Adresse canonique fictive du premier participant"
   $pinA=Read-Host "Empreinte de quorum independently approuvee (participant A)"
   $addrB=Read-Host "Adresse canonique fictive du second participant"
   $pinB=Read-Host "Empreinte de quorum independently approuvee (participant B)"
   $operationArgs+=@("-CanonicalAddress",$addrA,"-QuorumPin",$pinA,"-SecondCanonicalAddress",$addrB,"-SecondQuorumPin",$pinB)
  }
  if ($script:selectedAction -eq "Provision") {
   Write-Host "Coffre de test uniquement. Les valeurs suivantes sont publiques et doivent provenir d'une preparation independante."
   $quorum=Read-Host "Empreinte SHA256 du quorum"
   $address=Read-Host "Adresse canonique de test"
   $operationArgs+=@("-QuorumPin",$quorum,"-CanonicalAddress",$address)
  }
  if ($script:selectedAction -in @("MigrationCheck","MigrationHistory")) {
   $picker=New-Object Windows.Forms.OpenFileDialog
   $picker.Filter="Archive Quantic (*.qma)|*.qma"
   try {
    if ($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { continue }
    $archive=$picker.FileName
   }finally{$picker.Dispose()}
   $address=Read-Host "Adresse canonique historique"
   $pin=Read-Host "Empreinte SHA256 independante de la cle de propriete historique"
   $operationArgs+=@("-InputFile",$archive,"-CanonicalAddress",$address,"-TrustedRootPin",$pin)
  }

Write-Host ''
Write-Host 'Operation de laboratoire. Un succes ne prouve pas une livraison distante.'
& $shell -NoProfile -STA -File $launcher @operationArgs
$code=$LASTEXITCODE
Write-Host ('Code de retour : '+$code)
$null=Read-Host 'Entree pour fermer ce terminal technique'
exit $code
