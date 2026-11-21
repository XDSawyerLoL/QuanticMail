# Local operator dashboard. Secrets, cryptographic operations and approvals
# remain with the pre-existing native terminal tools. Not production enrollment.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$TrustedBinarySha256,
 [switch]$SelfTest
)
$ErrorActionPreference="Stop"
$root=$PSScriptRoot
$launcher=Join-Path $root "Start-Windows-PQ-Lab.ps1"
$shell=Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$actions=@(
 @{Id="Seal";Title="1. Preparer un message";Hint="Brouillon prive -> nouvelle enveloppe chiffree. Aucun envoi.";Input="draft";Output=$true;Scope=$true},
 @{Id="Send";Title="2. Envoyer";Hint="Deposer une enveloppe signee par Scattering. Relais local configure requis.";Input="wire";Scope=$true},
 @{Id="Receive";Title="3. Recevoir";Hint="Ouvrir et conserver un nouveau recu chiffre avant confirmation.";Input="receipt";Scope=$true},
 @{Id="Open";Title="Ouvrir une enveloppe locale";Hint="Verifier et ouvrir un fichier chiffre existant.";Input="wire";Scope=$true},
 @{Id="RecoverSeal";Title="Recuperer un chiffrement";Hint="Reprendre le resultat exact d'un brouillon, sans nouvel envoi.";Input="draft";Output=$true;Scope=$true},
 @{Id="RecoverOpen";Title="Recuperer une ouverture";Hint="Reprendre le resultat exact d'une enveloppe.";Input="wire";Scope=$true},
 @{Id="RecoverReceive";Title="Recuperer une reception";Hint="Reprendre le resultat exact ; nouveau fichier de recu obligatoire.";Input="receipt";Scope=$true},
 @{Id="ConfirmReceipt";Title="Confirmer un recu existant";Hint="Verifier le recu conserve et confirmer au relais.";Input="receipt";Scope=$true},
 @{Id="Provision";Title="Creer un coffre de test";Hint="Parametres publics independants requis. Ne cree pas de compte distant.";Scope=$true},
 @{Id="StartBridge";Title="Demarrer le pont Scattering";Hint="Dossier de transport distinct deja configure ; pacer et sink separes requis.";Scope=$true},
 @{Id="Providers";Title="Verifier la cryptographie";Hint="Diagnostic du fournisseur cryptographique natif."},
 @{Id="ProbeLoopback";Title="Tester le transport local";Hint="Diagnostic UDP local, sans compte ni reseau distant."},
 @{Id="MigrationCheck";Title="Verifier une sauvegarde de migration";Hint="Controle hors ligne des anciennes cles. Aucun transfert ou effacement."},
 @{Id="MigrationHistory";Title="Relire les messages historiques";Hint="Lecture locale de la sauvegarde verifiee. Aucun compte reactive."},
 @{Id="PayLab";Title="Quantic Pay - laboratoire";Hint="Portefeuille et paiements strictement fictifs. Aucune valeur monetaire."},
 @{Id="PayProvision";Title="Quantic Pay - creer le coffre";Hint="Nouveau dossier prive et phrase secrete distincte. Cles fictives." ;Scope=$true},
 @{Id="PayNative";Title="Quantic Pay - simulation avec coffre natif";Hint="Empreintes publiques independantes requises. Aucun transfert reel.";Scope=$true}
)
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
$form=New-Object Windows.Forms.Form
$form.Text="Quantic Sillage | Alpha privee"
$form.StartPosition="CenterScreen"
$form.ClientSize=New-Object Drawing.Size(720,520)
$form.MinimumSize=New-Object Drawing.Size(736,559)
$form.BackColor=[Drawing.Color]::FromArgb(19,25,35)
$form.ForeColor=[Drawing.Color]::WhiteSmoke
$form.Font=New-Object Drawing.Font("Segoe UI",10)
function Label-At([string]$Text,[int]$X,[int]$Y,[int]$W,[int]$H) {
 $c=New-Object Windows.Forms.Label; $c.Text=$Text
 $c.SetBounds($X,$Y,$W,$H);$form.Controls.Add($c);return $c
}
function Text-At([int]$X,[int]$Y,[int]$W) {
 $c=New-Object Windows.Forms.TextBox;$c.SetBounds($X,$Y,$W,28)
 $form.Controls.Add($c);return $c
}
$heading=Label-At "QUANTIC SILLAGE" 22 18 670 36
$heading.Font=New-Object Drawing.Font("Segoe UI",21,[Drawing.FontStyle]::Bold)
$null=Label-At "Identity Vault / Quantic Mail / Scattering / Pay Lab" 24 58 670 25
$notice=Label-At "LABORATOIRE - identites de test uniquement. Aucun compte reel ni migration." 24 90 670 38
$notice.ForeColor=[Drawing.Color]::Khaki
$null=Label-At "Operation" 24 132 670 22
$choice=New-Object Windows.Forms.ComboBox
$choice.DropDownStyle="DropDownList";$choice.SetBounds(24,157,672,30)
foreach ($a in $actions) { $null=$choice.Items.Add($a.Title) }
$form.Controls.Add($choice)
$hint=Label-At "" 24 196 672 45
$null=Label-At "Dossier prive du coffre (ou du transport pour le pont)" 24 245 672 23
$directory=Text-At 24 270 672
$il=Label-At "Fichier prive" 24 309 672 22
$inputName=Text-At 24 333 672
$ol=Label-At "Nouvelle enveloppe" 24 372 672 22
$outputName=Text-At 24 396 672
$run=New-Object Windows.Forms.Button;$run.Text="Continuer dans le terminal securise"
$run.ForeColor=[Drawing.Color]::Black;$run.BackColor=[Drawing.Color]::FromArgb(196,223,244)
$run.SetBounds(24,459,485,38);$form.Controls.Add($run)
$quit=New-Object Windows.Forms.Button;$quit.Text="Fermer";$quit.ForeColor=[Drawing.Color]::Black
$quit.SetBounds(526,459,170,38);$form.Controls.Add($quit)
$quit.DialogResult=[Windows.Forms.DialogResult]::Cancel;$form.CancelButton=$quit
$form.AcceptButton=$run
$script:selectedArguments=$null;$script:selectedAction=$null
$choice.Add_SelectedIndexChanged({
 $a=$actions[$choice.SelectedIndex]
 $hint.Text=$a.Hint
 $directory.Enabled=[bool]$a.Scope
 $inputName.Enabled=[bool]$a.Input
 $outputName.Enabled=[bool]$a.Output
 $il.Text=if($a.Input){"Fichier prive ("+$a.Input+"-nom.json)"}else{"Aucun fichier requis"}
 $ol.Text=if($a.Output){"Nouvelle enveloppe (wire-nom.json)"}else{"Aucune sortie a saisir"}
})
$run.Add_Click({
 try {
  $a=$actions[$choice.SelectedIndex]
  $script:selectedArguments=New-OperationArguments $a $directory.Text $inputName.Text $outputName.Text
  $script:selectedAction=$a.Id
  $form.DialogResult=[Windows.Forms.DialogResult]::OK
 }catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,"Parametres refuses","OK","Warning")|Out-Null}
})
$choice.SelectedIndex=0
if ($SelfTest) {
 try {
  if($choice.Items.Count -ne 17 -or -not $inputName.Enabled -or -not $outputName.Enabled){throw "Dashboard initialization failed"}
  $a=New-OperationArguments $actions[0] "C:\Quantic Lab\vault" "draft-test.json" "wire-test.json"
  if($a -notcontains "C:\Quantic Lab\vault\draft-test.json" -or $a -notcontains "C:\Quantic Lab\vault\wire-test.json"){throw "Wrong arguments"}
  $rejected=$false
  try{$null=New-OperationArguments $actions[1] "C:\Quantic Lab\vault" "..\wire-test.json" ""}catch{$rejected=$true}
  if(-not $rejected){throw "Path traversal accepted"}
  $choice.SelectedIndex=10
  if($directory.Enabled -or $inputName.Enabled -or $outputName.Enabled){throw "Diagnostic fields enabled"}
  Write-Output "Dashboard controls and operation mapping verified"
 }finally{$form.Dispose()}
 exit 0
}
try {
 while ($true) {
  $script:selectedArguments=$null;$script:selectedAction=$null
  if ($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { break }
  $operationArgs=$script:selectedArguments
  if ($script:selectedAction -eq "PayNative") {
   $signPin=Read-Host "Empreinte SHA256 P-256 du coffre Pay"
   $pqPin=Read-Host "Empreinte SHA256 ML-DSA-65 du coffre Pay"
   $operationArgs+=@("-PaySigningPin",$signPin,"-PayPQPin",$pqPin)
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
  Write-Host ""
  Write-Host "Quantic Sillage - operation locale. Les validations du coffre restent obligatoires."
  & $shell -NoProfile -File $launcher @operationArgs
  $code=$LASTEXITCODE
  Write-Host "Code de retour: $code. Un code nul n'est pas une preuve de livraison distante."
  $null=Read-Host "Entree pour revenir au tableau de bord"
 }
}finally{$form.Dispose()}
