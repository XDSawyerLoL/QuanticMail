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
 @{Id="ComposeDraft";Title="Rediger un message (sans terminal)";Hint="Choisir mon coffre et mon contact, ecrire puis conserver un brouillon prive. Aucun envoi automatique.";Scope=$false},
 @{Id="SealAndSend";Title="1. Rediger et envoyer (coffre natif)";Hint="Brouillon existant -> chiffrement PQ -> sauvegarde verifiee -> deux validations -> depot local. Test uniquement.";Input="draft";Output=$true;Scope=$true},
 @{Id="RecoverSealAndSend";Title="Reprendre chiffrement et envoi interrompus";Hint="Recuperation exacte PQ ; nouveau wire-*.json puis depot controle. Pas de renvoi automatique.";Input="draft";Output=$true;Scope=$true},
 @{Id="Seal";Title="2. Preparer sans envoyer";Hint="Brouillon prive -> nouvelle enveloppe chiffree. Aucun envoi.";Input="draft";Output=$true;Scope=$true},
 @{Id="Send";Title="3. Envoyer un fichier signe deja conserve";Hint="Deposer exactement ce fichier via Scattering. Ne pas rechiffrer apres une reponse incertaine.";Input="wire";Scope=$true},
 @{Id="Receive";Title="3. Recevoir";Hint="Ouvrir et conserver un nouveau recu chiffre avant confirmation.";Input="receipt";Scope=$true},
 @{Id="Open";Title="Ouvrir une enveloppe locale";Hint="Verifier et ouvrir un fichier chiffre existant.";Input="wire";Scope=$true},
 @{Id="RecoverSeal";Title="Recuperer un chiffrement";Hint="Reprendre le resultat exact d'un brouillon, sans nouvel envoi.";Input="draft";Output=$true;Scope=$true},
 @{Id="RecoverOpen";Title="Recuperer une ouverture";Hint="Reprendre le resultat exact d'une enveloppe.";Input="wire";Scope=$true},
 @{Id="RecoverReceive";Title="Recuperer une reception";Hint="Reprendre le resultat exact ; nouveau fichier de recu obligatoire.";Input="receipt";Scope=$true},
 @{Id="ConfirmReceipt";Title="Confirmer un recu existant";Hint="Verifier le recu conserve et confirmer au relais.";Input="receipt";Scope=$true},
 @{Id="Provision";Title="Creer un coffre de test";Hint="Parametres publics independants requis. Ne cree pas de compte distant.";Scope=$true},
 @{Id="ProvisionPair";Title="Creer deux coffres de test PQ";Hint="Deux identites fictives, deux repertoires neufs. Empreintes de quorum independantes exigees ; aucun compte distant.";Scope=$true},
 @{Id="StartBridge";Title="Demarrer le pont Scattering";Hint="Dossier de transport distinct deja configure ; pacer et sink separes requis.";Scope=$true},
 @{Id="Providers";Title="Verifier la cryptographie";Hint="Diagnostic du fournisseur cryptographique natif."},
 @{Id="ProbeLoopback";Title="Tester le transport local";Hint="Diagnostic UDP local, sans compte ni reseau distant."},
 @{Id="MigrationCheck";Title="Verifier une sauvegarde de migration";Hint="Controle hors ligne des anciennes cles. Aucun transfert ou effacement."},
 @{Id="MigrationHistory";Title="Relire les messages historiques";Hint="Lecture locale de la sauvegarde verifiee. Aucun compte reactive."},
 @{Id="PayLab";Title="Quantic Pay - laboratoire";Hint="Portefeuille et paiements strictement fictifs. Aucune valeur monetaire."},
 @{Id="PayProvision";Title="Quantic Pay - creer le coffre";Hint="Nouveau dossier prive et phrase secrete distincte. Cles fictives." ;Scope=$true},
 @{Id="PayNative";Title="Quantic Pay - simulation avec coffre natif";Hint="Empreintes publiques independantes requises. Aucun transfert reel.";Scope=$true},
 @{Id="PayQuorumDemo";Title="Quantic Pay - simulation quorum 3/4";Hint="Quatre temoins locaux en memoire. Aucune autorite externe ni argent reel."},
 @{Id="PayNativeQuorum";Title="Quantic Pay - coffre natif + quorum local";Hint="NOUVEAU dossier de test obligatoire. Temoins locaux non persistants.";Scope=$true},
 @{Id="PayHistoryCheck";Title="Quantic Pay - verifier historique natif";Hint="Lecture seule des preuves signees. Aucune validation distante.";Scope=$true},
 @{Id="PayOperator";Title="Quantic Pay - portefeuille avec quatre temoins";Hint="Coffre configure et quatre ponts actifs requis. Simulation.";Scope=$true},
 @{Id="StartPayBridge";Title="Quantic Pay - demarrer pont dedie";Hint="Transport Pay uniquement. Dossier Scattering distinct deja configure.";Scope=$true},
 @{Id="PayOperatorConfigure";Title="Quantic Pay - importer configuration";Hint="Nouveau coffre fictif, configuration privee et empreinte independante.";Scope=$true},
 @{Id="PayCirculation";Title="Quantic Pay - circulation multi-portefeuilles";Hint="Transferts signes et tests du quorum en memoire. Cles fictives ephemeres."},
 @{Id="MailPreflight";Title="Quantic Mail - verifier les deux PC (hors ligne)";Hint="Verifie 4 autorites publiques, contact signe attendu et carrier prive. Aucune connexion ni transmission.";Scope=$true},
 @{Id="MailAttest";Title="Quantic Mail - verifier les quatre autorites en direct";Hint="Exige trois attestations mTLS fraiches sur quatre avant confirmation. N'envoie aucun mail.";Scope=$true}
)
# User-controlled pages are never rendered. Modules group existing local actions.
function Get-AlphaModule([string]$Id) {
 switch -Regex ($Id) {
  '^(ComposeDraft|SealAndSend|RecoverSealAndSend|Seal|RecoverSeal|Send|Receive|Open|RecoverOpen|RecoverReceive|ConfirmReceipt|MailPreflight|MailAttest)$' { return "QUANTIC MAIL" }
  '^(Provision|ProvisionPair)$' { return "QUANTIC ID" }
  '^Migration' { return "IDENTITY VAULT" }
  '^(StartBridge|ProbeLoopback)$' { return "SCATTERING" }
  '^(Pay|StartPayBridge)' { return "QUANTIC PAY - LAB" }
  '^(Providers)$' { return "DIAGNOSTIC" }
  default { throw "Unknown native operation; fail closed." }
 }
}
$modules=@("QUANTIC MAIL","QUANTIC ID","IDENTITY VAULT","SCATTERING","QUANTIC PAY - LAB","DIAGNOSTIC")
foreach ($action in $actions) { if ((Get-AlphaModule $action.Id) -notin $modules) { throw "Unknown module." } }
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
$form.ClientSize=New-Object Drawing.Size(760,622)
$form.MinimumSize=New-Object Drawing.Size(776,661)
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
$heading=Label-At "QUANTIC SILLAGE" 22 18 712 36
$heading.Font=New-Object Drawing.Font("Segoe UI",21,[Drawing.FontStyle]::Bold)
$null=Label-At "Interface locale | Mail / Quantic ID / Vault / Scattering / Pay" 24 58 710 25
$notice=Label-At "ALPHA - identites de test uniquement. Aucun compte reel ni migration." 24 90 710 38
$notice.ForeColor=[Drawing.Color]::Khaki
$null=Label-At "Module" 24 132 710 22
$module=New-Object Windows.Forms.ComboBox
$module.DropDownStyle="DropDownList";$module.SetBounds(24,157,712,30)
foreach ($m in $modules) { $null=$module.Items.Add($m) }
$form.Controls.Add($module)
$null=Label-At "Operation native" 24 197 710 22
$choice=New-Object Windows.Forms.ComboBox
$choice.DropDownStyle="DropDownList";$choice.SetBounds(24,221,712,30)
$form.Controls.Add($choice)
$hint=Label-At "" 24 262 712 45
$null=Label-At "Dossier prive du coffre (ou du transport pour le pont)" 24 316 712 23
$directory=Text-At 24 341 712
$il=Label-At "Fichier prive" 24 380 712 22
$inputName=Text-At 24 404 712
$ol=Label-At "Nouvelle enveloppe" 24 443 712 22
$outputName=Text-At 24 467 712
$run=New-Object Windows.Forms.Button;$run.Text="Rediger un brouillon"
$run.ForeColor=[Drawing.Color]::Black;$run.BackColor=[Drawing.Color]::FromArgb(196,223,244)
$run.SetBounds(24,533,513,42);$form.Controls.Add($run)
$quit=New-Object Windows.Forms.Button;$quit.Text="Fermer";$quit.ForeColor=[Drawing.Color]::Black
$quit.SetBounds(556,533,180,42);$form.Controls.Add($quit)
$quit.DialogResult=[Windows.Forms.DialogResult]::Cancel;$form.CancelButton=$quit
$form.AcceptButton=$run
$script:selectedArguments=$null;$script:selectedAction=$null
$script:shownActions=@()
$module.Add_SelectedIndexChanged({
 $choice.Items.Clear()
 $script:shownActions=@($actions | Where-Object { (Get-AlphaModule $_.Id) -ceq $module.SelectedItem })
 if ($script:shownActions.Count -lt 1) { throw "Empty native module." }
 foreach ($a in $script:shownActions) { $null=$choice.Items.Add($a.Title) }
 $choice.SelectedIndex=0
})
$choice.Add_SelectedIndexChanged({
 if ($choice.SelectedIndex -lt 0) { return }
 $a=$script:shownActions[$choice.SelectedIndex]
 $hint.Text=$a.Hint
 $run.Text=if($a.Id -eq 'ComposeDraft'){"Rediger mon message"}else{"Ouvrir le laboratoire technique"}
 $simple=$a.Id -eq 'ComposeDraft'
 foreach($control in @($directory,$il,$inputName,$ol,$outputName)){$control.Visible=-not $simple}
 $directory.Enabled=[bool]$a.Scope
 $inputName.Enabled=[bool]$a.Input
 $outputName.Enabled=[bool]$a.Output
 $il.Text=if($a.Input){"Fichier prive ("+$a.Input+"-nom.json)"}else{"Aucun fichier requis"}
 $ol.Text=if($a.Output){"Nouvelle enveloppe (wire-nom.json)"}else{"Aucune sortie a saisir"}
})
$run.Add_Click({
 try{
  $a=$script:shownActions[$choice.SelectedIndex]
  if($a.Id -eq 'ComposeDraft'){
   & (Join-Path $root 'Quantic-Sillage-Compose.ps1') -ExpectedManifestSha256 $ExpectedManifestSha256 -TrustedBinarySha256 $TrustedBinarySha256
   return
  }
  $warn=[Windows.Forms.MessageBox]::Show('Ceci est une operation de laboratoire reservee aux tests. Elle ouvrira volontairement un terminal technique. Continuer ?','Mode technique','YesNo','Warning')
  if($warn -ne [Windows.Forms.DialogResult]::Yes){return}
  $script:selectedArguments=New-OperationArguments $a $directory.Text $inputName.Text $outputName.Text
  $script:selectedAction=$a.Id
  $form.DialogResult=[Windows.Forms.DialogResult]::OK
 }catch{
  [Windows.Forms.MessageBox]::Show('Operation indisponible : verifiez les conditions du coffre de test. Aucune migration ni envoi implicite.','Operation non confirmee','OK','Warning')|Out-Null
 }
})
$module.SelectedIndex=0
if ($SelfTest) {
 try {
  if($actions.Count -ne 30 -or $script:shownActions[0].Id -ne 'ComposeDraft' -or $inputName.Visible -or $outputName.Visible){throw "Dashboard initialization failed"}
  $choice.SelectedIndex=1
  if(-not $inputName.Enabled -or -not $outputName.Enabled){throw "Advanced input fields missing"}
  $a=New-OperationArguments $actions[1] "C:\Quantic Lab\vault" "draft-test.json" "wire-test.json"
  if($a -notcontains "C:\Quantic Lab\vault\draft-test.json" -or $a -notcontains "C:\Quantic Lab\vault\wire-test.json"){throw "Wrong arguments"}
  $rejected=$false
  try{$null=New-OperationArguments $actions[4] "C:\Quantic Lab\vault" "..\wire-test.json" ""}catch{$rejected=$true}
  if(-not $rejected){throw "Path traversal accepted"}
  $module.SelectedItem="DIAGNOSTIC"
  if ($script:shownActions.Count -ne 1 -or $script:shownActions[0].Id -ne "Providers") { throw "Diagnostic module wrong" }
  if($directory.Enabled -or $inputName.Enabled -or $outputName.Enabled){throw "Diagnostic fields enabled"}
  foreach ($m in $modules) {
   $module.SelectedItem=$m
   if ($script:shownActions.Count -lt 1) { throw "Missing module: $m" }
  }
  $module.SelectedItem="QUANTIC MAIL"
  Write-Output "Dashboard controls and operation mapping verified"
 }finally{$form.Dispose()}
 exit 0
}
function Quote-AdvancedArg([string]$Value){
 if($Value.Contains('"') -or $Value.Contains([char]10) -or $Value.Contains([char]13)){throw 'Argument advanced non autorise'}
 return '"'+$Value+'"'
}
try{
 while($true){
  $script:selectedArguments=$null;$script:selectedAction=$null
  if($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){break}
  if(-not $script:selectedAction){continue}
  $advanced=Join-Path $root 'Quantic-Sillage-Advanced.ps1'
  $argv=@('-NoLogo','-NoProfile','-STA','-ExecutionPolicy','Bypass',
   '-File',(Quote-AdvancedArg $advanced),
   '-ExpectedManifestSha256',$ExpectedManifestSha256,
   '-TrustedBinarySha256',$TrustedBinarySha256,
   '-Operation',$script:selectedAction,
   '-Directory',(Quote-AdvancedArg $directory.Text),
   '-InputName',(Quote-AdvancedArg $inputName.Text),
   '-OutputName',(Quote-AdvancedArg $outputName.Text))
  $psi=New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName=$shell
  $psi.Arguments=$argv -join ' '
  $psi.UseShellExecute=$true
  $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Normal
  $child=[Diagnostics.Process]::Start($psi)
  if($null -eq $child){throw 'Le laboratoire technique ne peut pas demarrer'}
  $child.Dispose()
 }
}finally{$form.Dispose()}
