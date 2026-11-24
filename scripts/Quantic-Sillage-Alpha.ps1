# Local operator dashboard. Secrets, cryptographic operations and approvals
# remain with the pre-existing native terminal tools. Not production enrollment.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$TrustedBinarySha256,
 [switch]$SelfTest,
 [string]$AdvancedAction,
 [string]$AdvancedDirectory,
 [string]$AdvancedInputName,
 [string]$AdvancedOutputName
)
$ErrorActionPreference="Stop"
$root=$PSScriptRoot
$launcher=Join-Path $root "Start-Windows-PQ-Lab.ps1"
$shell=Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$actions=@(
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
 @{Id="ProvisionGui";Title="Identity Vault - Creer mon identite de test";Hint="Assistant graphique : deux phrases secretes distinctes. Empreinte du quorum approuvee requise. Aucun compte distant.";Scope=$true},
 @{Id="VerifyGui";Title="Identity Vault - Verifier mon coffre existant";Hint="Ouvrir les deux coffres avec leurs phrases secretes, verifier les cles locales puis les refermer. Aucun compte distant.";Scope=$true},
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
 @{Id="ComposeGui";Title="Quantic Mail - Nouveau message";Hint="Rediger dans une fenetre. Le brouillon est chiffre automatiquement dans le coffre; confirmation avant envoi.";Scope=$true},
 @{Id="RecoverComposeGui";Title="Quantic Mail - Reprendre un message interrompu";Hint="Reprendre le meme brouillon et la meme signature. Aucun nouvel envoi automatique.";Scope=$true},
 @{Id="SendGui";Title="Quantic Mail - Envoyer une enveloppe";Hint="Choisir une enveloppe deja chiffree et signee. Confirmation graphique avant depot sur le relais local.";Scope=$true},
 @{Id="ReceiveGui";Title="Quantic Mail - Recevoir un message";Hint="Lire un message authentifie, conserver automatiquement un recu chiffre avant confirmation.";Scope=$true},
 @{Id="ImportMailKitGui";Title="Quantic Mail - Activer ma configuration de test";Hint="Importer le kit prive fourni par un operateur de confiance. Aucun remplacement de cle ni inscription distante.";Scope=$true},
 @{Id="ImportSessionKitGui";Title="Quantic ID - Activer ma configuration";Hint="Importer le kit prive approuve, une seule fois. Aucun compte reel.";Scope=$true},
 @{Id="SessionGui";Title="Quantic ID - Ouvrir ma session";Hint="Connexion de test a trois autorites minimum; verrouillage automatique Windows. Configuration privee approuvee requise.";Scope=$true},
 @{Id="MailAttest";Title="Quantic Mail - verifier les quatre autorites en direct";Hint="Exige trois attestations mTLS fraiches sur quatre avant confirmation. N'envoie aucun mail.";Scope=$true}
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
$directory=Text-At 24 270 530
$browse=New-Object Windows.Forms.Button;$browse.Text="Choisir..."
$browse.ForeColor=[Drawing.Color]::Black;$browse.SetBounds(566,270,130,28)
$form.Controls.Add($browse)
$browse.Add_Click({
 $picker=New-Object Windows.Forms.FolderBrowserDialog
 $picker.Description=if($actions[$choice.SelectedIndex].Id -in @("VerifyGui","SendGui","ReceiveGui","ComposeGui","RecoverComposeGui","ImportMailKitGui","ImportSessionKitGui","SessionGui")){"Choisir le dossier du coffre existant"}else{"Choisir le dossier parent du nouveau coffre de test"}
 $picker.ShowNewFolderButton=$false
 try{
  if($picker.ShowDialog() -eq [Windows.Forms.DialogResult]::OK){
   $directory.Text=if($actions[$choice.SelectedIndex].Id -in @("VerifyGui","SendGui","ReceiveGui","ComposeGui","RecoverComposeGui","ImportMailKitGui","ImportSessionKitGui","SessionGui")){$picker.SelectedPath}else{[IO.Path]::Combine($picker.SelectedPath,("Quantic-Test-"+[Guid]::NewGuid().ToString("N").Substring(0,12)))}
  }
 }finally{$picker.Dispose()}
})
$il=Label-At "Fichier prive" 24 309 672 22
$inputName=Text-At 24 333 672
$ol=Label-At "Nouvelle enveloppe" 24 372 672 22
$outputName=Text-At 24 396 672
$run=New-Object Windows.Forms.Button;$run.Text="Continuer"
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
 $run.Text=if($a.Id -eq "ProvisionGui"){"Creer mon identite"}elseif($a.Id -eq "VerifyGui"){"Verifier et refermer le coffre"}elseif($a.Id -eq "ImportSessionKitGui"){"Activer ma configuration"}elseif($a.Id -eq "SessionGui"){"Ouvrir ma session"}elseif($a.Id -eq "ImportMailKitGui"){"Importer la configuration"}elseif($a.Id -eq "ComposeGui"){"Rediger un message"}elseif($a.Id -eq "RecoverComposeGui"){"Reprendre le message"}elseif($a.Id -eq "SendGui"){"Choisir et envoyer"}elseif($a.Id -eq "ReceiveGui"){"Recevoir"}else{"Ouvrir les outils avances (terminal)"}
 $directory.Enabled=[bool]$a.Scope
 $browse.Visible=($a.Id -in @("ProvisionGui","VerifyGui","SendGui","ReceiveGui","ComposeGui","RecoverComposeGui","ImportMailKitGui","ImportSessionKitGui","SessionGui"))
 $directory.Width=if($browse.Visible){530}else{672}
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
if (-not $SelfTest -and -not $AdvancedAction) {$choice.SelectedIndex=10}
if ($SelfTest) {
 try {
  if($choice.Items.Count -ne 37 -or -not $inputName.Enabled -or -not $outputName.Enabled){throw "Dashboard initialization failed"}
  $a=New-OperationArguments $actions[0] "C:\Quantic Lab\vault" "draft-test.json" "wire-test.json"
  if($a -notcontains "C:\Quantic Lab\vault\draft-test.json" -or $a -notcontains "C:\Quantic Lab\vault\wire-test.json"){throw "Wrong arguments"}
  $rejected=$false
  try{$null=New-OperationArguments $actions[3] "C:\Quantic Lab\vault" "..\wire-test.json" ""}catch{$rejected=$true}
  if(-not $rejected){throw "Path traversal accepted"}
  $choice.SelectedIndex=14
  if($directory.Enabled -or $inputName.Enabled -or $outputName.Enabled){throw "Diagnostic fields enabled"}
  $choice.SelectedIndex=10
  if($actions[10].Id -cne "ProvisionGui" -or $inputName.Enabled -or $outputName.Enabled -or -not $directory.Enabled){throw "Graphical identity action unavailable"}
  $provisionArgs=New-OperationArguments $actions[10] "C:\Quantic Lab\new-test-vault" "" ""
  if($provisionArgs -notcontains "ProvisionGui" -or $provisionArgs -contains "-InputFile" -or $provisionArgs -contains "-OutputFile"){throw "Graphical identity arguments refused"}
  $choice.SelectedIndex=11
  if($actions[11].Id -cne "VerifyGui" -or $inputName.Enabled -or $outputName.Enabled -or -not $directory.Enabled){throw "Graphical verification action unavailable"}
  $verifyArgs=New-OperationArguments $actions[11] "C:\Quantic Lab\new-test-vault" "" ""
  if($verifyArgs -notcontains "VerifyGui" -or $verifyArgs -contains "-InputFile"){throw "Graphical verification mapping refused"}
  foreach($id in @("SendGui","ReceiveGui","ComposeGui","RecoverComposeGui","ImportMailKitGui","ImportSessionKitGui","SessionGui")){
   $mailAction=@($actions|Where-Object {$_.Id -ceq $id})
   if($mailAction.Count -ne 1){throw "Missing graphical mail operation"}
   $mailArgs=New-OperationArguments $mailAction[0] "C:\Quantic Lab\vault" "" ""
   if($mailArgs -notcontains $id -or $mailArgs -contains "-InputFile"){throw "Graphical mail mapping refused"}
  }
  Write-Output "Dashboard controls, graphical identity and mail route verified"
 }finally{$form.Dispose()}
 exit 0
}
function Invoke-AdvancedOperation([string]$ActionId,$operationArgs) {
 $script:selectedAction=$ActionId
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
    if ($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { return }
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
# A visible terminal is opened only for explicitly selected legacy operations.
if ($AdvancedAction) {
 try {
  $a=@($actions | Where-Object {$_.Id -ceq $AdvancedAction})
  if($a.Count -ne 1 -or $AdvancedAction -in @("ProvisionGui","VerifyGui","SendGui","ReceiveGui","ComposeGui","RecoverComposeGui","ImportMailKitGui","ImportSessionKitGui","SessionGui")){throw "Operation avancee refusee"}
  $op=New-OperationArguments $a[0] $AdvancedDirectory $AdvancedInputName $AdvancedOutputName
  Invoke-AdvancedOperation $AdvancedAction $op
 }finally{$form.Dispose()}
 exit 0
}
function Read-PublicValue([string]$Title,[string]$Prompt) {
 $dialog=New-Object Windows.Forms.Form
 $dialog.Text=$Title;$dialog.StartPosition="CenterScreen"
 $dialog.ClientSize=New-Object Drawing.Size(570,150)
 $dialog.FormBorderStyle="FixedDialog";$dialog.MaximizeBox=$false;$dialog.MinimizeBox=$false
 $label=New-Object Windows.Forms.Label;$label.Text=$Prompt;$label.SetBounds(12,12,546,45)
 $field=New-Object Windows.Forms.TextBox;$field.SetBounds(12,62,546,25)
 $ok=New-Object Windows.Forms.Button;$ok.Text="Continuer";$ok.SetBounds(345,105,100,30)
 $ok.DialogResult=[Windows.Forms.DialogResult]::OK
 $cancel=New-Object Windows.Forms.Button;$cancel.Text="Annuler";$cancel.SetBounds(455,105,100,30)
 $cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel
 $dialog.Controls.AddRange(@($label,$field,$ok,$cancel));$dialog.AcceptButton=$ok;$dialog.CancelButton=$cancel
 try{if($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK){return $field.Text};return $null}
 finally{$dialog.Dispose()}
}
function Invoke-GraphicalProvision($operationArgs) {
 $address=Read-PublicValue "Identity Vault - Identite" "Adresse canonique de test fournie par la preparation independante."
 if($null -eq $address){return}
 $quorum=Read-PublicValue "Identity Vault - Confiance" "Empreinte SHA256 du quorum, obtenue et verifiee independamment."
 if($null -eq $quorum){return}
 if($address -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$' -or $quorum -cnotmatch '^[a-f0-9]{64}$'){throw "Adresse ou empreinte publique invalide."}
 $operationArgs+=@("-CanonicalAddress",$address,"-QuorumPin",$quorum)
 # The verified package entrypoint invokes the native vault. Native Win32
 # dialogs collect the passwords; no secret enters PowerShell or the args.
 $publicResult=& $shell -NoProfile -File $launcher @operationArgs
 if($LASTEXITCODE -ne 0){throw "Creation annulee ou refusee. Conserver tout dossier partiel."}
 # Package verifier prints a status before the native JSON result.
 $record=($publicResult | Select-Object -Last 1 | ConvertFrom-Json)
 if($record.status -cne "local-provision-only-not-enrolled" -or $record.localReadback -cne "verified" -or $record.address -cne $address -or $record.deviceId -cnotmatch '^d-[a-f0-9]{32}$'){throw "Resultat natif non confirme. Conserver le dossier."}
 [Windows.Forms.MessageBox]::Show("Identite de test creee localement. Le coffre est ferme. Aucun compte distant inscrit.","Identity Vault","OK","Information")|Out-Null
}
function Invoke-GraphicalVerify($operationArgs) {
 $publicResult=& $shell -NoProfile -File $launcher @operationArgs
 if($LASTEXITCODE -ne 0){throw "Verification annulee ou refusee. Le coffre reste ferme."}
 $record=($publicResult | Select-Object -Last 1 | ConvertFrom-Json)
 if($record.status -cne "local-vault-verified-closed"){throw "Verification non confirmee."}
 [Windows.Forms.MessageBox]::Show("Les deux coffres ont ete ouverts et verifies, puis refermes. Aucun compte distant connecte.","Identity Vault","OK","Information")|Out-Null
}
function Read-GraphicalMessage {
 $dialog=New-Object Windows.Forms.Form
 $dialog.Text="Quantic Mail - Nouveau message";$dialog.StartPosition="CenterScreen"
 $dialog.ClientSize=New-Object Drawing.Size(650,475)
 $dialog.FormBorderStyle="FixedDialog";$dialog.MaximizeBox=$false
 $toLabel=New-Object Windows.Forms.Label;$toLabel.Text="Destinataire (adresse Quantic d'un contact valide)";$toLabel.SetBounds(12,12,625,24)
 $to=New-Object Windows.Forms.TextBox;$to.SetBounds(12,39,625,28);$to.MaxLength=96
 $subjectLabel=New-Object Windows.Forms.Label;$subjectLabel.Text="Objet";$subjectLabel.SetBounds(12,75,625,24)
 $subject=New-Object Windows.Forms.TextBox;$subject.SetBounds(12,102,625,28);$subject.MaxLength=512
 $bodyLabel=New-Object Windows.Forms.Label;$bodyLabel.Text="Message";$bodyLabel.SetBounds(12,138,625,24)
 $body=New-Object Windows.Forms.TextBox;$body.Multiline=$true;$body.ScrollBars="Vertical";$body.SetBounds(12,165,625,250);$body.MaxLength=7500
 $ok=New-Object Windows.Forms.Button;$ok.Text="Continuer";$ok.SetBounds(405,430,110,30);$ok.DialogResult=[Windows.Forms.DialogResult]::OK
 $cancel=New-Object Windows.Forms.Button;$cancel.Text="Annuler";$cancel.SetBounds(525,430,110,30);$cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel
 $dialog.Controls.AddRange(@($toLabel,$to,$subjectLabel,$subject,$bodyLabel,$body,$ok,$cancel));$dialog.CancelButton=$cancel
 try {
  if($dialog.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return $null}
  if($to.Text -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$'){throw "Adresse Quantic invalide."}
  if([Text.Encoding]::UTF8.GetByteCount($subject.Text)+[Text.Encoding]::UTF8.GetByteCount($body.Text) -gt 7500){throw "Message trop long."}
  return @{to=$to.Text;subject=$subject.Text;body=$body.Text}
 }finally{$subject.Clear();$body.Clear();$dialog.Dispose()}
}
function Invoke-ComposePipe([string]$vaultDir,$fields){
 $json=$fields|ConvertTo-Json -Compress
 # JSON travels as ASCII with Unicode escapes; preserve accents and emoji.
 $ascii=[Regex]::Replace($json,'[^\x00-\x7f]',[System.Text.RegularExpressions.MatchEvaluator]{param($m) '\u{0:x4}' -f [int][char]$m.Value})
 $psi=New-Object System.Diagnostics.ProcessStartInfo
 $psi.FileName=$shell
 $psi.Arguments='-NoProfile -NonInteractive -File "'+$launcher+'" -Operation ComposeGui -ExpectedManifestSha256 '+$ExpectedManifestSha256+' -TrustedBinarySha256 '+$TrustedBinarySha256+' -PrivateDirectory "'+$vaultDir+'"'
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true
 $child=[System.Diagnostics.Process]::Start($psi)
 try{
  $child.StandardInput.Write($ascii);$child.StandardInput.Close()
  $result=$child.StandardOutput.ReadToEnd();$child.WaitForExit()
  if($child.ExitCode -ne 0){throw "Message non confirme. Reprendre le brouillon conserve plutot que creer un nouvel envoi."}
  return (($result -split '\r?\n') | Where-Object {$_ -ne ""} | Select-Object -Last 1)
 }finally{$child.Dispose();$json=$null;$ascii=$null}
}
function Invoke-MailKitImport($operationArgs) {
 $picker=New-Object Windows.Forms.OpenFileDialog
 $picker.Title="Choisir le kit prive de configuration"
 $picker.Filter="Kit Quantic (onboarding.json)|onboarding.json";$picker.Multiselect=$false
 try{if($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return};$source=$picker.FileName}finally{$picker.Dispose()}
 $pin=Read-PublicValue "Quantic Mail - Confiance" "Empreinte SHA256 du kit, recue par un canal authentifie independant."
 if($null -eq $pin){return}
 if($pin -cnotmatch '^[a-f0-9]{64}$'){throw "Empreinte invalide."}
 $operationArgs+=@("-InputFile",$source,"-ExpectedTrustSha256",$pin)
 $result=& $shell -NoProfile -File $launcher @operationArgs
 if($LASTEXITCODE -ne 0){throw "Import refuse ou incomplet. Conserver le coffre et le kit; aucun remplacement automatique."}
 $record=($result | Select-Object -Last 1 | ConvertFrom-Json)
 if($record.status -cne "local-mail-kit-imported-not-enrolled"){throw "Import non confirme."}
 [Windows.Forms.MessageBox]::Show("Configuration locale importee et relue. Les autorites et le transport doivent encore etre controles. Aucun compte distant inscrit.","Quantic Mail","OK","Information")|Out-Null
}
function Invoke-SessionKitImport($operationArgs) {
 $picker=New-Object Windows.Forms.OpenFileDialog
 $picker.Title="Choisir la configuration privee Quantic ID"
 $picker.Filter="Kit Quantic ID (session-kit.json)|session-kit.json";$picker.Multiselect=$false
 try{if($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return};$source=$picker.FileName}finally{$picker.Dispose()}
 $pin=Read-PublicValue "Quantic ID - Verification" "Empreinte SHA256 recue separement de votre operateur de confiance."
 if($null -eq $pin){return}
 if($pin -cnotmatch '^[a-f0-9]{64}$'){throw "Empreinte invalide."}
 $operationArgs+=@("-InputFile",$source,"-ExpectedTrustSha256",$pin)
 $result=& $shell -NoProfile -File $launcher @operationArgs
 if($LASTEXITCODE -ne 0){throw "Configuration refusee. Aucun remplacement autorise."}
 $record=($result | Select-Object -Last 1 | ConvertFrom-Json)
 if($record.status -cne "local-session-kit-imported-lab"){throw "Import non confirme."}
 [Windows.Forms.MessageBox]::Show("Configuration importee et relue. Utiliser Ouvrir ma session. Aucun compte reel active.","Quantic ID","OK","Information")|Out-Null
}
function Invoke-GraphicalSession([string]$vaultDir) {
 $pin="approved"
 # The startup manifest pin is supplied by the native launcher, not the configuration.
 $manifest=Join-Path $root "SHA256SUMS.txt"
 if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256){throw "Integrite du paquet refusee."}
 $verifier=Join-Path $root "Test-Windows-PQ-Package.ps1"
 $line=@(Get-Content -LiteralPath $manifest | Where-Object {$_ -cmatch '^[a-f0-9]{64} \*\./Test-Windows-PQ-Package\.ps1$'})
 if($line.Count -ne 1 -or (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash -ine $line[0].Substring(0,64)){throw "Verificateur refuse."}
 & $verifier -PackageDirectory $root -ExpectedManifestSha256 $ExpectedManifestSha256 | Out-Null
 $node=Join-Path $root "runtime\node.exe";$vault=Join-Path $root "bin\Vault-PQ-lab.exe";$scriptFile=Join-Path $root "scripts\native-windows-session-ui.mjs"
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw "Coffre refuse."}
 $psi=New-Object System.Diagnostics.ProcessStartInfo
 $psi.FileName=$node
 $psi.Arguments='--experimental-transform-types "'+$scriptFile+'" "'+$vault+'" '+$TrustedBinarySha256.ToLowerInvariant()+' "'+$vaultDir+'" '+$pin
 $psi.WorkingDirectory=$root;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true
 foreach($v in @("NODE_OPTIONS","NODE_PATH","OPENSSL_CONF","OPENSSL_MODULES","OPENSSL_ENGINES")){$psi.EnvironmentVariables.Remove($v)}
 $psi.EnvironmentVariables["PATH"]=(Join-Path $root "bin")+";"+(Join-Path $env:SystemRoot "System32")
 $dialog=New-Object Windows.Forms.Form
 $dialog.Text="Quantic ID | Session de test";$dialog.StartPosition="CenterScreen"
 $dialog.ClientSize=New-Object Drawing.Size(600,190);$dialog.FormBorderStyle="FixedDialog";$dialog.MaximizeBox=$false
 $status=New-Object Windows.Forms.Label;$status.Text="Connexion en cours...";$status.SetBounds(18,16,564,88)
 $lock=New-Object Windows.Forms.Button;$lock.Text="Verrouiller et fermer";$lock.SetBounds(340,130,242,36)
 $lock.DialogResult=[Windows.Forms.DialogResult]::Cancel;$dialog.CancelButton=$lock
 $dialog.Controls.AddRange(@($status,$lock))
 $child=$null;$timer=New-Object Windows.Forms.Timer;$timer.Interval=150
 $state=@{read=$null;expiry=0L;terminal=$false}
 try{
  $child=[System.Diagnostics.Process]::Start($psi)
  $state.read=$child.StandardOutput.ReadLineAsync()
  $timer.Add_Tick({
   try{
    if($state.expiry -gt 0 -and [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge $state.expiry){
     $status.Text="Session expiree. Verrouillee localement.";$state.terminal=$true;$timer.Stop();return
    }
    if($state.read.IsCompleted){
     $line=$state.read.GetAwaiter().GetResult()
     if($null -eq $line){$status.Text="Session fermee ou indisponible.";$state.terminal=$true;$timer.Stop();return}
     if($line.Length -gt 4096){throw "Resultat invalide."}
     $record=$line|ConvertFrom-Json
     switch -CaseSensitive ($record.status){
      "authenticating" {$status.Text="Authentification du coffre et des autorites..."}
      "authenticated" {
       if($record.address -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$'){throw "Identite invalide."}
       $state.expiry=[long]$record.expires
       $status.Text="IDENTITE AUTHENTIFIEE (TEST)"+[Environment]::NewLine+$record.address+[Environment]::NewLine+"Session limitee a 60 secondes."
      }
      "locked" {$status.Text=if($record.remoteLockConfirmed -eq $true){"Session verrouillee, fermeture distante confirmee."}else{"Session locale verrouillee. Fermeture distante non confirmee."};$state.terminal=$true;$timer.Stop();return}
      "refused" {$status.Text="Connexion refusee. Verifier la configuration et les autorites.";$state.terminal=$true;$timer.Stop();return}
      default {throw "Statut inconnu."}
     }
     $state.read=$child.StandardOutput.ReadLineAsync()
    }
   }catch{$status.Text="Session interrompue.";$state.terminal=$true;$timer.Stop();try{$child.StandardInput.Close()}catch{}}
  })
  $timer.Start();$null=$dialog.ShowDialog()
 }finally{
  $timer.Stop();$timer.Dispose()
  if($null -ne $child){
   try{$child.StandardInput.Close()}catch{}
   try{if(-not $child.WaitForExit(8000)){$child.Kill();$child.WaitForExit()}}catch{}
   $child.Dispose()
  }
  $dialog.Dispose()
 }
}
function Invoke-GraphicalMail([string]$action,$operationArgs,[string]$vaultDir) {
 if($action -eq "ComposeGui"){
  $fields=Read-GraphicalMessage
  if($null -eq $fields){return}
  try{$publicResult=Invoke-ComposePipe $vaultDir $fields}finally{$fields.Clear()}
 }elseif($action -eq "RecoverComposeGui"){
  $picker=New-Object Windows.Forms.OpenFileDialog
  $picker.Title="Choisir un brouillon conserve"
  $picker.Filter="Brouillon Quantic (*.json)|draft-*.json";$picker.InitialDirectory=$vaultDir;$picker.Multiselect=$false
  try{if($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return};$file=$picker.FileName}finally{$picker.Dispose()}
  if([IO.Path]::GetDirectoryName($file) -cne $vaultDir -or [IO.Path]::GetFileName($file) -cnotmatch '^draft-([a-f0-9-]{36})\.json$'){throw "Choisir un brouillon cree par cet assistant."}
  $wire=[IO.Path]::Combine($vaultDir,("wire-"+$Matches[1]+".json"))
  if([IO.File]::Exists($wire)){throw "Une enveloppe est deja conservee. Utiliser Envoyer une enveloppe pour ne pas resigner."}
  $operationArgs+=@("-InputFile",$file,"-OutputFile",$wire)
  $publicResult=& $shell -NoProfile -File $launcher @operationArgs
  if($LASTEXITCODE -ne 0){throw "Reprise non confirmee. Conserver le brouillon."}
 }elseif($action -eq "SendGui"){
  $picker=New-Object Windows.Forms.OpenFileDialog
  $picker.Title="Choisir une enveloppe chiffree"
  $picker.Filter="Enveloppe Quantic (*.json)|wire-*.json"
  $picker.InitialDirectory=$vaultDir;$picker.Multiselect=$false
  try{
   if($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return}
   $file=$picker.FileName
  }finally{$picker.Dispose()}
  if([IO.Path]::GetDirectoryName($file) -cne $vaultDir -or [IO.Path]::GetFileName($file) -cnotmatch '^wire-[a-z0-9-]{1,48}\.json$'){throw "Choisir une enveloppe du coffre selectionne."}
 }elseif($action -eq "ReceiveGui"){
  $file=[IO.Path]::Combine($vaultDir,("receipt-"+[Guid]::NewGuid().ToString("N")+".json"))
 }else{throw "Action mail refusee"}
 if($action -in @("SendGui","ReceiveGui")){
  $operationArgs+=@("-InputFile",$file)
  $publicResult=& $shell -NoProfile -File $launcher @operationArgs
  if($LASTEXITCODE -ne 0){throw "Operation non confirmee. Conserver les donnees existantes; aucun nouvel envoi automatique."}
 }
 $record=($publicResult | Select-Object -Last 1 | ConvertFrom-Json)
 $message=switch -CaseSensitive ($record.status){
  "deposited" {"Depot confirme par le relais local. Ce depot ne prouve pas la lecture.";break}
  "acknowledged" {"Message authentifie et recu chiffre conserve. Confirmation transmise au relais. "+[Environment]::NewLine+[Environment]::NewLine+$record.display;break}
  "empty" {"Aucun message en attente.";break}
  "saved-not-sent" {"Message chiffre et enregistre, mais non envoye.";break}
  "cancelled-before-seal" {"Operation annulee. Le brouillon chiffre est conserve.";break}
  "cancelled" {"Operation annulee.";break}
  default {throw "Resultat de messagerie inconnu."}
 }
 [Windows.Forms.MessageBox]::Show($message,"Quantic Mail","OK","Information")|Out-Null
}
try {
 while ($true) {
  $script:selectedArguments=$null;$script:selectedAction=$null
  if ($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { break }
  try{
   if ($script:selectedAction -eq "ProvisionGui") {
    Invoke-GraphicalProvision $script:selectedArguments
   }elseif($script:selectedAction -eq "VerifyGui"){
    Invoke-GraphicalVerify $script:selectedArguments
   }elseif($script:selectedAction -eq "ImportSessionKitGui"){
    Invoke-SessionKitImport $script:selectedArguments
   }elseif($script:selectedAction -eq "SessionGui"){
    Invoke-GraphicalSession $directory.Text
   }elseif($script:selectedAction -eq "ImportMailKitGui"){
    Invoke-MailKitImport $script:selectedArguments
   }elseif($script:selectedAction -in @("SendGui","ReceiveGui","ComposeGui","RecoverComposeGui")){
    Invoke-GraphicalMail $script:selectedAction $script:selectedArguments $directory.Text
   }else{
    # All values have already been validated by New-OperationArguments.
    # Quote only the strictly validated public path and technical names.
    $parts=@("-NoProfile","-STA","-File",('"' + $PSCommandPath + '"'),"-ExpectedManifestSha256",$ExpectedManifestSha256,"-TrustedBinarySha256",$TrustedBinarySha256,"-AdvancedAction",$script:selectedAction)
    $a=$actions[$choice.SelectedIndex]
    if($a.Scope){$parts+=@("-AdvancedDirectory",('"' + $directory.Text + '"'))}
    if($a.Input){$parts+=@("-AdvancedInputName",$inputName.Text)}
    if($a.Output){$parts+=@("-AdvancedOutputName",$outputName.Text)}
    Start-Process -FilePath $shell -ArgumentList ($parts -join " ") -Wait -WindowStyle Normal
   }
  }catch{
   [Windows.Forms.MessageBox]::Show($_.Exception.Message,"Operation non terminee","OK","Warning")|Out-Null
  }
 }
}finally{$form.Dispose()}
