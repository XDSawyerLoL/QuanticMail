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
 @{Id="MailAttest";Title="Quantic Mail - verifier les quatre autorites en direct";Hint="Exige trois attestations mTLS fraiches sur quatre avant confirmation. N'envoie aucun mail.";Scope=$true},
 @{Id="MailRecovery";Title="Quantic Mail - reprendre un envoi";Hint="Choisir un message signe conserve, sans saisir de fichier. Le statut de depot n'est pas encore verifie.";Scope=$true}
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
function Invoke-RecoveryHelper([string[]]$Arguments,[string]$Consent="") {
 # Only trusted package launcher, validated arguments and a bounded hidden child.
 $tokens=@("-NoLogo","-NoProfile","-NonInteractive","-File",$launcher)+$Arguments
 foreach($token in $tokens) {
  if([string]::IsNullOrEmpty($token) -or $token -match '["\r\n]' -or $token.EndsWith('\')) {throw "Parametre interne refuse."}
 }
 $psi=New-Object System.Diagnostics.ProcessStartInfo
 $psi.FileName=$shell
 $psi.Arguments=($tokens|ForEach-Object{'"'+$_+'"'}) -join ' '
 $psi.WorkingDirectory=$root
 $psi.UseShellExecute=$false
 $psi.CreateNoWindow=$true
 $psi.WindowStyle=[System.Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardInput=$true
 $psi.RedirectStandardOutput=$true
 $psi.RedirectStandardError=$true
 $p=New-Object System.Diagnostics.Process
 $p.StartInfo=$psi
 try {
  if(-not $p.Start()){throw "Transport indisponible."}
  $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
  if($Consent){$p.StandardInput.WriteLine($Consent)}
  $p.StandardInput.Close()
  if(-not $p.WaitForExit(120000)){try{$p.Kill()}catch{};throw "Operation non confirmee."}
  $raw=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
  if($raw.Length -gt 65536){throw "Reponse inattendue."}
  $lines=@($raw -split '\r?\n'|Where-Object{$_ -cmatch '^QUANTIC_GUI_RESULT '})
  if($lines.Count -ne 1){throw "Operation non confirmee."}
  $result=$lines[0].Substring(19)|ConvertFrom-Json
  if($p.ExitCode -ne 0 -and $result.status -ne "deposit-unconfirmed"){throw "Operation non confirmee."}
  return $result
 }finally{$p.Dispose()}
}
function Show-MailRecovery([string]$Directory) {
 $argsList=New-OperationArguments @{Id="MailRecoveryList";Scope=$true} $Directory "" ""
 $result=Invoke-RecoveryHelper $argsList
 if($result.status -ne "saved-messages"){throw "Liste indisponible."}
 $rows=@($result.messages)
 if($rows.Count -eq 0){
  [Windows.Forms.MessageBox]::Show("Aucun message signe conserve dans ce coffre.","Quantic Mail","OK","Information")|Out-Null
  return
 }
 if($rows.Count -gt 64){throw "Liste trop longue."}
 $picker=New-Object Windows.Forms.Form
 $picker.Text="Quantic Mail - reprendre un envoi"
 $picker.StartPosition="CenterScreen";$picker.ClientSize=New-Object Drawing.Size(670,320)
 $info=New-Object Windows.Forms.Label
 $info.Text="Messages signes conserves. Leur statut de depot n'est pas verifie. Choisissez le message a reprendre."
 $info.SetBounds(15,15,640,48);$picker.Controls.Add($info)
 $list=New-Object Windows.Forms.ListBox
 $list.SetBounds(15,70,640,180);$list.HorizontalScrollbar=$true
 foreach($row in $rows){
  if($row.name -cnotmatch '^wire-[a-z0-9-]{1,48}\.json$' -or $row.digest -cnotmatch '^[a-f0-9]{64}$' -or $row.recipient -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$'){throw "Message interne invalide."}
  $reference=([string]$row.reference) -replace '[\x00-\x1f\x7f]',' '
  $null=$list.Items.Add(($row.recipient+"  |  "+$reference))
 }
 $picker.Controls.Add($list)
 $ok=New-Object Windows.Forms.Button;$ok.Text="Reprendre";$ok.SetBounds(335,265,155,35);$ok.Enabled=$false
 $ok.DialogResult=[Windows.Forms.DialogResult]::OK;$picker.Controls.Add($ok);$picker.AcceptButton=$ok
 $cancel=New-Object Windows.Forms.Button;$cancel.Text="Annuler";$cancel.SetBounds(500,265,155,35)
 $cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel;$picker.Controls.Add($cancel);$picker.CancelButton=$cancel
 $list.Add_SelectedIndexChanged({$ok.Enabled=$list.SelectedIndex -ge 0})
 try{
  if($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK -or $list.SelectedIndex -lt 0){return}
  $selected=$rows[$list.SelectedIndex]
 }finally{$picker.Dispose()}
 $question="Reprendre ce message pour "+$selected.recipient+" ? Le message original sera transmis sans nouvelle signature. Si le depot existe deja, le relais ne cree pas de doublon."
 if([Windows.Forms.MessageBox]::Show($question,"Confirmer la reprise","YesNo","Question") -ne [Windows.Forms.DialogResult]::Yes){return}
 $argsRetry=New-OperationArguments @{Id="MailRecoveryRetry";Scope=$true} $Directory "" ""
 $argsRetry+=@("-InputFile",[IO.Path]::Combine($Directory,$selected.name),"-OutputFile",$selected.digest)
 $reply=Invoke-RecoveryHelper $argsRetry ("APPROVE "+$selected.digest)
 if($reply.digest -cne $selected.digest){throw "Reponse inattendue."}
 if($reply.status -eq "deposited"){
  [Windows.Forms.MessageBox]::Show("Depot confirme par le relais. Le message original reste conserve.","Quantic Mail","OK","Information")|Out-Null
 }else{
  [Windows.Forms.MessageBox]::Show("Depot toujours non confirme. Le message original reste conserve. Retablissez le transport avant une nouvelle reprise.","Quantic Mail","OK","Warning")|Out-Null
 }
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
 $run.Text=if($a.Id -eq "MailRecovery"){"Choisir un message"}else{"Continuer dans le terminal securise"}
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
  if($choice.Items.Count -ne 30 -or -not $inputName.Enabled -or -not $outputName.Enabled){throw "Dashboard initialization failed"}
  $a=New-OperationArguments $actions[0] "C:\Quantic Lab\vault" "draft-test.json" "wire-test.json"
  if($a -notcontains "C:\Quantic Lab\vault\draft-test.json" -or $a -notcontains "C:\Quantic Lab\vault\wire-test.json"){throw "Wrong arguments"}
  $rejected=$false
  try{$null=New-OperationArguments $actions[3] "C:\Quantic Lab\vault" "..\wire-test.json" ""}catch{$rejected=$true}
  if(-not $rejected){throw "Path traversal accepted"}
  $choice.SelectedIndex=13
  if($directory.Enabled -or $inputName.Enabled -or $outputName.Enabled){throw "Diagnostic fields enabled"}
  $choice.SelectedIndex=29
  if(-not $directory.Enabled -or $inputName.Enabled -or $outputName.Enabled -or $run.Text -ne "Choisir un message"){throw "Recovery controls failed"}
  $recoveryArgs=New-OperationArguments @{Id="MailRecoveryList";Scope=$true} "C:\Quantic Lab\vault" "" ""
  if($recoveryArgs -contains "-InputFile" -or $recoveryArgs -contains "-OutputFile"){throw "Recovery listing asks for technical filenames"}
  Write-Output "Dashboard controls and operation mapping verified"
 }finally{$form.Dispose()}
 exit 0
}
try {
 while ($true) {
  $script:selectedArguments=$null;$script:selectedAction=$null
  if ($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { break }
  $operationArgs=$script:selectedArguments
  if($script:selectedAction -eq "MailRecovery"){
   try{Show-MailRecovery $directory.Text}catch{[Windows.Forms.MessageBox]::Show("Operation non confirmee. Les messages signes sont conserves.","Quantic Mail","OK","Warning")|Out-Null}
   continue
  }
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
  Write-Host ""
  Write-Host "Quantic Sillage - operation locale. Les validations du coffre restent obligatoires."
  & $shell -NoProfile -File $launcher @operationArgs
  $code=$LASTEXITCODE
  Write-Host "Code de retour: $code. Un code nul n'est pas une preuve de livraison distante."
  $null=Read-Host "Entree pour revenir au tableau de bord"
 }
}finally{$form.Dispose()}
