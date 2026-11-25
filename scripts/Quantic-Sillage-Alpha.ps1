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
 @{Id="ImportMailboxActivation";Title="Configurer ma messagerie de test";Hint="Importer le dossier prive authentifie fourni par mon operateur, sans configuration technique manuelle.";Scope=$false},
 @{Id="PrepareMailboxCredential";Title="Preparer ma messagerie de test";Hint="Verifier les trois approbations et proteger mon jeton local. Aucune activation distante.";Scope=$false},
 @{Id="AnswerEnrollment";Title="Prouver mon identite de test";Hint="Repondre au defi signe de mon operateur independant, sans transmettre de secret ni activer un compte.";Scope=$false},
 @{Id="PrepareEnrollment";Title="Preparer mon inscription de test";Hint="Creer une nouvelle identite avec ses racines proprietaires distinctes. Empreinte du quorum approuvee requise ; aucune inscription distante.";Scope=$false},
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
  '^(PrepareEnrollment|AnswerEnrollment|PrepareMailboxCredential|ImportMailboxActivation|Provision|ProvisionPair)$' { return "QUANTIC ID" }
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
# Native GUI identity test. Passwords never pass through PowerShell.
function Invoke-LocalIdentity([bool]$Create,[string]$Location) {
 if($Location -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Emplacement local refuse.'}
 foreach($part in $Location.Substring(3).Split('\')){
  if($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'Chemin ambigu.'}
 }
 $vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Fournisseur natif non approuve.'}
 $operation=if($Create){'--gui-create-synthetic-identity-lab'}else{'--gui-open-synthetic-identity-lab'}
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$vault
 $psi.Arguments=('{0} "{1}"' -f $operation,$Location)
 $psi.WorkingDirectory=(Join-Path $root 'bin')
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardOutput=$true
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $p=New-Object Diagnostics.Process;$p.StartInfo=$psi
 try{
  if(-not $p.Start()){throw 'Demarrage natif refuse.'}
  if(-not $p.WaitForExit(240000)){$p.Kill();throw 'Operation interrompue.'}
  if($p.ExitCode -ne 0){throw 'Verification locale refusee.'}
  $raw=$p.StandardOutput.ReadToEnd()
  if($raw.Length -lt 40 -or $raw.Length -gt 1024){throw 'Reponse native invalide.'}
  $r=ConvertFrom-Json -InputObject $raw
  if($r.labOnly -ne $true -or $r.remotelyEnrolled -ne $false -or
     $r.address -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{32}@quantic$'){throw 'Identite non verifiee.'}
  if($Create){
   if($r.status -cne 'synthetic-identity-created-local-only' -or
      $r.dir -cnotmatch ('^'+[Regex]::Escape($Location)+'\\quantic-test-[0-9a-f]{16}$')){throw 'Creation non confirmee.'}
  }elseif($r.status -cne 'synthetic-identity-keys-unlocked-local-only'){throw 'Deverrouillage non confirme.'}
  return $r
 }finally{
  if(-not $p.HasExited){$p.Kill()}
  $p.Dispose()
 }
}

# Trusted synthetic registry and public contact-card operations only.
# Does not create authenticated Quantic contacts, relay configuration or sessions.
function Invoke-SyntheticHelper([string]$Mode,[string]$Location,[string]$InputText=''){
 if($Mode -cnotmatch '^(list|share|stage)$'){throw 'Action refusee.'}
 if($Location -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Dossier local non autorise.'}
 foreach($part in $Location.Substring(3).Split('\')){
  if($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'Chemin ambigu.'}
 }
 $vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Moteur natif non authentifie.'}
 $cmd=switch($Mode){
  'list' {'--gui-list-synthetic-identities-lab'}
  'share' {'--gui-share-synthetic-contact-card-lab'}
  'stage' {'--gui-add-synthetic-contact-candidate-lab'}
 }
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$vault;$psi.Arguments=('{0} "{1}"' -f $cmd,$Location)
 $psi.WorkingDirectory=(Join-Path $root 'bin')
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardOutput=$true
 $psi.RedirectStandardInput=$Mode -ceq 'stage'
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $p=New-Object Diagnostics.Process;$p.StartInfo=$psi
 try{
  if(-not $p.Start()){throw 'Moteur local indisponible.'}
  if($Mode -ceq 'stage'){
   if($InputText -cnotmatch '^QSALPHA1:[A-Za-z0-9_-]{150,4096}$' -or $InputText.Length -gt 4096){throw 'Code de test invalide.'}
   $p.StandardInput.Write($InputText)
   $p.StandardInput.Close()
  }
  if(-not $p.WaitForExit(240000)){$p.Kill();throw 'Operation annulee ou bloquee.'}
  if($p.ExitCode -ne 0){throw 'Code ou autorisation refuse.'}
  $raw=$p.StandardOutput.ReadToEnd()
  if($raw.Length -lt 30 -or $raw.Length -gt 6000){throw 'Retour local non conforme.'}
  $result=ConvertFrom-Json -InputObject $raw
  if($result.labOnly -ne $true){throw 'Resultat non fictif.'}
  switch($Mode){
   'list' {
    if($result.status -cne 'local-synthetic-identities-only' -or $result.identities.Count -gt 32){throw 'Registre invalide.'}
    foreach($item in $result.identities){
     if($item.labOnly -ne $true -or $item.remotelyEnrolled -ne $false -or
        $item.directory -cnotmatch ('^'+[Regex]::Escape($Location)+'\\quantic-test-[0-9a-f]{16}$') -or
        $item.address -cnotmatch '^alpha~[0-9a-f]{32}@quantic$'){throw 'Registre refuse.'}
    }
   }
   'share' {
    if($result.status -cne 'synthetic-card-self-signed-not-authorized' -or
       $result.mailAuthorized -ne $false -or
       $result.fingerprint -cnotmatch '^[0-9a-f]{24}$' -or
       $result.code -cnotmatch '^QSALPHA1:[A-Za-z0-9_-]{150,4096}$'){throw 'Invitation non confirmee.'}
   }
   'stage' {
    if($result.status -cne 'contact-candidate-not-trusted' -or
       $result.independentlyVerified -ne $false -or
       $result.mailAuthorized -ne $false -or
       $result.fingerprint -cnotmatch '^[0-9a-f]{24}$'){throw 'Contact non confirme.'}
   }
  }
  return $result
 }finally{if(-not $p.HasExited){$p.Kill()};$p.Dispose()}
}
function Choose-SyntheticDirectory {
 if($script:latestSyntheticDirectory){return [string]$script:latestSyntheticDirectory}
 $base=[Environment]::GetFolderPath('LocalApplicationData')
 $data=Invoke-SyntheticHelper 'list' $base
 $items=@($data.identities)
 if($items.Count -eq 0){throw 'Aucun coffre de test retrouve. Creer une identite d abord.'}
 if($items.Count -eq 1){return [string]$items[0].directory}
 $selector=New-Object Windows.Forms.Form
 $selector.Text='Choisir mon identite locale'
 $selector.StartPosition='CenterParent'
 $selector.ClientSize=New-Object Drawing.Size(580,175)
 $selector.BackColor=[Drawing.Color]::FromArgb(19,25,35)
 $selector.ForeColor=[Drawing.Color]::WhiteSmoke
 $label=New-Object Windows.Forms.Label
 $label.Text='Choisissez un coffre fictif deja cree sur cet ordinateur.'
 $label.SetBounds(15,14,550,32);$selector.Controls.Add($label)
 $list=New-Object Windows.Forms.ComboBox
 $list.DropDownStyle='DropDownList';$list.SetBounds(15,53,550,29)
 foreach($item in $items){[void]$list.Items.Add([string]$item.address)}
 $list.SelectedIndex=0;$selector.Controls.Add($list)
 $ok=New-Object Windows.Forms.Button;$ok.Text='Continuer'
 $ok.SetBounds(320,108,115,40);$ok.DialogResult=[Windows.Forms.DialogResult]::OK
 $ok.ForeColor=[Drawing.Color]::Black;$selector.Controls.Add($ok)
 $cancel=New-Object Windows.Forms.Button;$cancel.Text='Annuler'
 $cancel.SetBounds(450,108,115,40);$cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel
 $cancel.ForeColor=[Drawing.Color]::Black;$selector.Controls.Add($cancel)
 $selector.AcceptButton=$ok;$selector.CancelButton=$cancel
 try{
  if($selector.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return $null}
  return [string]$items[$list.SelectedIndex].directory
 }finally{$selector.Dispose()}
}
function Show-SyntheticContactGuide {
 $dir=Choose-SyntheticDirectory
 if(-not $dir){return}
 $menu=New-Object Windows.Forms.Form
 $menu.Text='Quantic ID | Inviter un contact fictif'
 $menu.StartPosition='CenterParent'
 $menu.ClientSize=New-Object Drawing.Size(655,272)
 $menu.BackColor=[Drawing.Color]::FromArgb(19,25,35)
 $menu.ForeColor=[Drawing.Color]::WhiteSmoke
 $label=New-Object Windows.Forms.Label
 $label.Text='Une carte auto-signee ne remplace pas une attestation d autorite. Elle sera conservee EN ATTENTE et ne permettra aucun envoi.'
 $label.SetBounds(19,17,615,74);$menu.Controls.Add($label)
 $export=New-Object Windows.Forms.Button;$export.Text='Partager mon code de test'
 $export.SetBounds(19,107,615,44);$export.ForeColor=[Drawing.Color]::Black;$menu.Controls.Add($export)
 $import=New-Object Windows.Forms.Button;$import.Text='Entrer le code recu d un autre PC'
 $import.SetBounds(19,160,615,44);$import.ForeColor=[Drawing.Color]::Black;$menu.Controls.Add($import)
 $close=New-Object Windows.Forms.Button;$close.Text='Fermer'
 $close.SetBounds(475,219,159,38);$close.DialogResult=[Windows.Forms.DialogResult]::Cancel
 $close.ForeColor=[Drawing.Color]::Black;$menu.Controls.Add($close);$menu.CancelButton=$close
 $export.Add_Click({
  $export.Enabled=$false
  try{
   $r=Invoke-SyntheticHelper 'share' $dir
   $view=New-Object Windows.Forms.Form;$view.Text='Mon code de contact (test)'
   $view.StartPosition='CenterParent';$view.ClientSize=New-Object Drawing.Size(670,358)
   $view.BackColor=[Drawing.Color]::FromArgb(19,25,35)
   $view.ForeColor=[Drawing.Color]::WhiteSmoke
   $info=New-Object Windows.Forms.Label
   $info.Text=('Empreinte a comparer avec le destinataire : '+$r.fingerprint)
   $info.SetBounds(18,18,630,40);$view.Controls.Add($info)
   $code=New-Object Windows.Forms.TextBox
   $code.Multiline=$true;$code.ReadOnly=$true;$code.ScrollBars='Vertical'
   $code.SetBounds(18,69,633,195);$code.Text=$r.code;$view.Controls.Add($code)
   $copy=New-Object Windows.Forms.Button;$copy.Text='Copier mon code public'
   $copy.SetBounds(18,282,292,45);$copy.ForeColor=[Drawing.Color]::Black;$view.Controls.Add($copy)
   $copy.Add_Click({[Windows.Forms.Clipboard]::SetText($code.Text)})
   $done=New-Object Windows.Forms.Button;$done.Text='Fermer'
   $done.SetBounds(493,282,158,45);$done.DialogResult=[Windows.Forms.DialogResult]::OK
   $done.ForeColor=[Drawing.Color]::Black;$view.Controls.Add($done)
   try{[void]$view.ShowDialog()}finally{$view.Dispose()}
  }catch{
   [Windows.Forms.MessageBox]::Show('Creation de code refusee : les deux secrets et les fichiers du coffre doivent etre verifies.','Code indisponible','OK','Warning')|Out-Null
  }finally{$export.Enabled=$true}
 })
 $import.Add_Click({
  $entry=New-Object Windows.Forms.Form;$entry.Text='Ajouter un contact de laboratoire'
  $entry.StartPosition='CenterParent';$entry.ClientSize=New-Object Drawing.Size(670,348)
  $entry.BackColor=[Drawing.Color]::FromArgb(19,25,35)
  $entry.ForeColor=[Drawing.Color]::WhiteSmoke
  $help=New-Object Windows.Forms.Label
  $help.Text='Collez le code recu. Une fenetre native exigera une comparaison de l empreinte par un autre canal. Aucune autorisation de messagerie ne sera ajoutee.'
  $help.SetBounds(18,18,633,70);$entry.Controls.Add($help)
  $code=New-Object Windows.Forms.TextBox
  $code.Multiline=$true;$code.ScrollBars='Vertical';$code.MaxLength=4096
  $code.SetBounds(18,92,633,167);$entry.Controls.Add($code)
  $add=New-Object Windows.Forms.Button;$add.Text='Verifier et conserver en attente'
  $add.SetBounds(18,278,350,44);$add.ForeColor=[Drawing.Color]::Black;$entry.Controls.Add($add)
  $cancel=New-Object Windows.Forms.Button;$cancel.Text='Annuler'
  $cancel.SetBounds(492,278,159,44);$cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel
  $cancel.ForeColor=[Drawing.Color]::Black;$entry.Controls.Add($cancel)
  $add.Add_Click({
   $add.Enabled=$false
   try{
    $r=Invoke-SyntheticHelper 'stage' $dir $code.Text.Trim()
    [Windows.Forms.MessageBox]::Show(('Contact fictif conserve EN ATTENTE : '+$r.address+[Environment]::NewLine+'Empreinte : '+$r.fingerprint+[Environment]::NewLine+'Aucune inscription distante, aucun droit d envoi.'),'Code verifie localement','OK','Information')|Out-Null
    $entry.DialogResult=[Windows.Forms.DialogResult]::OK
   }catch{
    [Windows.Forms.MessageBox]::Show('Code, signature, date, empreinte ou consentement refuse. Aucun contact autorise.','Invitation refusee','OK','Warning')|Out-Null
   }finally{$add.Enabled=$true}
  })
  try{[void]$entry.ShowDialog()}finally{$entry.Dispose()}
 })
 try{[void]$menu.ShowDialog()}finally{$menu.Dispose()}
}

# Only a public signed enrollment request leaves the native process.
function Show-PrepareEnrollment {
 $dlg=New-Object Windows.Forms.Form
 $dlg.Text='Quantic ID | Preparer une inscription de test'
 $dlg.StartPosition='CenterParent';$dlg.ClientSize=New-Object Drawing.Size(680,410)
 $dlg.BackColor=[Drawing.Color]::FromArgb(19,25,35);$dlg.ForeColor=[Drawing.Color]::WhiteSmoke
 $info=New-Object Windows.Forms.Label
 $info.Text='Nouvelle identite de laboratoire. Utilisez une empreinte de quorum fournie et verifiee par un operateur independant. Trois secrets distincts seront demandes dans les fenetres natives. Aucun compte distant ne sera cree.'
 $info.SetBounds(20,16,640,105);$dlg.Controls.Add($info)
 $hLabel=New-Object Windows.Forms.Label;$hLabel.Text='Identifiant de test (lettres minuscules, chiffres, . _ -)'
 $hLabel.SetBounds(20,128,640,25);$dlg.Controls.Add($hLabel)
 $handle=New-Object Windows.Forms.TextBox;$handle.SetBounds(20,156,640,30);$handle.MaxLength=32;$dlg.Controls.Add($handle)
 $pLabel=New-Object Windows.Forms.Label;$pLabel.Text='Empreinte SHA-256 du quorum approuve (64 caracteres)'
 $pLabel.SetBounds(20,200,640,25);$dlg.Controls.Add($pLabel)
 $pin=New-Object Windows.Forms.TextBox;$pin.SetBounds(20,228,640,30);$pin.MaxLength=64;$dlg.Controls.Add($pin)
 $confirm=New-Object Windows.Forms.CheckBox
 $confirm.Text='Je confirme avoir obtenu et compare cette empreinte par un canal independant.'
 $confirm.SetBounds(20,271,640,44);$dlg.Controls.Add($confirm)
 $start=New-Object Windows.Forms.Button;$start.Text='Creer et signer ma candidature'
 $start.SetBounds(20,335,370,50);$start.ForeColor=[Drawing.Color]::Black;$dlg.Controls.Add($start)
 $cancel=New-Object Windows.Forms.Button;$cancel.Text='Annuler';$cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel
 $cancel.SetBounds(495,335,165,50);$cancel.ForeColor=[Drawing.Color]::Black;$dlg.Controls.Add($cancel);$dlg.CancelButton=$cancel
 $start.Add_Click({
  if(-not $confirm.Checked -or $handle.Text -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}$' -or $pin.Text -cnotmatch '^[a-f0-9]{64}$'){
   [Windows.Forms.MessageBox]::Show('Identifiant et empreinte independante valides requis.','Informations manquantes','OK','Warning')|Out-Null
   return
  }
  $start.Enabled=$false
  try{
   $parent=[Environment]::GetFolderPath('LocalApplicationData')
   if($parent -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Chemin local refuse.'}
   $vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
   if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Moteur non approuve.'}
   $psi=New-Object Diagnostics.ProcessStartInfo
   $psi.FileName=$vault;$psi.Arguments=('--gui-prepare-enrollment-claim-lab "{0}" {1} {2}' -f $parent,$handle.Text,$pin.Text)
   $psi.WorkingDirectory=(Join-Path $root 'bin');$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
   $psi.RedirectStandardOutput=$true;$psi.EnvironmentVariables.Clear()
   $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot;$psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
   $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
   $proc=New-Object Diagnostics.Process;$proc.StartInfo=$psi;$started=$false
   try{
    $started=$proc.Start()
    if(-not $started){throw 'Demarrage refuse.'}
    $reading=$proc.StandardOutput.ReadToEndAsync()
    if(-not $proc.WaitForExit(300000)){throw 'Operation expiree.'}
    if($proc.ExitCode -ne 0){throw 'Creation refusee.'}
    $raw=$reading.GetAwaiter().GetResult()
    if($raw.Length -lt 30 -or $raw.Length -gt 60000){throw 'Reponse invalide.'}
    $r=ConvertFrom-Json -InputObject $raw
    if($r.status -cne 'signed-claim-not-enrolled' -or $r.labOnly -ne $true -or $r.remotelyEnrolled -ne $false -or $r.code -cnotmatch '^QSENROLL1:[A-Za-z0-9_-]+$'){throw 'Candidature non confirmee.'}
    if($r.directory -cnotmatch ('^'+[Regex]::Escape($parent)+'\\quantic-enroll-[0-9a-f]{16}$')){throw 'Dossier non confirme.'}
   }finally{if($started -and -not $proc.HasExited){$proc.Kill()};$proc.Dispose()}
   $result=New-Object Windows.Forms.Form;$result.Text='Candidature publique signee - en attente'
   $result.StartPosition='CenterParent';$result.ClientSize=New-Object Drawing.Size(680,380)
   $notice=New-Object Windows.Forms.Label
   $notice.Text=('Identite '+$r.address+[Environment]::NewLine+'Copier ce dossier PUBLIC pour l operateur de laboratoire. Aucun compte actif ni droit de messagerie.')
   $notice.SetBounds(20,15,640,76);$result.Controls.Add($notice)
   $claim=New-Object Windows.Forms.TextBox;$claim.Multiline=$true;$claim.ReadOnly=$true;$claim.ScrollBars='Vertical'
   $claim.SetBounds(20,100,640,200);$claim.Text=$r.code;$result.Controls.Add($claim)
   $copy=New-Object Windows.Forms.Button;$copy.Text='Copier ma candidature publique';$copy.SetBounds(20,320,360,45);$result.Controls.Add($copy)
   $copy.Add_Click({[Windows.Forms.Clipboard]::SetText($claim.Text)})
   $done=New-Object Windows.Forms.Button;$done.Text='Fermer';$done.SetBounds(500,320,160,45);$done.DialogResult=[Windows.Forms.DialogResult]::OK;$result.Controls.Add($done)
   try{[void]$result.ShowDialog()}finally{$result.Dispose()}
   $dlg.DialogResult=[Windows.Forms.DialogResult]::OK
  }catch{
   [Windows.Forms.MessageBox]::Show('Candidature non confirmee. Aucun compte active. Un nouveau dossier partiel peut subsister ; ne pas le reutiliser.','Creation refusee','OK','Warning')|Out-Null
  }finally{$start.Enabled=$true}
 })
 try{[void]$dlg.ShowDialog()}finally{$dlg.Dispose()}
}

# Only signed public challenges and responses pass through this UI.
function Invoke-EnrollmentNative([string]$Mode,[string]$Path,[string]$Pin='', [string]$Code='') {
 if($Path -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Chemin local refuse.'}
 $vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Moteur non approuve.'}
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$vault;$psi.WorkingDirectory=(Join-Path $root 'bin')
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardOutput=$true;$psi.RedirectStandardInput=$true
 if($Mode -ceq 'list'){
  $psi.Arguments=('--gui-list-enrollment-candidates-lab "{0}"' -f $Path)
 }elseif($Mode -ceq 'answer' -and $Pin -cmatch '^[a-f0-9]{64}$' -and $Code -cmatch '^QSPROOF1:[A-Za-z0-9_-]{1,15991}$'){
  $psi.Arguments=('--gui-answer-enrollment-possession-lab "{0}" {1}' -f $Path,$Pin)
 }elseif($Mode -ceq 'credential' -and $Pin -cmatch '^[a-f0-9]{64}$' -and $Code -cmatch '^QSAPPROVAL1:[A-Za-z0-9_-]{1,19988}$'){
  $psi.Arguments=('--gui-prepare-mailbox-credential-lab "{0}" {1}' -f $Path,$Pin)
 }elseif($Mode -ceq 'activation' -and $Pin -cmatch '^[a-f0-9]{64}$' -and $Code -cmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){
  $psi.Arguments=('--gui-import-mailbox-activation-lab "{0}" "{1}" {2} {3}' -f $Path,$Code,$Pin,$TrustedBinarySha256.ToLowerInvariant())
 }else{throw 'Action non autorisee.'}
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot;$psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $proc=New-Object Diagnostics.Process;$proc.StartInfo=$psi;$started=$false
 try{
  $started=$proc.Start();if(-not $started){throw 'Moteur indisponible.'}
  $reading=$proc.StandardOutput.ReadToEndAsync()
  if($Mode -in @('answer','credential')){$proc.StandardInput.Write($Code)}
  $proc.StandardInput.Close()
  $timeout=if($Mode -ceq 'list'){15000}else{300000}
  if(-not $proc.WaitForExit($timeout)){throw 'Operation expiree.'}
  if($proc.ExitCode -ne 0){throw 'Operation refusee.'}
  $raw=$reading.GetAwaiter().GetResult()
  if($raw.Length -lt 20 -or $raw.Length -gt 50000){throw 'Reponse native invalide.'}
  return (ConvertFrom-Json -InputObject $raw)
 }finally{if($started -and -not $proc.HasExited){$proc.Kill()};$proc.Dispose()}
}
$script:configuredEnrollment=$null
$script:managedCarrier=$null
$script:managedAttempted=$false
function Stop-ManagedCarrier {
 if($script:managedCarrier){
  $p=$script:managedCarrier;$script:managedCarrier=$null
  try{$p.StandardInput.Close();if(-not $p.WaitForExit(5000)){$p.Kill()}}catch{}finally{$p.Dispose()}
 }
}
function Start-ManagedCarrier {
 if($script:managedAttempted){return}
 $script:managedAttempted=$true
 $parent=[Environment]::GetFolderPath('LocalApplicationData')
 if($parent -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){return}
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=Join-Path $root 'runtime\node.exe'
 $psi.Arguments=('"{0}" "{1}" {2} "{3}" {4}' -f (Join-Path $root 'scripts\start-native-managed-scattering.mjs'),(Join-Path $root 'bin\Vault-PQ-lab.exe'),$TrustedBinarySha256.ToLowerInvariant(),$parent,$ExpectedManifestSha256.ToLowerInvariant())
 $psi.WorkingDirectory=$root;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true
 $psi.EnvironmentVariables.Clear();$psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot;$psi.EnvironmentVariables['WINDIR']=$env:SystemRoot;$psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $p=New-Object Diagnostics.Process;$p.StartInfo=$psi
 try{
  if(-not $p.Start()){throw 'Transport indisponible'}
  $read=$p.StandardOutput.ReadLineAsync()
  if(-not $read.Wait(20000)){throw 'Transport indisponible'}
  $line=$read.Result;if(-not $line -or $line.Length -gt 1024){throw 'Transport indisponible'}
  $r=ConvertFrom-Json $line
  if($r.status -ceq 'local-carrier-ready-not-remote-verified' -and $r.directory -cmatch ('^'+[Regex]::Escape($parent)+'\\quantic-enroll-[0-9a-f]{16}$') -and -not $p.HasExited){
   $script:configuredEnrollment=[string]$r.directory;$script:managedCarrier=$p;$p=$null
   $notice.Text='Scattering local demarre | correspondant distant non verifie.'
  }elseif($r.status -ceq 'hybrid-session-required' -and $r.directory -cmatch ('^'+[Regex]::Escape($parent)+'\\quantic-enroll-[0-9a-f]{16}$')){
   $script:configuredEnrollment=[string]$r.directory
   $notice.Text='Profil hybride importe | ouvrir Quantic Mail pour demarrer la session commune.'
  }elseif($r.status -ceq 'not-configured'){$script:managedAttempted=$false}
  else{$notice.Text='Transport non disponible | aucune relance automatique.'}
 }catch{$notice.Text='Transport non disponible | aucune relance automatique.'}
 finally{if($p){try{$p.StandardInput.Close();if(-not $p.WaitForExit(5000)){$p.Kill()}}catch{};$p.Dispose()}}
}

function Show-MailboxActivation {
 $parent=[Environment]::GetFolderPath('LocalApplicationData')
 $data=Invoke-EnrollmentNative 'list' $parent
 if($data.status -cne 'pending-enrollment-candidates-only' -or $data.candidates.Count -gt 32){throw 'Registre non valide.'}
 $items=@($data.candidates)
 if($items.Count -eq 0){[Windows.Forms.MessageBox]::Show('Preparez votre identite de test.','Aucune candidature','OK','Information')|Out-Null;return}
 foreach($item in $items){
  if($item.directory -cnotmatch ('^'+[Regex]::Escape($parent)+'\\quantic-enroll-[0-9a-f]{16}$') -or $item.address -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{32}@quantic$'){throw 'Identite locale invalide.'}
 }
 $dlg=New-Object Windows.Forms.Form;$dlg.Text='Quantic Mail | Configurer ma messagerie de test';$dlg.StartPosition='CenterParent'
 $dlg.ClientSize=New-Object Drawing.Size(700,410);$dlg.BackColor=[Drawing.Color]::FromArgb(19,25,35);$dlg.ForeColor=[Drawing.Color]::WhiteSmoke
 $help=New-Object Windows.Forms.Label;$help.Text='Selectionnez votre identite et le dossier prive fourni par votre operateur. Comparez son empreinte par un canal independant. Aucune activation distante automatique.'
 $help.SetBounds(20,15,660,65);$dlg.Controls.Add($help)
 $choose=New-Object Windows.Forms.ComboBox;$choose.DropDownStyle='DropDownList';$choose.SetBounds(20,90,660,30)
 foreach($item in $items){[void]$choose.Items.Add([string]$item.address)};$choose.SelectedIndex=0;$dlg.Controls.Add($choose)
 $selected=New-Object Windows.Forms.TextBox;$selected.ReadOnly=$true;$selected.SetBounds(20,145,470,30);$dlg.Controls.Add($selected)
 $browse=New-Object Windows.Forms.Button;$browse.Text='Choisir le dossier';$browse.ForeColor=[Drawing.Color]::Black;$browse.SetBounds(505,142,175,35);$dlg.Controls.Add($browse)
 $browse.Add_Click({
  $p=New-Object Windows.Forms.OpenFileDialog;$p.Filter='Configuration Quantic (*.json)|*.json';$p.CheckFileExists=$true;$p.Multiselect=$false
  try{if($p.ShowDialog() -eq [Windows.Forms.DialogResult]::OK){$selected.Text=$p.FileName}}finally{$p.Dispose()}
 })
 $label=New-Object Windows.Forms.Label;$label.Text='Empreinte SHA-256 du dossier authentifie';$label.SetBounds(20,195,660,25);$dlg.Controls.Add($label)
 $pin=New-Object Windows.Forms.TextBox;$pin.MaxLength=64;$pin.SetBounds(20,225,660,30);$dlg.Controls.Add($pin)
 $confirmed=New-Object Windows.Forms.CheckBox;$confirmed.Text='Empreinte comparee independamment et dossier prive.';$confirmed.SetBounds(20,270,660,35);$dlg.Controls.Add($confirmed)
 $apply=New-Object Windows.Forms.Button;$apply.Text='Configurer ma messagerie';$apply.ForeColor=[Drawing.Color]::Black;$apply.SetBounds(20,330,330,45);$dlg.Controls.Add($apply)
 $cancel=New-Object Windows.Forms.Button;$cancel.Text='Annuler';$cancel.ForeColor=[Drawing.Color]::Black;$cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel;$cancel.SetBounds(500,330,180,45);$dlg.Controls.Add($cancel);$dlg.CancelButton=$cancel
 $apply.Add_Click({
  if(-not $confirmed.Checked -or $pin.Text -cnotmatch '^[a-f0-9]{64}$' -or [string]::IsNullOrWhiteSpace($selected.Text)){[Windows.Forms.MessageBox]::Show('Dossier prive et empreinte independante requis.','Validation requise','OK','Warning')|Out-Null;return}
  $apply.Enabled=$false
  try{
   $item=$items[$choose.SelectedIndex]
   $r=Invoke-EnrollmentNative 'activation' ([string]$item.directory) $pin.Text $selected.Text
   if($r.status -cne 'native-mailbox-configured-pending-live-verification' -or $r.mailAuthorized -ne $false -or $r.address -cne $item.address){throw 'Import non confirme.'}
   $script:configuredEnrollment=[string]$item.directory
   [Windows.Forms.MessageBox]::Show('Configuration locale importee. Les autorites et le transport seront verifies lors des operations de messagerie. Aucun compte distant confirme.','Configuration importee','OK','Information')|Out-Null
   $dlg.DialogResult=[Windows.Forms.DialogResult]::OK
  }catch{[Windows.Forms.MessageBox]::Show('Import refuse : dossier prive NTFS, empreinte, votes valides et jeton correspondant requis. Aucun fichier existant ne sera remplace.','Configuration non confirmee','OK','Warning')|Out-Null}
  finally{$apply.Enabled=$true}
 })
 try{[void]$dlg.ShowDialog()}finally{$dlg.Dispose()}
}

function Show-EnrollmentPossession([bool]$Credential=$false) {
 $parent=[Environment]::GetFolderPath('LocalApplicationData')
 $data=Invoke-EnrollmentNative 'list' $parent
 if($data.status -cne 'pending-enrollment-candidates-only' -or $data.candidates.Count -gt 32){throw 'Registre non valide.'}
 $items=@($data.candidates)
 if($items.Count -eq 0){[Windows.Forms.MessageBox]::Show('Preparez d abord une candidature dans Quantic ID.','Aucune candidature','OK','Information')|Out-Null;return}
 foreach($item in $items){
  if($item.directory -cnotmatch ('^'+[Regex]::Escape($parent)+'\\quantic-enroll-[0-9a-f]{16}$') -or $item.address -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{32}@quantic$'){throw 'Identite locale invalide.'}
 }
 $dlg=New-Object Windows.Forms.Form
 $dlg.Text='Quantic ID | Prouver mon identite de test';$dlg.StartPosition='CenterParent'
 $dlg.ClientSize=New-Object Drawing.Size(730,550);$dlg.BackColor=[Drawing.Color]::FromArgb(19,25,35);$dlg.ForeColor=[Drawing.Color]::WhiteSmoke
 $help=New-Object Windows.Forms.Label;$help.Text='Choisissez votre candidature. Collez le defi fourni par un operateur independant et verifiez son empreinte par un autre canal. Aucune cle privee ni autorisation de messagerie ne sera transmise.'
 $help.SetBounds(20,15,690,73);$dlg.Controls.Add($help)
 $choose=New-Object Windows.Forms.ComboBox;$choose.DropDownStyle='DropDownList';$choose.SetBounds(20,92,690,32)
 foreach($item in $items){[void]$choose.Items.Add([string]$item.address)};$choose.SelectedIndex=0;$dlg.Controls.Add($choose)
 $label=New-Object Windows.Forms.Label;$label.Text='Empreinte SHA-256 de la cle de signature de l operateur (pas celle du quorum).';$label.SetBounds(20,143,690,30);$dlg.Controls.Add($label)
 $pin=New-Object Windows.Forms.TextBox;$pin.SetBounds(20,177,690,30);$pin.MaxLength=64;$dlg.Controls.Add($pin)
 $code=New-Object Windows.Forms.TextBox;$code.Multiline=$true;$code.ScrollBars='Vertical';$code.MaxLength=16000;$code.SetBounds(20,225,690,166);$dlg.Controls.Add($code)
 $confirmed=New-Object Windows.Forms.CheckBox;$confirmed.Text='J ai compare l empreinte de cet operateur par un canal independant.';$confirmed.SetBounds(20,408,690,40);$dlg.Controls.Add($confirmed)
 $send=New-Object Windows.Forms.Button;$send.Text='Produire ma preuve signee';$send.SetBounds(20,477,330,48);$send.ForeColor=[Drawing.Color]::Black;$dlg.Controls.Add($send)
 $cancel=New-Object Windows.Forms.Button;$cancel.Text='Annuler';$cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel;$cancel.SetBounds(550,477,160,48);$cancel.ForeColor=[Drawing.Color]::Black;$dlg.Controls.Add($cancel);$dlg.CancelButton=$cancel
 if($Credential){
  $dlg.Text='Quantic Mail | Preparer mon acces de test'
  $help.Text='Collez le dossier QSAPPROVAL1 de trois votes et de quatre cles publiques. Comparez l empreinte de la liste par un canal independant. Le jeton reste chiffre sur ce PC.'
  $label.Text='Empreinte SHA-256 de la liste des quatre autorites.'
  $code.MaxLength=20000
  $confirmed.Text='J ai compare l empreinte de cette liste par un canal independant.'
  $send.Text='Proteger mon jeton local'
 }
 $send.Add_Click({
  if(-not $confirmed.Checked -or $pin.Text -cnotmatch '^[a-f0-9]{64}$' -or $code.Text.Trim() -cnotmatch $(if($Credential){'^QSAPPROVAL1:[A-Za-z0-9_-]+$'}else{'^QSPROOF1:[A-Za-z0-9_-]+$'})){[Windows.Forms.MessageBox]::Show('Defi et empreinte independante requis.','Validation requise','OK','Warning')|Out-Null;return}
  $send.Enabled=$false
  try{
   $mode=if($Credential){'credential'}else{'answer'}
   $r=Invoke-EnrollmentNative $mode ([string]$items[$choose.SelectedIndex].directory) $pin.Text $code.Text.Trim()
   $status=if($Credential){'mailbox-credential-sealed-not-activated'}else{'device-proof-only-not-enrolled'}
   $pattern=if($Credential){'^QSCRED1:[A-Za-z0-9_-]+$'}else{'^QSPROOFREPLY1:[A-Za-z0-9_-]+$'}
   if($r.status -cne $status -or $r.mailAuthorized -ne $false -or $r.code -cnotmatch $pattern){throw 'Preuve non confirmee.'}
   $view=New-Object Windows.Forms.Form;$view.Text='Preuve signee - candidature en attente';$view.ClientSize=New-Object Drawing.Size(680,340);$view.StartPosition='CenterParent'
   $notice=New-Object Windows.Forms.Label;$notice.Text='Renvoyez cette preuve a l operateur qui a emis le defi. Il reste a obtenir l approbation independante. Aucun compte active.'
   if($Credential){if($r.transportCode -cnotmatch '^QSTLS1:[A-Za-z0-9_-]+$'){throw 'Demandes de certificats invalides.'};$notice.Text='Jeton et deux cles de transport crees localement. Transmettez les deux codes publics a l operateur. Aucune cle privee ne sort du PC.'}
   $notice.SetBounds(20,15,640,65);$view.Controls.Add($notice)
   $reply=New-Object Windows.Forms.TextBox;$reply.Multiline=$true;$reply.ReadOnly=$true;$reply.ScrollBars='Vertical';$reply.Text=if($Credential){$r.code+[Environment]::NewLine+$r.transportCode}else{$r.code};$reply.SetBounds(20,82,640,180);$view.Controls.Add($reply)
   $copy=New-Object Windows.Forms.Button;$copy.Text='Copier ma preuve';$copy.SetBounds(20,280,300,42);$view.Controls.Add($copy);$copy.Add_Click({[Windows.Forms.Clipboard]::SetText($reply.Text)})
   $close=New-Object Windows.Forms.Button;$close.Text='Fermer';$close.DialogResult=[Windows.Forms.DialogResult]::OK;$close.SetBounds(500,280,160,42);$view.Controls.Add($close)
   try{[void]$view.ShowDialog()}finally{$view.Dispose()}
   $dlg.DialogResult=[Windows.Forms.DialogResult]::OK
  }catch{[Windows.Forms.MessageBox]::Show('Defi, signature, empreinte, expiration ou secret refuse. Aucun compte actif.','Preuve refusee','OK','Warning')|Out-Null}
  finally{$send.Enabled=$true}
 })
 try{[void]$dlg.ShowDialog()}finally{$dlg.Dispose()}
}

$form=New-Object Windows.Forms.Form
$form.Text="Quantic Sillage | Alpha privee"
$form.StartPosition="CenterScreen"
$form.ClientSize=New-Object Drawing.Size(760,870)
$form.MinimumSize=New-Object Drawing.Size(776,910)
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
$quit.SetBounds(556,812,180,42);$form.Controls.Add($quit)
$quit.DialogResult=[Windows.Forms.DialogResult]::Cancel;$form.CancelButton=$quit
$form.AcceptButton=$run
$createIdentity=New-Object Windows.Forms.Button
$createIdentity.Text='Creer mon identite de test'
$createIdentity.SetBounds(24,591,712,43)
$createIdentity.ForeColor=[Drawing.Color]::Black
$createIdentity.BackColor=[Drawing.Color]::FromArgb(192,212,200)
$form.Controls.Add($createIdentity)
$openIdentity=New-Object Windows.Forms.Button
$openIdentity.Text='Ouvrir mon coffre de test'
$openIdentity.SetBounds(24,645,712,43)
$openIdentity.ForeColor=[Drawing.Color]::Black
$form.Controls.Add($openIdentity)
$contactGuide=New-Object Windows.Forms.Button
$contactGuide.Text='Inviter un contact de test (en attente)'
$contactGuide.SetBounds(24,698,712,43)
$contactGuide.ForeColor=[Drawing.Color]::Black
$form.Controls.Add($contactGuide)
$script:desktopContactAction={
 $contactGuide.Enabled=$false
 try{Show-SyntheticContactGuide}catch{
  [Windows.Forms.MessageBox]::Show('Carnet de laboratoire indisponible. Creer ou ouvrir d abord un coffre de test.','Contact non configure','OK','Warning')|Out-Null
 }finally{$contactGuide.Enabled=$true}
}
$contactGuide.Add_Click($script:desktopContactAction)
$contactNotice=New-Object Windows.Forms.Label
$contactNotice.Text='Les invitations ne sont pas des contacts approuves par les autorites.'
$contactNotice.SetBounds(24,750,700,30)
$form.Controls.Add($contactNotice)
$script:latestSyntheticDirectory=$null
$script:desktopCreateAction={
 $createIdentity.Enabled=$false
 try{
  $parent=[Environment]::GetFolderPath('LocalApplicationData')
  $r=Invoke-LocalIdentity $true $parent
  $script:latestSyntheticDirectory=$r.dir
  [Windows.Forms.MessageBox]::Show(('Coffre prive cree : '+$r.address+[Environment]::NewLine+'Cliquez sur Ouvrir mon coffre pour tester les deux secrets.'+[Environment]::NewLine+'Aucune inscription distante ou contact cree.'),'Identite fictive creee','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Creation non confirmee. Un dossier partiel peut subsister : aucune suppression ou reutilisation automatique. Disque NTFS et chemin Windows compatible requis.','Creation refusee','OK','Warning')|Out-Null
 }finally{$createIdentity.Enabled=$true}
}
$createIdentity.Add_Click($script:desktopCreateAction)
$script:desktopOpenAction={
 $openIdentity.Enabled=$false
 try{
  $folder=Choose-SyntheticDirectory
  if(-not $folder){return}
  $r=Invoke-LocalIdentity $false $folder
  [Windows.Forms.MessageBox]::Show(('Cles classiques et post-quantiques deverrouillees localement : '+$r.address+[Environment]::NewLine+'Aucune session distante : contacts, autorites et relais restent a configurer pour la messagerie.'),'Coffre de test verifie','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Deverrouillage refuse : secrets ou fichiers non verifies. Aucune session ni message envoye.','Coffre verrouille','OK','Warning')|Out-Null
 }finally{$openIdentity.Enabled=$true}
}
$openIdentity.Add_Click($script:desktopOpenAction)
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
 $run.Text=if($a.Id -eq 'ComposeDraft'){"Rediger mon message"}elseif($a.Id -eq 'PrepareEnrollment'){"Preparer mon inscription de test"}elseif($a.Id -eq 'AnswerEnrollment'){"Prouver mon identite de test"}elseif($a.Id -eq 'PrepareMailboxCredential'){"Preparer ma messagerie de test"}elseif($a.Id -eq 'ImportMailboxActivation'){"Configurer ma messagerie de test"}else{"Ouvrir le laboratoire technique"}
 $simple=$a.Id -in @('ComposeDraft','PrepareEnrollment','AnswerEnrollment','PrepareMailboxCredential','ImportMailboxActivation')
 foreach($control in @($directory,$il,$inputName,$ol,$outputName)){$control.Visible=-not $simple}
 $directory.Enabled=[bool]$a.Scope
 $inputName.Enabled=[bool]$a.Input
 $outputName.Enabled=[bool]$a.Output
 $il.Text=if($a.Input){"Fichier prive ("+$a.Input+"-nom.json)"}else{"Aucun fichier requis"}
 $ol.Text=if($a.Output){"Nouvelle enveloppe (wire-nom.json)"}else{"Aucune sortie a saisir"}
})
$script:desktopRunAction={
 try{
  $a=$script:shownActions[$choice.SelectedIndex]
  if($a.Id -eq 'ImportMailboxActivation'){
   Show-MailboxActivation
   if($script:configuredEnrollment -and -not $script:managedCarrier){Start-ManagedCarrier}
   return
  }
  if($a.Id -eq 'PrepareMailboxCredential'){
   Show-EnrollmentPossession $true
   return
  }
  if($a.Id -eq 'AnswerEnrollment'){
   Show-EnrollmentPossession
   return
  }
  if($a.Id -eq 'PrepareEnrollment'){
   Show-PrepareEnrollment
   return
  }
  if($a.Id -eq 'ComposeDraft'){
   & (Join-Path $root 'Quantic-Sillage-Compose.ps1') -ExpectedManifestSha256 $ExpectedManifestSha256 -TrustedBinarySha256 $TrustedBinarySha256 -EnrollmentDirectory $script:configuredEnrollment
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
}
$run.Add_Click($script:desktopRunAction)

# Unified Windows desktop: no browser, no synthetic balances, no security
# claims from unverified metadata. Existing native actions remain unchanged.
$script:desktopColors=@{
 Canvas=[Drawing.Color]::FromArgb(243,246,251)
 White=[Drawing.Color]::White
 Ink=[Drawing.Color]::FromArgb(17,33,55)
 Muted=[Drawing.Color]::FromArgb(87,105,126)
 Navy=[Drawing.Color]::FromArgb(13,35,60)
 Blue=[Drawing.Color]::FromArgb(8,84,179)
 Border=[Drawing.Color]::FromArgb(222,230,239)
}
function Desktop-Label($parent,[string]$text,[int]$x,[int]$y,[int]$w,[int]$h,[float]$size=10,[bool]$bold=$false){
 $c=New-Object Windows.Forms.Label
 $c.Text=$text;$c.ForeColor=$script:desktopColors.Ink
 $style=if($bold){[Drawing.FontStyle]::Bold}else{[Drawing.FontStyle]::Regular}
 $c.Font=New-Object Drawing.Font('Segoe UI',([float]($size*1.3333)),$style,[Drawing.GraphicsUnit]::Pixel)
 $c.UseCompatibleTextRendering=$false
 $c.SetBounds($x,$y,$w,$h);$parent.Controls.Add($c);return $c
}
function Desktop-Button($parent,[string]$text,[string]$tag,[int]$x,[int]$y,[int]$w,[int]$h,[bool]$primary=$false){
 $c=New-Object Windows.Forms.Button
 $c.Text=$text;$c.Tag=$tag;$c.FlatStyle='Flat';$c.FlatAppearance.BorderSize=1
 $c.FlatAppearance.BorderColor=$script:desktopColors.Border
 $c.BackColor=if($primary){$script:desktopColors.Blue}else{$script:desktopColors.White}
 $c.ForeColor=if($primary){[Drawing.Color]::White}else{$script:desktopColors.Ink}
 $c.Font=New-Object Drawing.Font('Segoe UI',13,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
 $c.UseVisualStyleBackColor=$false
 $c.FlatAppearance.MouseOverBackColor=if($primary){[Drawing.Color]::FromArgb(9,83,164)}else{[Drawing.Color]::FromArgb(238,244,251)}
 $c.FlatAppearance.MouseDownBackColor=[Drawing.Color]::FromArgb(215,231,249)
 $c.SetBounds($x,$y,$w,$h);$c.Cursor=[Windows.Forms.Cursors]::Hand
 $c.Add_Click({param($sender,$e) Invoke-DesktopAction ([string]$sender.Tag)})
 $parent.Controls.Add($c);return $c
}
function Desktop-Card($parent,[string]$title,[string]$description,[string]$button,[string]$tag,[int]$x,[int]$y,[int]$w=396,[int]$h=172){
 $c=New-Object Windows.Forms.Panel
 $c.BackColor=$script:desktopColors.White;$c.BorderStyle='None';Set-DesktopRoundedCard $c
 $c.SetBounds($x,$y,$w,$h)
 $parent.Controls.Add($c)
 $null=Desktop-Label $c $title 20 17 ($w-40) 31 15 $true
 $d=Desktop-Label $c $description 20 55 ($w-40) 56 10
 $d.ForeColor=$script:desktopColors.Muted
 if($button){$action=Desktop-Button $c ($button+'  '+[char]0x2192) $tag 20 ($h-48) ($w-40) 32 $false;$action.FlatAppearance.BorderSize=0;$action.ForeColor=$script:desktopColors.Blue;$action.TextAlign='MiddleLeft';$action.BackColor=$script:desktopColors.White}
 return $c
}
# Native card surfaces: thin border, rounded corners, real controls.
function Set-DesktopRoundedCard($panel){
 $panel.Add_SizeChanged({
  param($sender,$e)
  if($sender.Width -lt 24 -or $sender.Height -lt 24){return}
  $path=New-Object Drawing.Drawing2D.GraphicsPath
  try{
   $w=$sender.Width;$h=$sender.Height;$d=16
   $path.AddArc(0,0,$d,$d,180,90);$path.AddArc($w-$d,0,$d,$d,270,90)
   $path.AddArc($w-$d,$h-$d,$d,$d,0,90);$path.AddArc(0,$h-$d,$d,$d,90,90);$path.CloseFigure()
   $old=$sender.Region;$sender.Region=New-Object Drawing.Region($path);if($old){$old.Dispose()}
  }finally{$path.Dispose()}
 })
 $panel.Add_Paint({
  param($sender,$e)
  $w=$sender.Width-1;$h=$sender.Height-1
  if($w -lt 20 -or $h -lt 20){return}
  $e.Graphics.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $path=New-Object Drawing.Drawing2D.GraphicsPath;$pen=New-Object Drawing.Pen($script:desktopColors.Border)
  try{
   $d=16;$path.AddArc(0,0,$d,$d,180,90);$path.AddArc($w-$d,0,$d,$d,270,90)
   $path.AddArc($w-$d,$h-$d,$d,$d,0,90);$path.AddArc(0,$h-$d,$d,$d,90,90);$path.CloseFigure()
   $e.Graphics.DrawPath($pen,$path)
  }finally{$path.Dispose();$pen.Dispose()}
 })
}
function Desktop-HomeCard($parent,[string]$title,[string]$description,[string]$button,[string]$tag,[int]$glyph,[int]$x,[int]$y){
 $panel=New-Object Windows.Forms.Panel
 $panel.BackColor=[Drawing.Color]::FromArgb(248,250,253);Set-DesktopRoundedCard $panel
 $panel.SetBounds($x,$y,260,140);$parent.Controls.Add($panel)
 $icon=Desktop-Label $panel ([string][char]$glyph) 18 13 36 35 17
 $icon.Font=New-Object Drawing.Font('Segoe MDL2 Assets',23,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
 $icon.TextAlign='MiddleCenter';$icon.BackColor=$panel.BackColor;$icon.ForeColor=$script:desktopColors.Blue
 $null=Desktop-Label $panel $title 18 55 224 26 14 $true
 $desc=Desktop-Label $panel $description 18 80 224 30 9.5
 $desc.ForeColor=$script:desktopColors.Muted
 $action=Desktop-Button $panel ($button+'  '+[char]0x2192) $tag 12 110 236 24 $false
 $action.TextAlign='MiddleLeft';$action.ForeColor=$script:desktopColors.Blue;$action.FlatAppearance.BorderSize=0;$action.BackColor=$panel.BackColor
}
function Invoke-DesktopNativeAction([string]$id){
 $match=@($actions|Where-Object {$_.Id -ceq $id})
 if($match.Count -ne 1){throw 'Action locale indisponible'}
 $module.SelectedItem=Get-AlphaModule $id
 for($i=0;$i -lt $script:shownActions.Count;$i++){
  if($script:shownActions[$i].Id -ceq $id){$choice.SelectedIndex=$i;& $script:desktopRunAction;return}
 }
 throw 'Action locale non trouvee'
}
function Invoke-DesktopAction([string]$tag){
 switch($tag){
  'create' {& $script:desktopCreateAction;return}
  'open' {& $script:desktopOpenAction;return}
  'contacts' {& $script:desktopContactAction;return}
  'compose' {Invoke-DesktopNativeAction 'ComposeDraft';return}
  'mail-list' {Start-DesktopReceipt 'list';return}
  'mail-open' {Start-DesktopReceipt 'open';return}
  'enroll' {Invoke-DesktopNativeAction 'PrepareEnrollment';return}
  'proof' {Invoke-DesktopNativeAction 'AnswerEnrollment';return}
  'credential' {Invoke-DesktopNativeAction 'PrepareMailboxCredential';return}
  'activation' {Invoke-DesktopNativeAction 'ImportMailboxActivation';return}
  'session-lock' {Close-DesktopDocumentSession;return}
  'session-open' {try{$null=Open-DesktopDocumentSession}catch{[Windows.Forms.MessageBox]::Show('Ouverture non confirmée. Préparez une identité de laboratoire dans Identité.','Quantic Sillage','OK','Warning')|Out-Null};return}
  'doc-import' {Start-DesktopDocument 'import';return}
  'doc-list' {Start-DesktopDocument 'list';return}
  'doc-export' {Start-DesktopDocument 'export';return}
  'pay-demo' {Start-DesktopPayDemo;return}
  'refresh-protection' {Refresh-DesktopProtection;return}
  'sentinel-enable' {Set-DesktopSentinelProtection $true;return}
  'sentinel-disable' {Set-DesktopSentinelProtection $false;return}
  'advanced' {Show-DesktopPage 'Paramètres';$script:desktopAdvanced.Visible=$true;$script:desktopBody.Visible=$false;Update-DesktopLayout;return}
  default {Show-DesktopPage $tag}
 }
}

# Read only the existing local Sentinel telemetry; never launch the installed
# agent or change registry/security settings. Named events are advisory and
# can be spoofed by the same Windows user. Never infer device-wide safety.
function Read-DesktopSentinelEvent([string]$name){
 $handle=$null
 try{
  $handle=[Threading.EventWaitHandle]::OpenExisting($name,[Security.AccessControl.EventWaitHandleRights]::Synchronize)
  if($handle.WaitOne(0)){return 'signaled'}
  return 'unset'
 }catch [Threading.WaitHandleCannotBeOpenedException]{return 'absent'}
 catch{return 'unknown'}
 finally{if($handle){$handle.Dispose()}}
}
function Read-DesktopSentinelSignal([string]$name,[uint64]$bucket,[int]$count){
 $signal=Read-DesktopSentinelEvent $name
 if($signal -eq 'absent'){return 'absent'}
 if($signal -eq 'unknown'){return 'unknown'}
 if($count -eq 0){return 'none'}
 if($signal -ne 'signaled'){return 'unconfirmed'}
 for($i=0;$i -le 1 -and $i -le $bucket;$i++){
  $pulse=$name+'-pulse-'+($bucket-[uint64]$i).ToString('x16')
  if((Read-DesktopSentinelEvent $pulse) -eq 'signaled'){return 'fresh'}
 }
 return 'unconfirmed'
}
function Read-DesktopSentinelState {
 $stream=$null;$sha=$null
 try{
  $base=[Environment]::GetFolderPath('LocalApplicationData')
  $parent=Join-Path $base 'QuanticSillage'
  $dir=Join-Path $parent 'Sentinel'
  $path=Join-Path $dir 'installed.json'
  foreach($item in @($base,$parent,$dir)){
   if(-not [IO.Directory]::Exists($item)){return @{State='absent';Count=0}}
   if(([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse path refused'}
  }
  if(-not [IO.File]::Exists($path)){return @{State='absent';Count=0}}
  if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse file refused'}
  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  if($stream.Length -lt 1 -or $stream.Length -gt 65536){throw 'Invalid manifest size'}
  $raw=New-Object byte[] ([int]$stream.Length)
  $offset=0
  while($offset -lt $raw.Length){
   $n=$stream.Read($raw,$offset,$raw.Length-$offset)
   if($n -le 0){throw 'Incomplete manifest'}
   $offset+=$n
  }
  if($stream.ReadByte() -ne -1){throw 'Manifest changed'}
  $metadata=([Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json -ErrorAction Stop)
  if($metadata.version -ne 1 -or $metadata.exe_sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Unknown manifest version'}
  $count=0
  if($null -ne $metadata.backups){$count=@($metadata.backups).Count}
  if($count -gt 16){throw 'Invalid backup count'}
  $exe=Join-Path $dir 'quantic-sentinel.exe'
  if(-not [IO.File]::Exists($exe)){return @{State='unknown';Count=$count}}
  if(([IO.File]::GetAttributes($exe) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse executable refused'}
  $sha=[Security.Cryptography.SHA256]::Create()
  $digest=[BitConverter]::ToString($sha.ComputeHash($raw)).Replace('-','').ToLowerInvariant()
  if(-not ('QuanticDesktopUptime' -as [type])){
   Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class QuanticDesktopUptime { [DllImport("kernel32.dll")] public static extern ulong GetTickCount64(); }'
  }
  $bucket=[uint64][Math]::Floor([QuanticDesktopUptime]::GetTickCount64()/4000.0)
  $state=Read-DesktopSentinelSignal ('Local\QuanticSentinelBackupHealthV3-'+$digest) $bucket $count
  return @{State=$state;Count=$count}
 }catch{return @{State='unknown';Count=0}}
 finally{if($stream){$stream.Dispose()};if($sha){$sha.Dispose()}}
}

# Start only the package-pinned engine, retaining a deny-write/delete handle
# until it exits. Private file selections are sent over stdin, never argv.
function Invoke-DesktopSentinelEngine([string]$operation,[string]$payload=''){
 if($operation -notin @('--desktop-install','--desktop-uninstall')){throw 'Unknown action'}
 $manifest=Join-Path $root 'SHA256SUMS.txt'
 $engine=Join-Path $root 'bin\Quantic-Sentinel-Engine.exe'
 $manifestFile=$null;$engineFile=$null;$hash=$null;$child=$null
 try{
  foreach($path in @($root,(Join-Path $root 'bin'),$manifest,$engine)){
   if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse path'}
  }
  $manifestFile=[IO.File]::Open($manifest,'Open','Read','Read')
  if($manifestFile.Length -lt 1 -or $manifestFile.Length -gt 262144){throw 'Manifest size'}
  $hash=[Security.Cryptography.SHA256]::Create()
  $digest=[BitConverter]::ToString($hash.ComputeHash($manifestFile)).Replace('-','')
  if($digest -ine $ExpectedManifestSha256){throw 'Manifest mismatch'}
  $manifestFile.Position=0
  $reader=New-Object IO.StreamReader($manifestFile)
  $entries=@($reader.ReadToEnd() -split '\r?\n'|Where-Object {$_ -match '^[a-f0-9]{64} \*\./bin/Quantic-Sentinel-Engine\.exe$'})
  if($entries.Count -ne 1){throw 'Engine not inventoried'}
  $pin=$entries[0].Substring(0,64)
  $engineFile=[IO.File]::Open($engine,'Open','Read','Read')
  if($engineFile.Length -lt 1 -or $engineFile.Length -gt 33554432){throw 'Engine size'}
  $digest=[BitConverter]::ToString($hash.ComputeHash($engineFile)).Replace('-','')
  if($digest -ine $pin){throw 'Engine mismatch'}
  $psi=New-Object Diagnostics.ProcessStartInfo
  $psi.FileName=$engine;$psi.Arguments=$operation;$psi.WorkingDirectory=Split-Path -Parent $engine
  $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardInput=$true
  $child=[Diagnostics.Process]::Start($psi)
  if(-not $child){throw 'Engine launch failed'}
  try{
   $bytes=[Text.Encoding]::UTF8.GetBytes($payload)
   $child.StandardInput.BaseStream.Write($bytes,0,$bytes.Length)
   $child.StandardInput.BaseStream.Flush()
  }finally{$child.StandardInput.Close()}
  if(-not $child.WaitForExit(15000)){throw 'Action non confirmée. Vérifiez son état avant toute nouvelle tentative.'}
  if($child.ExitCode -ne 0){throw 'Action native refusée'}
 }finally{
  if($child){$child.Dispose()}
  if($engineFile){$engineFile.Dispose()}
  if($manifestFile){$manifestFile.Dispose()}
  if($hash){$hash.Dispose()}
 }
}
function Set-DesktopSentinelProtection([bool]$enable){
 try{
  if($enable){
   $folder=New-Object Windows.Forms.FolderBrowserDialog
   $folder.Description='Choisissez le dossier à surveiller'
   try{if($folder.ShowDialog($form) -ne 'OK'){return};$selected=$folder.SelectedPath}finally{$folder.Dispose()}
   $files=New-Object Windows.Forms.OpenFileDialog
   $files.Title='Choisissez les copies de sauvegarde inactives à protéger'
   $files.Filter='Sauvegardes|*.bak;*.backup;*.zip;*.7z;*.qvb'
   $files.Multiselect=$true;$files.CheckFileExists=$true
   try{if($files.ShowDialog($form) -ne 'OK'){return};$backups=@($files.FileNames)}finally{$files.Dispose()}
   if($backups.Count -lt 1 -or $backups.Count -gt 16){throw 'Sélectionnez entre 1 et 16 copies.'}
   $consent=[Windows.Forms.MessageBox]::Show($form,('Activer Sentinel au démarrage de votre session Windows et verrouiller '+$backups.Count+' copie(s) en lecture seule ? Les autres logiciels ne pourront plus modifier ces copies pendant le verrouillage.'),'Activer la protection','YesNo','Question','Button2')
   if($consent -ne 'Yes'){return}
   $request=@{root=$selected;backups=$backups}|ConvertTo-Json -Compress
   Invoke-DesktopSentinelEngine '--desktop-install' $request
   $message='Installation de l''agent acceptée. Attendez la confirmation des verrous dans cette page.'
  }else{
   $consent=[Windows.Forms.MessageBox]::Show($form,'Arrêter Sentinel et retirer son démarrage automatique ? Les verrous seront libérés. Les journaux et les sauvegardes seront conservés.','Désactiver la protection','YesNo','Warning','Button2')
   if($consent -ne 'Yes'){return}
   Invoke-DesktopSentinelEngine '--desktop-uninstall'
   $message='Agent désinstallé. Les sauvegardes et journaux sont conservés.'
  }
  [Windows.Forms.MessageBox]::Show($form,$message,'Quantic Sillage','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show($form,'Action non confirmée. Vérifiez l''installation et l''état de l''agent avant de réessayer. Une ancienne version installée doit être retirée volontairement.','Quantic Sillage','OK','Warning')|Out-Null
 }finally{Refresh-DesktopProtection}
}

function Refresh-DesktopProtection {
 if($script:desktopCurrent -ne 'Protection' -or -not $script:desktopProtectionTitle -or $script:desktopProtectionTitle.IsDisposed){return}
 $r=Read-DesktopSentinelState
 $script:desktopProtectionTitle.Text=switch($r.State){
  'fresh' {'Verrous signalés actifs'}
  'none' {'Aucune sauvegarde configurée'}
  'absent' {'Agent absent ou état non disponible'}
  'unconfirmed' {'Protection non confirmée'}
  default {'État indéterminé'}
 }
 $script:desktopProtectionDetail.Text=if($r.State -eq 'fresh'){
  ('{0} sauvegarde(s) signalée(s) par Sentinel. Signal récent, non authentifié.' -f $r.Count)
 }else{'Aucune garantie de protection ne peut être déduite de cet état.'}
 $script:desktopProtectionTime.Text='Dernière lecture locale : '+[DateTime]::Now.ToString('HH:mm:ss')
}
function Test-DesktopSentinelReadOnly {
 $name='Local\QuanticDesktop-CI-'+[Guid]::NewGuid().ToString('N')
 $status=$null;$pulse=$null
 try{
  if((Read-DesktopSentinelSignal $name 20 2) -ne 'absent'){throw 'Missing signal accepted'}
  $status=New-Object Threading.EventWaitHandle($true,[Threading.EventResetMode]::ManualReset,$name)
  if((Read-DesktopSentinelSignal $name 20 2) -ne 'unconfirmed'){throw 'Positive event alone accepted'}
  $pulse=New-Object Threading.EventWaitHandle($true,[Threading.EventResetMode]::ManualReset,($name+'-pulse-'+([uint64]20).ToString('x16')))
  if((Read-DesktopSentinelSignal $name 20 2) -ne 'fresh'){throw 'Fresh pulse rejected'}
  if((Read-DesktopSentinelSignal $name 21 2) -ne 'fresh'){throw 'Previous bucket rejected'}
  if((Read-DesktopSentinelSignal $name 22 2) -ne 'unconfirmed'){throw 'Stale positive signal accepted'}
  if((Read-DesktopSentinelSignal $name 20 0) -ne 'none'){throw 'Empty selection accepted'}
  $null=$status.Reset()
  if((Read-DesktopSentinelSignal $name 20 2) -ne 'unconfirmed'){throw 'Reset status ignored'}
 }finally{if($pulse){$pulse.Dispose()};if($status){$status.Dispose()}}
}


function Invoke-DesktopPayDemo([string]$payee,[string]$amount,[int]$witnesses){
 # Recheck the package pin and the verifier itself before invoking it.
 $manifest=Join-Path $root 'SHA256SUMS.txt'
 if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256){throw 'Package modified'}
 $line=@(Get-Content -LiteralPath $manifest|Where-Object {$_ -cmatch '^[a-f0-9]{64} \*\./Test-Windows-PQ-Package\.ps1$'})
 if($line.Count -ne 1){throw 'Verifier not inventoried'}
 $verifier=Join-Path $root 'Test-Windows-PQ-Package.ps1'
 if((Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash -ine $line[0].Substring(0,64)){throw 'Verifier modified'}
 & $verifier -PackageDirectory $root -ExpectedManifestSha256 $ExpectedManifestSha256 | Out-Null
 $scriptPath=Join-Path $root 'scripts\quantic-pay-desktop.mjs'
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=Join-Path $root 'runtime\node.exe'
 $psi.Arguments='"'+$scriptPath+'"'
 $psi.WorkingDirectory=$root;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 # Do not inherit code injection options from a developer's Node environment.
 $psi.EnvironmentVariables.Remove('NODE_OPTIONS')
 $psi.EnvironmentVariables.Remove('NODE_PATH')
 $child=[Diagnostics.Process]::Start($psi)
 try{
  $out=$child.StandardOutput.ReadToEndAsync();$err=$child.StandardError.ReadToEndAsync()
  $child.StandardInput.Write((@{payee=$payee;amount=$amount;witnesses=$witnesses;consent=$true}|ConvertTo-Json -Compress))
  $child.StandardInput.Close()
  if(-not $child.WaitForExit(20000)){try{$child.Kill()}catch{};throw 'Simulation interrompue'}
  if($child.ExitCode -ne 0 -or $out.Result.Length -gt 4096){throw 'Simulation refusée'}
  $r=$out.Result|ConvertFrom-Json
  if($r.mode -ne 'simulation' -or $r.realPaymentAuthorized -ne $false -or $r.status -notin @('confirmed','refused') -or $r.witnesses -ne $witnesses){throw 'Résultat non reconnu'}
  return $r
 }finally{$child.Dispose()}
}
function Start-DesktopPayDemo {
 if($script:desktopCurrent -ne 'Paiements'){return}
 $amount=$script:desktopPayAmount.Text.Trim()
 if($amount -notmatch '^(0|[1-9][0-9]{0,2})([.,][0-9]{1,2})?$'){ $script:desktopPayResult.Text='Saisissez un montant de 0,01 à 100,00 unités fictives.';return }
 $payee=if($script:desktopPayee.SelectedIndex -eq 0){'demo-bob'}else{'demo-shop'}
 $witnesses=2+$script:desktopPayWitnesses.SelectedIndex
 $answer=[Windows.Forms.MessageBox]::Show($form,('Simuler '+$amount+' unités fictives vers '+$script:desktopPayee.SelectedItem+' ? Aucun argent réel ne sera envoyé.'),'Confirmer la simulation','YesNo','Question','Button2')
 if($answer -ne 'Yes'){return}
 $script:desktopPayResult.Text='Vérification cryptographique en cours…'
 $script:desktopPayButton.Enabled=$false
 $form.Refresh()
 try{
  $r=Invoke-DesktopPayDemo $payee $amount $witnesses
  if($r.status -eq 'confirmed'){
   $script:desktopPayResult.Text=('Simulation confirmée par {0}/4 témoins locaux. Reste fictif : {1:N2}. Référence : {2}' -f $r.witnesses,($r.balanceCents/100),$r.reference)
  }else{$script:desktopPayResult.Text=('Simulation refusée : {0}/4 témoins disponibles. Solde fictif inchangé.' -f $r.witnesses)}
 }catch{$script:desktopPayResult.Text='Simulation non confirmée. Aucun paiement réel effectué.'}
 finally{$script:desktopPayButton.Enabled=$true}
}



$script:desktopDocumentProcess=$null
$script:desktopActiveAddress=$null
function Close-DesktopDocumentSession {
 $p=$script:desktopDocumentProcess;$script:desktopDocumentProcess=$null;$script:desktopActiveAddress=$null
 if($p){try{$p.StandardInput.Close();if(-not $p.WaitForExit(2000)){$p.Kill()}}catch{}finally{$p.Dispose()}}
 if($script:desktopDocuments -and -not $script:desktopDocuments.IsDisposed){$script:desktopDocuments.Items.Clear()}
 $script:desktopDocumentIDs=@()
 if($script:desktopStorageText -and -not $script:desktopStorageText.IsDisposed){$script:desktopStorageText.Text='Inventaire non ouvert'}
 if($script:desktopStorageRing -and -not $script:desktopStorageRing.IsDisposed){$script:desktopStorageRing.Tag=-1;$script:desktopStorageRing.Invalidate()}
 if($script:desktopMailList -and -not $script:desktopMailList.IsDisposed){$script:desktopMailList.Items.Clear()}
 $script:desktopMailIDs=@()
 if($script:desktopMailBody -and -not $script:desktopMailBody.IsDisposed){$script:desktopMailBody.Clear()}
 if($script:desktopMailStatus -and -not $script:desktopMailStatus.IsDisposed){$script:desktopMailStatus.Text='Historique local verrouillé.'}
 if($script:desktopIdentityAddress -and -not $script:desktopIdentityAddress.IsDisposed){$script:desktopIdentityAddress.Text='Aucune identité locale ouverte.'}
 if($script:desktopIdentityStatus -and -not $script:desktopIdentityStatus.IsDisposed){$script:desktopIdentityStatus.Text='Espace privé fermé · aucune certification officielle'}
 if($script:desktopDocumentStatus -and -not $script:desktopDocumentStatus.IsDisposed){$script:desktopDocumentStatus.Text='Coffre documentaire verrouillé.'}
 if($script:desktopSessionLabel -and -not $script:desktopSessionLabel.IsDisposed){$script:desktopSessionLabel.Text='Espace privé fermé'}
}
function Choose-DesktopEnrollment {
 $parent=[Environment]::GetFolderPath('LocalApplicationData')
 $r=Invoke-EnrollmentNative 'list' $parent
 if($r.status -cne 'pending-enrollment-candidates-only' -or $r.candidates.Count -gt 32){throw 'Registre non reconnu'}
 $items=@($r.candidates)
 if($items.Count -eq 0){throw 'Préparez une identité de laboratoire dans Identité.'}
 foreach($item in $items){
  if($item.directory -cnotmatch ('^'+[Regex]::Escape($parent)+'\\quantic-enroll-[0-9a-f]{16}$') -or $item.address -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{32}@quantic$'){throw 'Identité non reconnue'}
 }
 $dlg=New-Object Windows.Forms.Form
 $dlg.Text='Ouvrir mon espace documentaire';$dlg.StartPosition='CenterParent';$dlg.ClientSize=New-Object Drawing.Size(560,180)
 $null=Desktop-Label $dlg 'Sélectionnez une identité locale de laboratoire.' 20 15 520 36 11
 $list=New-Object Windows.Forms.ComboBox;$list.DropDownStyle='DropDownList';$list.SetBounds(20,57,520,35)
 foreach($item in $items){$null=$list.Items.Add([string]$item.address)}
 $list.SelectedIndex=0;$dlg.Controls.Add($list)
 $ok=New-Object Windows.Forms.Button;$ok.Text='Continuer';$ok.SetBounds(260,115,135,40);$ok.DialogResult='OK';$dlg.Controls.Add($ok);$dlg.AcceptButton=$ok
 $cancel=New-Object Windows.Forms.Button;$cancel.Text='Annuler';$cancel.SetBounds(405,115,135,40);$cancel.DialogResult='Cancel';$dlg.Controls.Add($cancel);$dlg.CancelButton=$cancel
 try{if($dlg.ShowDialog($form) -ne 'OK'){return $null};return $items[$list.SelectedIndex]}finally{$dlg.Dispose()}
}
function Open-DesktopDocumentSession {
 if($script:desktopDocumentProcess -and -not $script:desktopDocumentProcess.HasExited){return $true}
 Close-DesktopDocumentSession
 $chosen=Choose-DesktopEnrollment
 if(-not $chosen){return $false}
 $dir=[string]$chosen.directory
 $vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
 $manifest=Join-Path $root 'SHA256SUMS.txt'
 if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256){throw 'Inventaire modifié'}
 $line=@(Get-Content -LiteralPath $manifest|Where-Object {$_ -cmatch '^[a-f0-9]{64} \*\./Test-Windows-PQ-Package\.ps1$'})
 $verifier=Join-Path $root 'Test-Windows-PQ-Package.ps1'
 if($line.Count -ne 1 -or (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash -ine $line[0].Substring(0,64)){throw 'Vérificateur non reconnu'}
 & $verifier -PackageDirectory $root -ExpectedManifestSha256 $ExpectedManifestSha256 | Out-Null
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Coffre non vérifié'}
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$vault;$psi.Arguments=('--gui-document-session-lab "{0}"' -f $dir);$psi.WorkingDirectory=(Join-Path $root 'bin')
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.StandardOutputEncoding=[Text.Encoding]::UTF8
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')

 $child=[Diagnostics.Process]::Start($psi)
 try{
  $err=$child.StandardError.ReadToEndAsync()
  $line=$child.StandardOutput.ReadLineAsync()
  if(-not $line.Wait(240000) -or -not $line.Result -or $line.Result.Length -gt 2048){throw 'Session non confirmée'}
  $r=$line.Result|ConvertFrom-Json
  if($r.labOnly -ne $true -or $r.status -cne 'document-session-ready' -or $r.address -cne $chosen.address -or $child.HasExited){throw 'Session non reconnue'}
  $script:desktopDocumentProcess=$child;$child=$null;$script:desktopActiveAddress=[string]$r.address
  if($script:desktopIdentityAddress -and -not $script:desktopIdentityAddress.IsDisposed){$script:desktopIdentityAddress.Text=$script:desktopActiveAddress}
  if($script:desktopIdentityStatus -and -not $script:desktopIdentityStatus.IsDisposed){$script:desktopIdentityStatus.Text='Coffres locaux ouverts · aucune certification officielle'}
  $script:desktopSessionLabel.Text='Espace privé ouvert · 5 min max.'
  return $true
 }finally{if($child){try{$child.StandardInput.Close();if(-not $child.WaitForExit(1000)){$child.Kill()}}catch{};$child.Dispose()}}
}
function Invoke-DesktopDocument([string]$mode,[string]$path='', [string]$id='', [string[]]$paths=@()){
 if(-not (Open-DesktopDocumentSession)){throw 'Ouverture annulée'}
 $p=$script:desktopDocumentProcess
 try{
  $json=@{operation=$mode;request=@{path=$path;id=$id;paths=@($paths)}}|ConvertTo-Json -Depth 4 -Compress
  $bytes=[Text.Encoding]::UTF8.GetBytes($json+[Environment]::NewLine)
  if($bytes.Length -gt 4096){throw 'Sélection trop longue'}
  $p.StandardInput.BaseStream.Write($bytes,0,$bytes.Length);$p.StandardInput.BaseStream.Flush()
  $line=$p.StandardOutput.ReadLineAsync()
  if(-not $line.Wait(240000) -or -not $line.Result -or $line.Result.Length -gt 65536){throw 'Session interrompue'}
  $r=$line.Result|ConvertFrom-Json
  $expected=switch($mode){'list'{'listed'};'import'{'imported'};'export'{'exported'};'mail-list'{'mail-listed'};'mail-open'{'mail-opened'}}
  if($r.labOnly -ne $true -or ($r.status -cne $expected -and -not ($mode -eq 'import' -and $r.status -ceq 'partial'))){throw 'Opération non confirmée'}
  return $r
 }catch{Close-DesktopDocumentSession;throw}
}

function Start-DesktopDocument([string]$mode){
 try{
  switch($mode){
   'import' {
    $picker=New-Object Windows.Forms.OpenFileDialog
    $picker.Title='Choisir jusqu''à 8 fichiers de test (8 Mio chacun maximum)'
    $picker.CheckFileExists=$true;$picker.Multiselect=$true
    try{if($picker.ShowDialog($form) -ne 'OK'){return};$paths=@($picker.FileNames)}finally{$picker.Dispose()}
    if($paths.Count -lt 1 -or $paths.Count -gt 8){throw 'Sélection hors limites'}
    $r=Invoke-DesktopDocument -mode 'import' -paths $paths
    $n=@($r.documents).Count
    $script:desktopDocumentStatus.Text=if($r.status -eq 'partial'){
     ('Importation interrompue : {0} sur {1} copies confirmées. Tous les originaux sont conservés.' -f $n,$paths.Count)
    }else{('{0} copie(s) chiffrée(s) enregistrée(s) et relue(s). Originaux conservés.' -f $n)}
   }
   'list' {
    $r=Invoke-DesktopDocument 'list'
    $script:desktopDocuments.Items.Clear();$script:desktopDocumentIDs=@()
    foreach($d in @($r.documents)){
     if($d.id -cnotmatch '^[a-f0-9]{32}$' -or $d.size -lt 1 -or $d.size -gt 8388608){throw 'Inventaire invalide'}
     $item=New-Object Windows.Forms.ListViewItem([string]$d.name)
     $null=$item.SubItems.Add(('{0:N1} Kio' -f ($d.size/1024.0)))
     $null=$script:desktopDocuments.Items.Add($item)
     $script:desktopDocumentIDs+= [string]$d.id
    }
    if($script:desktopDocumentIDs.Count -gt 0){$script:desktopDocuments.Items[0].Selected=$true}
    $sum=0;foreach($d in @($r.documents)){$sum+=[int64]$d.size}
    $script:desktopStorageText.Text=('{0:N2} Mio / 256 Mio' -f ($sum/1048576.0))
    $script:desktopStorageRing.Tag=[int][Math]::Min(100,[Math]::Ceiling($sum/268435456.0*100));$script:desktopStorageRing.Invalidate()
    $script:desktopDocumentStatus.Text=('{0} document(s) vérifié(s). Session documentaire temporaire.' -f $script:desktopDocumentIDs.Count)
   }
   'export' {
    $i=if($script:desktopDocuments.SelectedIndices.Count -eq 1){$script:desktopDocuments.SelectedIndices[0]}else{-1}
    if($i -lt 0 -or $i -ge $script:desktopDocumentIDs.Count){throw 'Consultez et sélectionnez un document avant de le récupérer.'}
    $id=$script:desktopDocumentIDs[$i]
    $picker=New-Object Windows.Forms.FolderBrowserDialog
    $picker.Description='Choisir où créer un nouveau dossier privé pour la copie déchiffrée'
    try{if($picker.ShowDialog($form) -ne 'OK'){return};$path=$picker.SelectedPath}finally{$picker.Dispose()}
    $null=Invoke-DesktopDocument 'export' $path $id
    $script:desktopDocumentStatus.Text='Copie déchiffrée récupérée dans un dossier privé neuf. Le coffre conserve sa copie chiffrée.'
   }
  }
 }catch{$script:desktopDocumentStatus.Text='Action non confirmée : accès, chemin ou limites du laboratoire. Aucun écrasement demandé.'}
}

function Start-DesktopReceipt([string]$mode){
 try{
  if($mode -eq 'list'){
   $r=Invoke-DesktopDocument 'mail-list'
   $script:desktopMailList.Items.Clear();$script:desktopMailBody.Clear();$script:desktopMailIDs=@()
   foreach($m in @($r.messages)){
    if($m.id -cnotmatch '^[a-f0-9]{32}$' -or ([string]$m.subject).Length -gt 240 -or $script:desktopMailIDs.Count -ge 64){throw 'Historique invalide'}
    $subject=if([string]::IsNullOrWhiteSpace([string]$m.subject)){'(Sans objet)'}else{[string]$m.subject}
    $null=$script:desktopMailList.Items.Add($subject);$script:desktopMailIDs+=[string]$m.id
   }
   $status=('{0} reçu(s) local(aux) authentifié(s).' -f $script:desktopMailIDs.Count)
   if($r.unverified -gt 0){$status+=(' {0} non vérifié(s).' -f $r.unverified)}
   if($r.truncated -eq $true){$status+=' Liste limitée à 64.'}
   $script:desktopMailStatus.Text=$status
  }elseif($mode -eq 'open'){
   if(-not $script:desktopDocumentProcess -or $script:desktopDocumentProcess.HasExited){Close-DesktopDocumentSession;return}
   $i=$script:desktopMailList.SelectedIndex
   if($i -lt 0 -or $i -ge $script:desktopMailIDs.Count){return}
   $id=$script:desktopMailIDs[$i];$r=Invoke-DesktopDocument 'mail-open' '' $id
   if($r.message.id -cne $id -or ([string]$r.message.body).Length -gt 8192){throw 'Reçu non reconnu'}
   $script:desktopMailBody.Text=([string]$r.message.subject+[Environment]::NewLine+[Environment]::NewLine+[string]$r.message.body)
  }
 }catch{
  Close-DesktopDocumentSession
  $script:desktopMailStatus.Text='Historique non confirmé. Aucun message envoyé ou acquitté.'
 }
}

function Desktop-Section($parent,[int]$x,[int]$y,[int]$w,[int]$h){
 $p=New-Object Windows.Forms.Panel
 $p.BackColor=$script:desktopColors.White
 Set-DesktopRoundedCard $p;$p.SetBounds($x,$y,$w,$h);$parent.Controls.Add($p)
 return $p
}
function Desktop-SettingRow($parent,[string]$title,[string]$detail,[int]$glyph,[int]$y,[string]$action='',[string]$tag=''){
 $p=Desktop-Section $parent 0 $y 812 68
 $i=Desktop-Label $p ([string][char]$glyph) 14 13 39 39 17
 $i.Font=New-Object Drawing.Font('Segoe MDL2 Assets',22,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
 $i.TextAlign='MiddleCenter';$i.ForeColor=$script:desktopColors.Blue;$i.BackColor=[Drawing.Color]::FromArgb(237,244,252)
 $null=Desktop-Label $p $title 66 10 515 22 12 $true
 $d=Desktop-Label $p $detail 66 33 515 28 9
 $d.ForeColor=$script:desktopColors.Muted
 if($action){$b=Desktop-Button $p ($action+'  '+[char]0x203A) $tag 608 17 186 34 $false;$b.FlatAppearance.BorderSize=0;$b.ForeColor=$script:desktopColors.Blue}
}

function Show-DesktopPage([string]$name){
 if($name -notin $script:desktopPages){throw 'Page inconnue'}
 $script:desktopCurrent=$name
 foreach($b in $script:desktopNav){
  $b.BackColor=if($b.Tag -eq $name){[Drawing.Color]::FromArgb(28,66,105)}else{$script:desktopColors.Navy}
 }
 $script:desktopAdvanced.Visible=$false
 $script:desktopBody.Visible=$true
 $script:desktopTitle.Text=$name
 $script:desktopPageBounds=@{}
 while($script:desktopBody.Controls.Count -gt 0){$old=$script:desktopBody.Controls[0];$script:desktopBody.Controls.RemoveAt(0);$old.Dispose()}
 $body=$script:desktopBody
 $w=396;$right=416
 switch($name){
  'Accueil' {
   $hero=New-Object Windows.Forms.Panel
   $hello=Desktop-Label $body 'Bienvenue dans Quantic Sillage' 0 0 812 36 20 $true
   $subtitle=Desktop-Label $body 'Votre espace numérique unifié · Édition de laboratoire.' 0 39 812 24 10
   $subtitle.ForeColor=$script:desktopColors.Muted
   $hero.BackColor=$script:desktopColors.Navy;Set-DesktopRoundedCard $hero;$hero.SetBounds(0,75,812,142);$body.Controls.Add($hero)
   $hero.Add_Paint({param($sender,$e)
    $rect=New-Object Drawing.Rectangle(0,0,$sender.Width,$sender.Height)
    $gradient=New-Object Drawing.Drawing2D.LinearGradientBrush($rect,[Drawing.Color]::FromArgb(10,29,51),[Drawing.Color]::FromArgb(17,68,111),0)
    try{$e.Graphics.FillRectangle($gradient,$rect)}finally{$gradient.Dispose()}
    # Embedded decorative crop of the approved Earth banner, not a screenshot of UI controls.
    $stream=New-Object IO.MemoryStream(,([Convert]::FromBase64String('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDACAWGBwYFCAcGhwkIiAmMFA0MCwsMGJGSjpQdGZ6eHJmcG6AkLicgIiuim5woNqirr7EztDOfJri8uDI8LjKzsb/2wBDASIkJDAqMF40NF7GhHCExsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsb/wAARCAArAFADASIAAhEBAxEB/8QAGQAAAwEBAQAAAAAAAAAAAAAAAgMEAAEF/8QANBAAAgEDAwICBgkFAAAAAAAAAQIDABEhBBIxQWEyUQUTcYGRwRQVIiMzQlKh0TREVGKx/8QAGAEBAQEBAQAAAAAAAAAAAAAAAgEAAwT/xAAaEQADAAMBAAAAAAAAAAAAAAAAARECITES/9oADAMBAAIRAxEAPwCL6x1n+Q/xro9Iaw/3EnxqUDNOjjxuc2X/ALXpWKZxeUKotXrXNhPIffVI1UkX4mod2/SDj4157T2G2PC+Q60cMJklVZDtuLgXyar8oC9Mpl9JTlrB9p4xXItZqZMnUOFvYW5J7V58rjeQoKqDxen6dWMDlpWQDAsPP5UcmkuCxTpY2s1Jm9Ukr4JFxkmlrrtS4YfSSjg2IY8DtUuomBxFcEizNwKSB6vmxJ4tR6Phc2t1PI1TEgZHF/ZSfrHVgf1D39tTGwAbm/TihtddwHHNbSMGAFyfhXHcnk+6hJ8+aHNr2xToIGkhU+EE9+lXaTULGWYo8jMLE8V56bg42c1UWMkxMKnHFsG1c8t9GtFkQ0iK8zfakP5SLAeypJGaSRmOQBckG96dpYo13iZmRk8Xbt7apdNKYTNGkkuLhb8++ufqM6eajzB943hY2HT8oopDB6kKm4uOW4Fq6FMyu0CgKLXAwRSpVkCncrC2D2pp0IAI22PHNxWIITcqnbe24+dZgAwBFjww+dC0jeEH7PlWIZVLsFFWQK0kypEbBR0xbvSYWKxNbFzY47VuLkfpFZ7MtFCsrQlHxsPjHzNTzzqLrDI7E+JyLX7eym6kD6Ppv9gxPc1EzEgAnAwKKV2JsajPPIokYuBkhm6UzT6lYrrIDbO0r0P8UvTAH1p6iMkUk0omSwsmgLETQuCzm+0HF+38VoVd0KE7S44JsLg9aTHnSS9iCP2otOTZs8ZFHcKY/dgpexNrjz/alsgZmKsLc5FFILaph0DWFNlRV06MBkk1bCdP/9k=')))
    try{
     $earth=[Drawing.Image]::FromStream($stream)
     try{
      $e.Graphics.InterpolationMode=[Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
      $w=[int]($sender.Width*0.37);$x=$sender.Width-$w
      $e.Graphics.DrawImage($earth,(New-Object Drawing.Rectangle($x,0,$w,$sender.Height)))
      $fade=New-Object Drawing.Drawing2D.LinearGradientBrush((New-Object Drawing.Rectangle($x,0,48,$sender.Height)),[Drawing.Color]::FromArgb(255,14,43,76),[Drawing.Color]::FromArgb(0,14,43,76),0)
      try{$e.Graphics.FillRectangle($fade,$x,0,48,$sender.Height)}finally{$fade.Dispose()}
     }finally{$earth.Dispose()}
    }finally{$stream.Dispose()}
   })
   $kicker=Desktop-Label $hero 'QUANTIC SILLAGE' 22 17 460 22 9 $true
   $kicker.BackColor=[Drawing.Color]::Transparent;$kicker.ForeColor=[Drawing.Color]::FromArgb(173,202,232)
   $headline=Desktop-Label $hero ('Votre identité, vos échanges,'+[Environment]::NewLine+'vos paiements et vos données') 22 45 505 58 17 $true
   $headline.BackColor=[Drawing.Color]::Transparent;$headline.ForeColor=[Drawing.Color]::White
   $detail=Desktop-Label $hero 'Dans un espace numérique sous votre contrôle.' 24 109 510 24 10
   $detail.BackColor=[Drawing.Color]::Transparent;$detail.ForeColor=[Drawing.Color]::FromArgb(212,226,241)
   Desktop-HomeCard $body 'Identité' 'Votre identité numérique locale.' 'Mon identité' 'Identité' 0xE77B 0 233
   Desktop-HomeCard $body 'Messagerie' 'Vos échanges et vos contacts.' 'Mes messages' 'Messagerie' 0xE715 276 233
   Desktop-HomeCard $body 'Paiements' 'Simulation sans valeur monétaire.' 'Mes paiements' 'Paiements' 0xE8C7 552 233
   Desktop-HomeCard $body 'Coffre-fort' 'Vos documents chiffrés de test.' 'Mon coffre' 'Coffre-fort' 0xE72E 0 387
   Desktop-HomeCard $body 'Protection' 'Surveillance locale des sauvegardes.' 'Ma protection' 'Protection' 0xEA18 276 387
   Desktop-HomeCard $body 'État de votre espace' 'Consulter les signaux locaux disponibles.' 'Voir la protection' 'Protection' 0xE9D9 552 387
  }
  'Identité' {
   $null=Desktop-Label $body 'Identité numérique' 0 0 810 36 19 $true
   $lead=Desktop-Label $body 'Créez ou vérifiez votre identité de laboratoire.' 0 40 810 30 10
   $lead.ForeColor=$script:desktopColors.Muted
   $idCard=New-Object Windows.Forms.Panel
   $idCard.BackColor=[Drawing.Color]::FromArgb(224,237,252);Set-DesktopRoundedCard $idCard
   $idCard.Add_Paint({param($sender,$e) $r=New-Object Drawing.Rectangle(0,0,$sender.Width,$sender.Height);$g=New-Object Drawing.Drawing2D.LinearGradientBrush($r,[Drawing.Color]::FromArgb(239,247,255),[Drawing.Color]::FromArgb(180,211,245),25);try{$e.Graphics.FillRectangle($g,$r)}finally{$g.Dispose()}})
   $idCard.SetBounds(0,88,500,248);$body.Controls.Add($idCard)
   $mark=Desktop-Label $idCard ([string][char]0xE77B) 24 85 88 88 19
   $mark.Font=New-Object Drawing.Font('Segoe MDL2 Assets',56,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
   $mark.TextAlign='MiddleCenter';$mark.BackColor=[Drawing.Color]::FromArgb(214,230,248);$mark.ForeColor=$script:desktopColors.Blue
   $null=Desktop-Label $idCard 'Quantic Sillage' 24 19 446 26 14 $true
   $null=Desktop-Label $idCard 'IDENTITÉ NUMÉRIQUE DE LABORATOIRE' 24 49 446 25 9
   $null=Desktop-Label $idCard 'Mon identité locale' 130 87 342 31 16 $true
   $address=if($script:desktopActiveAddress){$script:desktopActiveAddress}else{'Aucune identité locale ouverte.'}
   $script:desktopIdentityAddress=Desktop-Label $idCard $address 130 125 342 65 10
   $script:desktopIdentityAddress.ForeColor=$script:desktopColors.Muted
   $status=if($script:desktopActiveAddress){'Coffres locaux ouverts · aucune certification officielle'}else{'Espace privé fermé · aucune certification officielle'}
   $script:desktopIdentityStatus=Desktop-Label $idCard $status 24 204 446 27 9
   $script:desktopIdentityStatus.ForeColor=$script:desktopColors.Muted
   foreach($control in $idCard.Controls){if($control -is [Windows.Forms.Label] -and $control -ne $mark){$control.BackColor=[Drawing.Color]::Transparent}}
   $actionPanel=New-Object Windows.Forms.Panel;$actionPanel.BackColor=$script:desktopColors.White
   Set-DesktopRoundedCard $actionPanel;$actionPanel.SetBounds(516,88,296,248);$body.Controls.Add($actionPanel)
   $null=Desktop-Label $actionPanel 'Actions' 17 17 262 29 14 $true
   $null=Desktop-Button $actionPanel 'Ouvrir mon espace' 'session-open' 17 59 262 39 $true
   $null=Desktop-Button $actionPanel 'Créer une identité' 'create' 17 109 262 39 $false
   $null=Desktop-Button $actionPanel 'Préparer mon inscription' 'enroll' 17 159 262 39 $false
   $null=Desktop-Card $body 'Preuve de possession' 'Répondre au défi signé fourni par votre opérateur indépendant.' 'Prouver mon identité' 'proof' 0 352 812 148
  }
  'Messagerie' {
   $null=Desktop-Label $body 'Messagerie sécurisée' 0 0 500 37 19 $true
   $lead=Desktop-Label $body 'Vos échanges privés, depuis votre espace local.' 0 43 800 28 10
   $lead.ForeColor=$script:desktopColors.Muted
   $null=Desktop-Button $body '+ Nouveau message' 'compose' 574 0 238 41 $true
   $nav=New-Object Windows.Forms.Panel;$nav.BackColor=$script:desktopColors.White
   Set-DesktopRoundedCard $nav;$nav.SetBounds(0,90,230,390);$body.Controls.Add($nav)
   $null=Desktop-Label $nav 'Messagerie' 16 18 198 28 12 $true
   $null=Desktop-Button $nav 'Nouveau message' 'compose' 13 62 204 38 $false
   $null=Desktop-Button $nav 'Contacts' 'contacts' 13 108 204 38 $false
   $null=Desktop-Button $nav 'Recevoir / envoyer' 'compose' 13 304 204 38 $false
   $null=Desktop-Label $nav 'Configuration' 16 174 198 28 12 $true
   $null=Desktop-Button $nav 'Configurer mes accès' 'activation' 13 214 204 38 $false
   $null=Desktop-Button $nav 'Préparer mes accès' 'credential' 13 260 204 38 $false
   $mail=New-Object Windows.Forms.Panel;$mail.BackColor=$script:desktopColors.White
   Set-DesktopRoundedCard $mail;$mail.SetBounds(246,90,566,390);$body.Controls.Add($mail)
   $null=Desktop-Label $mail 'Boîte de réception' 22 20 522 32 15 $true
   $rule=New-Object Windows.Forms.Panel;$rule.BackColor=$script:desktopColors.Border;$rule.SetBounds(20,62,526,1);$mail.Controls.Add($rule)
   $null=Desktop-Button $mail 'Actualiser mes reçus' 'mail-list' 22 78 255 36 $true
   $null=Desktop-Button $mail 'Lire le message' 'mail-open' 289 78 255 36 $false
   $script:desktopMailList=New-Object Windows.Forms.ListBox
   $script:desktopMailList.Font=New-Object Drawing.Font('Segoe UI',13,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
   $script:desktopMailList.SetBounds(22,126,522,94);$mail.Controls.Add($script:desktopMailList)
   $script:desktopMailIDs=@()
   $script:desktopMailBody=New-Object Windows.Forms.TextBox
   $script:desktopMailBody.Multiline=$true;$script:desktopMailBody.ReadOnly=$true
   $script:desktopMailBody.ScrollBars='Vertical';$script:desktopMailBody.BackColor=$script:desktopColors.White
   $script:desktopMailBody.Font=New-Object Drawing.Font('Segoe UI',13,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
   $script:desktopMailBody.SetBounds(22,232,522,103);$mail.Controls.Add($script:desktopMailBody)
   $script:desktopMailStatus=Desktop-Label $mail 'Reçus locaux uniquement · aucune preuve de livraison distante.' 22 347 522 36 9
   $script:desktopMailStatus.ForeColor=$script:desktopColors.Muted

  }
  'Paiements' {
   $lead=Desktop-Label $body 'Payer et recevoir · simulation de laboratoire sans argent réel.' 0 0 812 30 10
   $lead.ForeColor=$script:desktopColors.Muted
   $wallet=Desktop-Section $body 0 44 396 236
   $null=Desktop-Label $wallet 'Solde du portefeuille' 18 16 358 27 12 $true
   $null=Desktop-Label $wallet 'Non disponible' 18 50 358 43 23 $true
   $d=Desktop-Label $wallet 'Aucun compte financier actif' 18 100 358 28 10
   $d.ForeColor=$script:desktopColors.Muted
   $null=Desktop-Label $wallet 'SIMULATION LOCALE' 18 151 358 25 10 $true
   $null=Desktop-Label $wallet '100 unités fictives au début de chaque essai.' 18 181 358 39 10
   $panel=Desktop-Section $body 412 44 400 236
   $null=Desktop-Label $panel 'Effectuer un paiement fictif' 18 12 364 28 14 $true
   $null=Desktop-Label $panel 'Destinataire' 18 44 364 20 9
   $script:desktopPayee=New-Object Windows.Forms.ComboBox
   $script:desktopPayee.DropDownStyle='DropDownList';$script:desktopPayee.SetBounds(18,66,364,28)
   $null=$script:desktopPayee.Items.Add('Particulier de démonstration');$null=$script:desktopPayee.Items.Add('Commerce de démonstration')
   $script:desktopPayee.SelectedIndex=0;$panel.Controls.Add($script:desktopPayee)
   $null=Desktop-Label $panel 'Montant fictif' 18 103 174 22 9
   $script:desktopPayAmount=New-Object Windows.Forms.TextBox
   $script:desktopPayAmount.SetBounds(18,127,174,28);$script:desktopPayAmount.MaxLength=6;$panel.Controls.Add($script:desktopPayAmount)
   $null=Desktop-Label $panel 'Témoins disponibles' 206 103 176 22 9
   $script:desktopPayWitnesses=New-Object Windows.Forms.ComboBox
   $script:desktopPayWitnesses.DropDownStyle='DropDownList';$script:desktopPayWitnesses.SetBounds(206,127,176,28)
   foreach($n in @('2 sur 4','3 sur 4','4 sur 4')){$null=$script:desktopPayWitnesses.Items.Add($n)}
   $script:desktopPayWitnesses.SelectedIndex=2;$panel.Controls.Add($script:desktopPayWitnesses)
   $script:desktopPayButton=Desktop-Button $panel 'Simuler le paiement' 'pay-demo' 18 178 364 38 $true
   $null=Desktop-Label $body 'Dernières transactions' 0 299 812 32 15 $true
   $history=Desktop-Section $body 0 339 812 144
   $null=Desktop-Label $history 'Résultat du dernier essai' 18 13 776 25 11 $true
   $script:desktopPayResult=Desktop-Label $history 'Aucune simulation effectuée dans cette page. Aucun historique bancaire réel.' 18 47 776 81 11
   $script:desktopPayResult.ForeColor=$script:desktopColors.Muted
  }
  'Coffre-fort' {
   $lead=Desktop-Label $body 'Vos documents de test, chiffrés et sous votre contrôle.' 0 0 812 30 10
   $lead.ForeColor=$script:desktopColors.Muted
   $storage=Desktop-Section $body 0 44 812 135
   $script:desktopStorageRing=New-Object Windows.Forms.Panel
   $script:desktopStorageRing.SetBounds(18,17,100,100);$script:desktopStorageRing.Tag=-1
   $storage.Controls.Add($script:desktopStorageRing)
   $script:desktopStorageRing.Add_Paint({param($sender,$e)
    $e.Graphics.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $rect=New-Object Drawing.Rectangle(9,9,80,80)
    $track=New-Object Drawing.Pen([Drawing.Color]::FromArgb(226,233,242),7)
    $used=New-Object Drawing.Pen([Drawing.Color]::FromArgb(15,139,121),7)
    try{
     $e.Graphics.DrawEllipse($track,$rect)
     if([int]$sender.Tag -gt 0){$e.Graphics.DrawArc($used,$rect,-90,[float]([Math]::Min(360,[int]$sender.Tag*3.6)))}
     $value=if([int]$sender.Tag -lt 0){'—'}else{([string]$sender.Tag+'%')}
     [Windows.Forms.TextRenderer]::DrawText($e.Graphics,$value,$sender.Font,$rect,$script:desktopColors.Ink,([Windows.Forms.TextFormatFlags]::HorizontalCenter -bor [Windows.Forms.TextFormatFlags]::VerticalCenter))
    }finally{$track.Dispose();$used.Dispose()}
   })
   $null=Desktop-Label $storage 'Espace de stockage' 134 20 365 28 14 $true
   $script:desktopStorageText=Desktop-Label $storage 'Inventaire non ouvert' 134 53 365 27 12
   $null=Desktop-Label $storage 'Limite : 32 documents · 8 Mio par fichier' 134 83 365 32 9
   $null=Desktop-Button $storage '+ Ajouter des fichiers' 'doc-import' 548 46 244 40 $true
   $null=Desktop-Label $body 'Mes documents' 0 199 812 30 15 $true
   $panel=Desktop-Section $body 0 238 812 265
   $null=Desktop-Label $panel 'Nom du document' 20 13 480 24 10 $true
   $null=Desktop-Label $panel 'Taille' 570 13 220 24 10 $true
   $script:desktopDocuments=New-Object Windows.Forms.ListView
   $script:desktopDocuments.View='Details';$script:desktopDocuments.FullRowSelect=$true;$script:desktopDocuments.MultiSelect=$false
   $script:desktopDocuments.HeaderStyle='Nonclickable'
   $script:desktopDocuments.SetBounds(18,41,776,124);$panel.Controls.Add($script:desktopDocuments)
   $null=$script:desktopDocuments.Columns.Add('Nom',500);$null=$script:desktopDocuments.Columns.Add('Taille',200)
   $script:desktopDocumentIDs=@()
   $null=Desktop-Button $panel 'Actualiser' 'doc-list' 18 180 370 35 $false
   $null=Desktop-Button $panel 'Récupérer la copie' 'doc-export' 404 180 390 35 $false
   $script:desktopDocumentStatus=Desktop-Label $panel 'Coffre fermé. Ouvrez votre espace pour consulter les documents.' 18 224 776 32 9
  }
  'Protection' {
   $lead=Desktop-Label $body 'Sécurité, confidentialité et maîtrise de vos données.' 0 0 812 30 10
   $lead.ForeColor=$script:desktopColors.Muted
   $panel=Desktop-Section $body 0 44 812 140
   $null=Desktop-Label $panel 'État des sauvegardes' 20 11 770 23 10 $true
   $script:desktopProtectionTitle=Desktop-Label $panel 'État indéterminé' 20 38 770 30 16 $true
   $script:desktopProtectionDetail=Desktop-Label $panel '' 20 73 770 33 10
   $script:desktopProtectionTime=Desktop-Label $panel '' 20 108 520 23 9
   $null=Desktop-Button $panel 'Actualiser' 'refresh-protection' 622 103 170 27 $false
   Desktop-SettingRow $body 'Sécurité de l''appareil' 'Diagnostic antivirus complet non disponible.' 0xE83D 200
   Desktop-SettingRow $body 'Confidentialité' 'Coffre documentaire local chiffré · édition de test.' 0xE72E 278 'Mon coffre' 'Coffre-fort'
   Desktop-SettingRow $body 'Conformité européenne' 'Aucune certification officielle à ce stade.' 0xEA18 356
   Desktop-SettingRow $body 'Protection des accès' 'Ouverture temporaire du coffre local par deux secrets.' 0xE72E 434 'Verrouiller' 'session-lock'
   $null=Desktop-Button $body 'Activer Sentinel' 'sentinel-enable' 0 516 396 37 $true
   $null=Desktop-Button $body 'Désactiver Sentinel' 'sentinel-disable' 416 516 396 37 $false
   Refresh-DesktopProtection
  }
  'Paramètres' {
   $null=Desktop-Label $body 'Paramètres' 0 0 812 36 19 $true
   Desktop-SettingRow $body 'Mon compte' 'Identité locale et accès à votre espace privé.' 0xE77B 55 'Mon identité' 'Identité'
   Desktop-SettingRow $body 'Préférences' 'Options d''interface avancées non disponibles.' 0xE713 133
   Desktop-SettingRow $body 'Confidentialité' 'Verrouiller les documents et les reçus ouverts.' 0xE72E 211 'Verrouiller' 'session-lock'
   Desktop-SettingRow $body 'Appareils' 'État de la protection locale · pas de registre distant.' 0xE7F4 289 'Protection' 'Protection'
   Desktop-SettingRow $body 'À propos' 'Quantic Sillage Desktop · Alpha privée non certifiée.' 0xE946 367
   Desktop-SettingRow $body 'Outils avancés' 'Diagnostics de laboratoire · terminal possible.' 0xE90F 445 'Diagnostics' 'advanced'
  }
 }
 Save-DesktopPageBounds $script:desktopBody
 Update-DesktopLayout
}
function Initialize-Desktop {
 $form.SuspendLayout()
 $old=@($form.Controls)
 $form.AcceptButton=$null
 $form.CancelButton=$null
 $form.Text='Quantic Sillage'
 $form.AutoScaleMode=[Windows.Forms.AutoScaleMode]::None
 $form.Font=New-Object Drawing.Font('Segoe UI',13,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
 $form.MinimumSize=New-Object Drawing.Size(1000,680)
 $work=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea
 $form.MinimumSize=New-Object Drawing.Size(900,620)
 $form.Size=New-Object Drawing.Size(([Math]::Min(1180,$work.Width)),([Math]::Min(850,$work.Height)))
 $form.BackColor=$script:desktopColors.Canvas
 $form.ForeColor=$script:desktopColors.Ink
 $sidebar=New-Object Windows.Forms.Panel
 $sidebar.Dock='Fill';$sidebar.Margin=New-Object Windows.Forms.Padding(0);$sidebar.BackColor=$script:desktopColors.Navy
 $layout=New-Object Windows.Forms.Panel
 $layout.Margin=New-Object Windows.Forms.Padding(0)
 $sidebar.Dock='None'
 $workspace=New-Object Windows.Forms.Panel
 $workspace.BackColor=$script:desktopColors.Canvas
 $form.Controls.Add($layout);$layout.Controls.Add($sidebar);$layout.Controls.Add($workspace)
 $script:desktopLayout=$layout;$script:desktopSidebar=$sidebar;$script:desktopWorkspace=$workspace
 # Brand mark cropped from the supplied original Quantic Sillage banner.
 # It is embedded in the existing inventory-pinned script, not downloaded.
 $logoBytes=[Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAMAAABg3Am1AAAAkFBMVEVaoNoqkdyp2PCJst7a6frM7vogZrcWadfE8P5ZxOtRdrfs7v4NPJNOgr+ms9i92/Hw9f0NZ9ImtvUSiOoap/QVmPAPdNgNeOQNVbnm9/4MWsYctPUlqe/Y9/3d9v0twfdwx+tLh80NSqoteMzh9/7J5vuNye2z5/kvabdRuOt1p9dtuOiP1/Gs1vLS9v7j7fwNjfcsAAAAMHRSTlP///H/VZ7//9X//w///6+5Av//////////LP///25R//////9Hrv/6///////+jzEKCDpDAAADQ0lEQVR42n2ViZKqMBBFOyCoM29hUSAYFEQ2Bfz/v3vdSQiozOuaGouqe9ILnQs8n5vzjXvL4Nm42+2c8eatBCDwoufVUOddB9B1j3pwPoEznv9t1E7/AMGYOBwORwzGoHc+AHM+3/UgSKviKINBPb4Ck/7mWHshgsMbEIYh9IuageODfN7tA4pXOenDkN2dBaDLsR5Sf1oDQgaVAb4phccbUHoEdBuzHCMqrAlQP1YXXDQhxDSjWU9EswScvdZL4PAGxGEchxE4M5DlweUiiZPuWqo1EUsiimACOLdQH2iA5EIABmNMAXEUx0QMUwZnf9EJiBAs75sxOztNDYzORqkk/IJroKfTL6qgQHRNNo0wGyAyQBT5lgLG/STG/yLPlotws8sokoDvRzIFeLzX5Z+IyvnbdkrC97c+xUAAjkgPlPTnj32++7E/BRCA72wCAmbxD2AsjT4tbwQEJkTPV+6YnWj9Nm3/ItDL03GcIhDN2qXctCaFa3lwy01BohvXAF6kfqqAxPbA9CxwpKvX3rsnfpoilPrJHYHupGrClcj5KmAnqYoXgHYo937IYABAYH+aLtrxhwxwTdNEQpThnB8C7RTHLltv+op6SVDTPD+cJm/5YaxuoiJNaaxej2p1yQ7HerXnq1TTX+sg0LDZJdjuU1+1iQaSpKBdGgGPnoDHx/JxuKoMSFxtud45CrULHVl9WysoVURbyQvUsBkIWf2W4+sXElvZwRWU82UPrQ/JJSIYXmdkQ3tVVbmOvtMNW7pQVN7rHZpA1tjaijYWYOMpdaCA8yM0JqcMpSyKwm3d1niwY39dv7gxsh2bPTGWjqLCXpb2Z7OwyoEtE1AOYth5bbHUsB+Rqt8EJdDvfbSqlw/KRCjHWugLuYqZXZQMrDeAY+Ol9MPY6HGVSQ8uPZf1+xfI43Xpz+1SyFMfvvK9choYyI+0/Ao1gCer06Wp0CJmbCsnEJuJQSYB5b1W4ZKFaoA+axXVud1Gvns3n93n0nstKPG6SJdrJVDG21j6qgGeuiDzTi0oSpL83siefaXfThsGmyfn/PXy386bqqrUix1arD9Cu+Az8HzydbeQwxsKF8M21wQ2GP8BaFftupof/wG9MK5EVFuMbQAAAABJRU5ErkJggg==')
 $stream=New-Object IO.MemoryStream(,$logoBytes)
 try{
  $image=[Drawing.Image]::FromStream($stream)
  try{$logoBitmap=New-Object Drawing.Bitmap($image)}finally{$image.Dispose()}
 }finally{$stream.Dispose()}
 $logoView=New-Object Windows.Forms.PictureBox
 $logoView.Image=$logoBitmap;$logoView.SizeMode='Zoom';$logoView.SetBounds(18,24,40,40)
 $logoView.BackColor=$script:desktopColors.Navy
 $sidebar.Controls.Add($logoView)
 $form.Add_Disposed(({$logoView.Image.Dispose()}).GetNewClosure())
 $brand=Desktop-Label $sidebar ('Quantic'+[Environment]::NewLine+'Sillage') 66 17 108 48 13 $true
 $brand.ForeColor=[Drawing.Color]::White
 $tagline=Desktop-Label $sidebar '' 20 70 148 20 9
 $tagline.ForeColor=[Drawing.Color]::FromArgb(170,192,214)
 $script:desktopPages=@('Accueil','Identité','Messagerie','Paiements','Coffre-fort','Protection','Paramètres')
 $script:desktopNav=@()
 $y=95
 foreach($page in $script:desktopPages){
  $b=Desktop-Button $sidebar $page $page 12 $y 176 43 $false
  $b.TextAlign='MiddleLeft';$b.Padding=New-Object Windows.Forms.Padding(43,0,0,0)
  $b.AccessibleName=$page
  $b.Add_Paint({param($sender,$e) $g=@{Accueil=0xE80F;'Identité'=0xE77B;Messagerie=0xE715;Paiements=0xE8C7;'Coffre-fort'=0xE72E;Protection=0xEA18;'Paramètres'=0xE713};$font=New-Object Drawing.Font('Segoe MDL2 Assets',17,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel);try{[Windows.Forms.TextRenderer]::DrawText($e.Graphics,([string][char]$g[[string]$sender.Tag]),$font,(New-Object Drawing.Rectangle(13,0,24,$sender.Height)),[Drawing.Color]::White,([Windows.Forms.TextFormatFlags]::HorizontalCenter -bor [Windows.Forms.TextFormatFlags]::VerticalCenter))}finally{$font.Dispose()}})
  $b.FlatAppearance.BorderSize=0;$b.ForeColor=[Drawing.Color]::White
  $b.FlatAppearance.MouseOverBackColor=[Drawing.Color]::FromArgb(28,66,105);$b.FlatAppearance.MouseDownBackColor=[Drawing.Color]::FromArgb(35,77,118)
  $script:desktopNav+= $b;$y+=49
  if($page -eq 'Protection'){$y+=24}
 }
 $alpha=Desktop-Label $sidebar 'ÉDITION ALPHA PRIVÉE' 23 526 150 44 9
 $script:desktopAlpha=$alpha
 $alpha.ForeColor=[Drawing.Color]::FromArgb(170,192,214)
 $header=New-Object Windows.Forms.Panel
 $header.Dock='None';$header.Margin=New-Object Windows.Forms.Padding(0);$header.BackColor=$script:desktopColors.White
 $workspace.Controls.Add($header)
 $script:desktopHeader=$header
 $script:desktopTitle=Desktop-Label $header 'Accueil' 28 9 400 30 15 $true
 $state=Desktop-Label $header 'Espace local · Édition de test' 29 39 400 21 9
 $state.ForeColor=$script:desktopColors.Muted
 $script:desktopSessionLabel=Desktop-Label $header 'Espace privé fermé' 460 3 280 21 9
 $script:desktopSessionLabel.TextAlign='MiddleRight'
 $script:desktopSessionOpen=Desktop-Button $header 'Ouvrir' 'session-open' 460 27 125 29 $true
 $script:desktopSessionLock=Desktop-Button $header 'Verrouiller' 'session-lock' 595 27 145 29 $false
 $script:desktopState=$state
 $header.Add_SizeChanged({
  $x=[Math]::Max(4,$script:desktopHeader.ClientSize.Width-308)
  $script:desktopSessionLabel.Left=$x;$script:desktopSessionOpen.Left=$x;$script:desktopSessionLock.Left=$x+135
  $script:desktopTitle.Width=[Math]::Max(1,$x-46);$script:desktopState.Width=[Math]::Max(1,$x-46)
 })
 # Preserve status of the existing managed carrier, without claiming the
 # transport is connected to a remote correspondent.
 $workspace.Controls.Add($notice);$notice.Dock='None';$notice.Margin=New-Object Windows.Forms.Padding(0);$notice.Height=40
 $script:desktopFooter=$notice
 $notice.Text='Identités de test uniquement. Aucun compte réel ni migration.'
 $notice.ForeColor=$script:desktopColors.Muted;$notice.BackColor=$script:desktopColors.White
 $notice.Padding=New-Object Windows.Forms.Padding(28,9,12,0)
 $scroll=New-Object Windows.Forms.Panel
 $scroll.Dock='None';$scroll.Margin=New-Object Windows.Forms.Padding(0);$scroll.AutoScroll=$true;$workspace.Controls.Add($scroll)
 $script:desktopScroll=$scroll
 $script:desktopBody=New-Object Windows.Forms.Panel
 $script:desktopBody.SetBounds(28,20,824,650);$scroll.Controls.Add($script:desktopBody)
 $script:desktopAdvanced=New-Object Windows.Forms.Panel
 $script:desktopAdvanced.SetBounds(28,20,760,870);$script:desktopAdvanced.Visible=$false
 $scroll.Controls.Add($script:desktopAdvanced)
 $form.Add_ClientSizeChanged({Update-DesktopLayout})
 foreach($c in $old){
  if($c -eq $notice){continue}
  $c.Parent=$script:desktopAdvanced
  $c.ForeColor=$script:desktopColors.Ink
  if($c -is [Windows.Forms.Button]){$c.BackColor=$script:desktopColors.White}
 }
 $heading.Text='Outils avancés'
 Show-DesktopPage 'Accueil'
 $form.ResumeLayout($true)
 $layout.PerformLayout();$workspace.PerformLayout()
 Update-DesktopLayout
}
function Save-DesktopPageBounds($parent){
 foreach($c in $parent.Controls){
  $script:desktopPageBounds[$c]=$c.Bounds
  if($c.Controls.Count -gt 0){Save-DesktopPageBounds $c}
 }
}
function Resize-DesktopPage($parent,[double]$scale){
 foreach($c in $parent.Controls){
  $r=$script:desktopPageBounds[$c]
  if($null -ne $r){
   $c.SetBounds([int]($r.X*$scale),$r.Y,[Math]::Max(1,[int]($r.Width*$scale)),$r.Height)
   if($c -is [Windows.Forms.ListView] -and $c.Columns.Count -eq 2){$c.Columns[0].Width=[int]($c.ClientSize.Width*0.72);$c.Columns[1].Width=[Math]::Max(40,$c.ClientSize.Width-$c.Columns[0].Width-4)}
   if($c.Controls.Count -gt 0){Resize-DesktopPage $c $scale}
  }
 }
}
function Update-DesktopLayout {
 if($script:desktopLayoutBusy -or -not $script:desktopBody -or -not $script:desktopScroll){return}
 $script:desktopLayoutBusy=$true
 try{
  $fw=[Math]::Min($form.ClientSize.Width,$form.Width-16);$fh=[Math]::Min($form.ClientSize.Height,$form.Height-39)
  if($fw -lt 300 -or $fh -lt 180){return}
  $side=if($fw -lt 1100){184}else{206};$ww=$fw-$side
  $script:desktopLayout.SetBounds(0,0,$fw,$fh)
  $script:desktopSidebar.SetBounds(0,0,$side,$fh)
  $script:desktopAlpha.Top=[Math]::Max(515,$fh-74)
  foreach($b in $script:desktopNav){$b.Width=$side-24}
  $script:desktopWorkspace.SetBounds($side,0,$ww,$fh)
  $script:desktopHeader.SetBounds(0,0,$ww,66)
  $script:desktopFooter.SetBounds(0,$fh-40,$ww,40)
  $scroll=$script:desktopScroll
  $scroll.SetBounds(0,66,$ww,$fh-106)
  # Fit the complete page into the actual client width, including room
  # for a vertical scrollbar. Never infer layout from requested window size.
  $width=[Math]::Min(824,[Math]::Max(540,$ww-52))
  $x=[Math]::Max(16,[int](($ww-$width-16)/2))
  $pageHeight=0
  foreach($c in $script:desktopBody.Controls){$pageHeight=[Math]::Max($pageHeight,$c.Bottom)}
  $contentHeight=if($script:desktopCurrent -eq 'Paramètres' -and $script:desktopAdvanced.Visible){910}else{[Math]::Max(100,$pageHeight+40)}
  $scroll.AutoScrollMinSize=New-Object Drawing.Size(0,$contentHeight)
  $position=$scroll.AutoScrollPosition
  $script:desktopBody.SetBounds($x,(20+$position.Y),$width,([Math]::Max(80,$pageHeight+2)))
  $script:desktopAdvanced.SetBounds(16,(20+$position.Y),760,870)
  if($script:desktopPageBounds){Resize-DesktopPage $script:desktopBody ($width/824.0)}
  $hx=[Math]::Max(4,$ww-308)
  $script:desktopSessionLabel.Left=$hx;$script:desktopSessionOpen.Left=$hx;$script:desktopSessionLock.Left=$hx+135
  $script:desktopTitle.Width=[Math]::Max(1,$hx-46);$script:desktopState.Width=[Math]::Max(1,$hx-46)
 }finally{$script:desktopLayoutBusy=$false}
}
$module.SelectedIndex=0
if ($SelfTest) {
 try {
  if($actions.Count -ne 34 -or $script:shownActions[0].Id -ne 'ComposeDraft' -or $inputName.Visible -or $outputName.Visible -or $createIdentity.Text -notmatch 'identite de test' -or $openIdentity.Text -notmatch 'coffre de test' -or $contactGuide.Text -notmatch 'contact de test'){throw "Dashboard initialization failed"}
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
  Test-DesktopSentinelReadOnly
  Initialize-Desktop
  foreach($page in $script:desktopPages){Show-DesktopPage $page;if($script:desktopTitle.Text -ne $page -or $script:desktopBody.Controls.Count -lt 2){throw "Desktop page incomplete: $page"}}
  Show-DesktopPage "Accueil"
  Show-DesktopPage 'Messagerie'
  $null=$script:desktopMailList.Items.Add('synthetic test subject')
  $script:desktopMailBody.Text='synthetic test body'
  $script:desktopMailIDs=@('synthetic')
  Close-DesktopDocumentSession
  if($script:desktopMailList.Items.Count -ne 0 -or $script:desktopMailBody.Text -ne '' -or $script:desktopMailIDs.Count -ne 0){throw 'Private receipt content remains after lock'}
  Show-DesktopPage 'Identité'
  $script:desktopIdentityAddress.Text='synthetic test address'
  Close-DesktopDocumentSession
  if($script:desktopIdentityAddress.Text -eq 'synthetic test address'){throw 'Private identity remains after lock'}
  Show-DesktopPage 'Accueil'
  # Exercise rendered geometry, not just existence of controls.
  $form.Show()
  try{
   foreach($size in @(@(1160,810),@(1000,680),@(1440,900))){
    $form.ClientSize=New-Object Drawing.Size($size[0],$size[1])
    $form.PerformLayout();$script:desktopLayout.PerformLayout();$script:desktopWorkspace.PerformLayout()
    [Windows.Forms.Application]::DoEvents()
    Update-DesktopLayout
    if($script:desktopLayout.Right -gt $form.ClientSize.Width -or $script:desktopLayout.Bottom -gt $form.ClientSize.Height){throw 'Root outside real client area'}
    if($script:desktopWorkspace.Right -gt $script:desktopLayout.ClientSize.Width){throw 'Workspace clipped'}
    if($script:desktopWorkspace.Left -lt $script:desktopSidebar.Right){throw 'Navigation overlays workspace'}
    if($script:desktopScroll.Top -lt $script:desktopHeader.Bottom){throw 'Header overlays content'}
    if($notice.Top -lt $script:desktopScroll.Bottom){throw 'Footer overlays content'}
    if($script:desktopTitle.Right -gt $script:desktopSessionLabel.Left){throw 'Header labels overlap'}
    if($script:desktopSessionLock.Right -gt $script:desktopHeader.ClientSize.Width){throw 'Header controls clipped'}
    if($script:desktopBody.Left -lt 0 -or $script:desktopBody.Right -gt $script:desktopScroll.ClientSize.Width){throw 'Body outside visible width'}
   }
   $area=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea
   $form.Size=New-Object Drawing.Size(([Math]::Min(1160,$area.Width)),([Math]::Min(810,$area.Height)))
   $form.PerformLayout();[Windows.Forms.Application]::DoEvents()
   Update-DesktopLayout
   $form.Refresh()
   if($env:QUANTIC_UI_TEST_CAPTURE -and $env:RUNNER_TEMP){
    $capture=Join-Path $env:RUNNER_TEMP 'quantic-ui-captures'
    [void][IO.Directory]::CreateDirectory($capture)
    $index=0
    foreach($page in $script:desktopPages){
     Show-DesktopPage $page
     [Windows.Forms.Application]::DoEvents()
     $form.Refresh()
     Update-DesktopLayout
     $bmp=New-Object Drawing.Bitmap($script:desktopLayout.Width,$script:desktopLayout.Height)
     try{
      $script:desktopLayout.DrawToBitmap($bmp,(New-Object Drawing.Rectangle(0,0,$bmp.Width,$bmp.Height)))
      $bmp.Save((Join-Path $capture ('{0:D2}.png' -f $index)),[Drawing.Imaging.ImageFormat]::Png)
     }finally{$bmp.Dispose()}
     $index++
    }
   }
  }finally{$form.Hide()}
  Write-Output "Unified desktop: seven native pages, non-overlapping geometry at three sizes and existing operation mapping verified"
 }finally{$form.Dispose()}
 exit 0
}
Initialize-Desktop
function Quote-AdvancedArg([string]$Value){
 if($Value.Contains('"') -or $Value.Contains([char]10) -or $Value.Contains([char]13)){throw 'Argument advanced non autorise'}
 return '"'+$Value+'"'
}
$form.Add_Shown({Start-ManagedCarrier})
$transportTimer=New-Object Windows.Forms.Timer;$transportTimer.Interval=1000
$transportTimer.Add_Tick({if($script:managedCarrier -and $script:managedCarrier.HasExited){Stop-ManagedCarrier;$notice.Text='Transport arrete | aucun renvoi automatique.'}})
$transportTimer.Start()
$protectionTimer=New-Object Windows.Forms.Timer;$protectionTimer.Interval=2000
$protectionTimer.Add_Tick({Refresh-DesktopProtection;if($script:desktopDocumentProcess -and $script:desktopDocumentProcess.HasExited){Close-DesktopDocumentSession}});$protectionTimer.Start()
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
}finally{Close-DesktopDocumentSession;$protectionTimer.Stop();$protectionTimer.Dispose();$transportTimer.Stop();$transportTimer.Dispose();Stop-ManagedCarrier;$form.Dispose()}
