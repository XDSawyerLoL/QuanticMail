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
  }elseif($r.status -ceq 'hybrid-session-required' -and $r.directory -cmatch ('^'+[Regex]::Escape($parent)+'\\quantic-enroll-[0-9a-f]{16}{$script:managedAttempted=$false}
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
$contactGuide.Add_Click({
 $contactGuide.Enabled=$false
 try{Show-SyntheticContactGuide}catch{
  [Windows.Forms.MessageBox]::Show('Carnet de laboratoire indisponible. Creer ou ouvrir d abord un coffre de test.','Contact non configure','OK','Warning')|Out-Null
 }finally{$contactGuide.Enabled=$true}
})
$contactNotice=New-Object Windows.Forms.Label
$contactNotice.Text='Les invitations ne sont pas des contacts approuves par les autorites.'
$contactNotice.SetBounds(24,750,700,30)
$form.Controls.Add($contactNotice)
$script:latestSyntheticDirectory=$null
$createIdentity.Add_Click({
 $createIdentity.Enabled=$false
 try{
  $parent=[Environment]::GetFolderPath('LocalApplicationData')
  $r=Invoke-LocalIdentity $true $parent
  $script:latestSyntheticDirectory=$r.dir
  [Windows.Forms.MessageBox]::Show(('Coffre prive cree : '+$r.address+[Environment]::NewLine+'Cliquez sur Ouvrir mon coffre pour tester les deux secrets.'+[Environment]::NewLine+'Aucune inscription distante ou contact cree.'),'Identite fictive creee','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Creation non confirmee. Un dossier partiel peut subsister : aucune suppression ou reutilisation automatique. Disque NTFS et chemin Windows compatible requis.','Creation refusee','OK','Warning')|Out-Null
 }finally{$createIdentity.Enabled=$true}
})
$openIdentity.Add_Click({
 $openIdentity.Enabled=$false
 try{
  $folder=Choose-SyntheticDirectory
  if(-not $folder){return}
  $r=Invoke-LocalIdentity $false $folder
  [Windows.Forms.MessageBox]::Show(('Cles classiques et post-quantiques deverrouillees localement : '+$r.address+[Environment]::NewLine+'Aucune session distante : contacts, autorites et relais restent a configurer pour la messagerie.'),'Coffre de test verifie','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Deverrouillage refuse : secrets ou fichiers non verifies. Aucune session ni message envoye.','Coffre verrouille','OK','Warning')|Out-Null
 }finally{$openIdentity.Enabled=$true}
})
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
$run.Add_Click({
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
})
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
  Write-Output "Dashboard controls and operation mapping verified"
 }finally{$form.Dispose()}
 exit 0
}
function Quote-AdvancedArg([string]$Value){
 if($Value.Contains('"') -or $Value.Contains([char]10) -or $Value.Contains([char]13)){throw 'Argument advanced non autorise'}
 return '"'+$Value+'"'
}
$form.Add_Shown({Start-ManagedCarrier})
$transportTimer=New-Object Windows.Forms.Timer;$transportTimer.Interval=1000
$transportTimer.Add_Tick({if($script:managedCarrier -and $script:managedCarrier.HasExited){Stop-ManagedCarrier;$notice.Text='Transport arrete | aucun renvoi automatique.'}})
$transportTimer.Start()
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
}finally{$transportTimer.Stop();$transportTimer.Dispose();Stop-ManagedCarrier;$form.Dispose()}
)){
   $script:configuredEnrollment=[string]$r.directory
   $notice.Text='Profil hybride importe | ouverture de session commune requise. Aucun ancien transport lance.'
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
$contactGuide.Add_Click({
 $contactGuide.Enabled=$false
 try{Show-SyntheticContactGuide}catch{
  [Windows.Forms.MessageBox]::Show('Carnet de laboratoire indisponible. Creer ou ouvrir d abord un coffre de test.','Contact non configure','OK','Warning')|Out-Null
 }finally{$contactGuide.Enabled=$true}
})
$contactNotice=New-Object Windows.Forms.Label
$contactNotice.Text='Les invitations ne sont pas des contacts approuves par les autorites.'
$contactNotice.SetBounds(24,750,700,30)
$form.Controls.Add($contactNotice)
$script:latestSyntheticDirectory=$null
$createIdentity.Add_Click({
 $createIdentity.Enabled=$false
 try{
  $parent=[Environment]::GetFolderPath('LocalApplicationData')
  $r=Invoke-LocalIdentity $true $parent
  $script:latestSyntheticDirectory=$r.dir
  [Windows.Forms.MessageBox]::Show(('Coffre prive cree : '+$r.address+[Environment]::NewLine+'Cliquez sur Ouvrir mon coffre pour tester les deux secrets.'+[Environment]::NewLine+'Aucune inscription distante ou contact cree.'),'Identite fictive creee','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Creation non confirmee. Un dossier partiel peut subsister : aucune suppression ou reutilisation automatique. Disque NTFS et chemin Windows compatible requis.','Creation refusee','OK','Warning')|Out-Null
 }finally{$createIdentity.Enabled=$true}
})
$openIdentity.Add_Click({
 $openIdentity.Enabled=$false
 try{
  $folder=Choose-SyntheticDirectory
  if(-not $folder){return}
  $r=Invoke-LocalIdentity $false $folder
  [Windows.Forms.MessageBox]::Show(('Cles classiques et post-quantiques deverrouillees localement : '+$r.address+[Environment]::NewLine+'Aucune session distante : contacts, autorites et relais restent a configurer pour la messagerie.'),'Coffre de test verifie','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Deverrouillage refuse : secrets ou fichiers non verifies. Aucune session ni message envoye.','Coffre verrouille','OK','Warning')|Out-Null
 }finally{$openIdentity.Enabled=$true}
})
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
$run.Add_Click({
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
})
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
  Write-Output "Dashboard controls and operation mapping verified"
 }finally{$form.Dispose()}
 exit 0
}
function Quote-AdvancedArg([string]$Value){
 if($Value.Contains('"') -or $Value.Contains([char]10) -or $Value.Contains([char]13)){throw 'Argument advanced non autorise'}
 return '"'+$Value+'"'
}
$form.Add_Shown({Start-ManagedCarrier})
$transportTimer=New-Object Windows.Forms.Timer;$transportTimer.Interval=1000
$transportTimer.Add_Tick({if($script:managedCarrier -and $script:managedCarrier.HasExited){Stop-ManagedCarrier;$notice.Text='Transport arrete | aucun renvoi automatique.'}})
$transportTimer.Start()
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
}finally{$transportTimer.Stop();$transportTimer.Dispose();Stop-ManagedCarrier;$form.Dispose()}
