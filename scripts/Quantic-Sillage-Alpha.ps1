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
  if($actions.Count -ne 30 -or $script:shownActions[0].Id -ne 'ComposeDraft' -or $inputName.Visible -or $outputName.Visible -or $createIdentity.Text -notmatch 'identite de test' -or $openIdentity.Text -notmatch 'coffre de test' -or $contactGuide.Text -notmatch 'contact de test'){throw "Dashboard initialization failed"}
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
