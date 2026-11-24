# Native GUI-only laboratory mailbox. No production account enrollment.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$TrustedBinarySha256,
 [switch]$SelfTest
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$root=$PSScriptRoot
$node=Join-Path $root 'runtime\node.exe'
$vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
$helper=Join-Path $root 'scripts\native-windows-compose-draft.mjs'
$script:privateDirectory=$null
function Invoke-Composer([string]$Directory,[string]$Payload,[bool]$List,[bool]$Send=$false,[bool]$StatusOnly=$false,[string]$ReceiveMode=''){
 if($ReceiveMode -notin @('','receive','recover-receive','confirm-receipt','receipt-list','receipt-read','provision','readiness')){throw 'Mode reception invalide.'}
 if($ReceiveMode -and ($List -or $Send -or $StatusOnly)){throw 'Modes incompatibles.'}
 if($Directory -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Dossier prive non valide.'}
 foreach($part in $Directory.Substring(3).Split('\')){
  if($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'Chemin ambigu.'}
 }
 $psi=New-Object System.Diagnostics.ProcessStartInfo
 $psi.FileName=$node
 $psi.Arguments= ('"{0}" "{1}" {2} "{3}"{4}' -f $helper,$vault,$TrustedBinarySha256.ToLowerInvariant(),$Directory,$(if($List){' --list'}elseif($Send){' --send'}elseif($StatusOnly){' --status'}elseif($ReceiveMode){' --'+$ReceiveMode}else{''}))
 $psi.WorkingDirectory=$root
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.StandardOutputEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.StandardErrorEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 if($script:operationBusy){throw 'Une operation est deja en cours.'}
 $script:operationBusy=$true
 $controls=@($choose,$save,$send,$cancel,$statusButton,$receiveButton,$recoverButton,$confirmButton,$newVault,$connectionButton)
 foreach($control in $controls){$control.Enabled=$false}
 $form.ControlBox=$false
 $status.Text='Operation locale en cours. Consultez les demandes du coffre Windows.'
 $p=New-Object System.Diagnostics.Process
 $p.StartInfo=$psi
 try{
  if(-not $p.Start()){throw 'Demarrage refuse.'}
  if(-not $List){
   $bytes=[System.Text.Encoding]::UTF8.GetBytes($Payload)
   try{$p.StandardInput.BaseStream.Write($bytes,0,$bytes.Length)}finally{[Array]::Clear($bytes,0,$bytes.Length)}
  }
  $p.StandardInput.BaseStream.Close()
  $readOut=$p.StandardOutput.ReadToEndAsync()
  $readErr=$p.StandardError.ReadToEndAsync()
  $maximum=if($ReceiveMode -eq 'receipt-list'){180000}elseif($ReceiveMode -eq 'provision'){320000}elseif($Send -or $ReceiveMode){300000}else{15000}
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while(-not $p.WaitForExit(100)){
   [Windows.Forms.Application]::DoEvents()
   if($clock.ElapsedMilliseconds -gt $maximum){
    $p.Kill()
    throw 'Le coffre ne repond plus. Ne recommencez pas un envoi incertain.'
   }
  }
  if($p.ExitCode -ne 0){throw 'Operation privee refusee.'}
  $answer=$readOut.GetAwaiter().GetResult()
  $null=$readErr.GetAwaiter().GetResult()
  if($answer.Length -lt 1 -or $answer.Length -gt 65536){throw 'Reponse privee invalide.'}
  return ConvertFrom-Json -InputObject $answer
 }finally{
  $p.Dispose()
  foreach($control in $controls){$control.Enabled=$true}
  $form.ControlBox=$true
  $status.Text=''
  $script:operationBusy=$false
 }
}
$form=New-Object Windows.Forms.Form
$form.Text='Quantic Mail | Messagerie de test'
$form.StartPosition='CenterParent';$form.ClientSize=New-Object Drawing.Size(710,690)
$form.BackColor=[Drawing.Color]::FromArgb(19,25,35);$form.ForeColor=[Drawing.Color]::WhiteSmoke
$form.Font=New-Object Drawing.Font('Segoe UI',10)
function Label-At([string]$Text,[int]$Y){
 $l=New-Object Windows.Forms.Label;$l.Text=$Text;$l.SetBounds(24,$Y,660,24);$form.Controls.Add($l)
}
$heading=New-Object Windows.Forms.Label;$heading.Text='MESSAGERIE DE TEST';$heading.SetBounds(24,18,260,28);$form.Controls.Add($heading)
$newVault=New-Object Windows.Forms.Button;$newVault.Text='Creer mon coffre';$newVault.SetBounds(293,14,190,32);$form.Controls.Add($newVault)
$connectionButton=New-Object Windows.Forms.Button;$connectionButton.Text='Verifier la connexion';$connectionButton.SetBounds(490,14,190,32);$form.Controls.Add($connectionButton)
Label-At 'TEST : brouillon chiffre par Windows DPAPI (utilisateur local). Pas de donnees reelles.' 55
$vaultLabel=New-Object Windows.Forms.Label;$vaultLabel.Text='Mon coffre de test';$vaultLabel.SetBounds(24,98,470,24);$form.Controls.Add($vaultLabel)
$chosen=New-Object Windows.Forms.TextBox;$chosen.SetBounds(24,128,464,29);$chosen.ReadOnly=$true;$form.Controls.Add($chosen)
$choose=New-Object Windows.Forms.Button;$choose.Text='Choisir mon coffre';$choose.SetBounds(500,125,180,35);$form.Controls.Add($choose)
$statusButton=New-Object Windows.Forms.Button
$statusButton.Text='Mes essais locaux'
$statusButton.SetBounds(518,91,163,30)
$form.Controls.Add($statusButton)
Label-At 'Destinataire dans mon carnet local' 178
$recipient=New-Object Windows.Forms.ComboBox;$recipient.DropDownStyle='DropDownList'
$recipient.SetBounds(24,208,656,30);$form.Controls.Add($recipient)
Label-At 'Objet' 254
$subject=New-Object Windows.Forms.TextBox;$subject.SetBounds(24,284,656,30);$subject.MaxLength=160;$form.Controls.Add($subject)
$status=New-Object Windows.Forms.Label
$status.ForeColor=[Drawing.Color]::Khaki
$status.SetBounds(24,534,655,20)
$form.Controls.Add($status)
$script:operationBusy=$false
Label-At 'Message' 332
$body=New-Object Windows.Forms.TextBox;$body.Multiline=$true;$body.ScrollBars='Vertical'
$body.MaxLength=7500;$body.SetBounds(24,361,656,162);$form.Controls.Add($body)
$save=New-Object Windows.Forms.Button;$save.Text='Enregistrer mon brouillon';$save.SetBounds(24,558,240,43)
$save.BackColor=[Drawing.Color]::FromArgb(196,223,244);$save.ForeColor=[Drawing.Color]::Black;$form.Controls.Add($save)
$cancel=New-Object Windows.Forms.Button;$cancel.Text='Fermer';$cancel.SetBounds(495,558,185,43);$form.Controls.Add($cancel)
$send=New-Object Windows.Forms.Button
$send.Text='Chiffrer et deposer (test)'
$send.SetBounds(276,558,208,43)
$form.Controls.Add($send)
$receiveButton=New-Object Windows.Forms.Button;$receiveButton.Text='Recevoir un message';$receiveButton.SetBounds(24,617,210,43);$form.Controls.Add($receiveButton)
$recoverButton=New-Object Windows.Forms.Button;$recoverButton.Text='Reprendre reception';$recoverButton.SetBounds(247,617,210,43);$form.Controls.Add($recoverButton)
$confirmButton=New-Object Windows.Forms.Button;$confirmButton.Text='Messages recus';$confirmButton.SetBounds(470,617,210,43);$form.Controls.Add($confirmButton)
function Invoke-Receive([string]$Mode,[string]$Receipt){
 try{
  if(-not $script:privateDirectory){throw 'Choisissez un coffre de test.'}
  if($Mode -eq 'recover-receive'){
   $decision=[Windows.Forms.MessageBox]::Show('Reprendre une ouverture interrompue sans effacer les fichiers existants ? Si un recu existe deja, utilisez plutot Confirmer un recu.','Reprise explicite','YesNo','Warning')
   if($decision -ne [Windows.Forms.DialogResult]::Yes){return}
  }
  $result=Invoke-Composer $script:privateDirectory $Receipt $false $false $false $Mode
  if($result.liveAccountEnrollmentAuthorized -ne $false -or $result.noAutomaticRetry -ne $true){throw 'Resultat prive inattendu.'}
  switch($result.status){
   'empty'{[Windows.Forms.MessageBox]::Show('Aucun message en attente.','Reception','OK','Information')|Out-Null}
   'cancelled'{[Windows.Forms.MessageBox]::Show('Reception annulee.','Reception','OK','Information')|Out-Null}
   'acknowledged'{
    if($result.receiptFile -cnotmatch '^receipt-[a-z0-9-]{1,48}\.json$' -or $result.display -isnot [string]){throw 'Recu invalide.'}
    Show-ReceivedText 'Recu chiffre enregistre et confirmation du relais de test obtenue.' $result
   }
   'receipt-saved-ack-unknown'{
    if($result.receiptFile -cnotmatch '^receipt-[a-z0-9-]{1,48}\.json$' -or $result.display -isnot [string]){throw 'Recu invalide.'}
    Show-ReceivedText 'Recu chiffre authentifie conserve. Confirmation inconnue. Utilisez Confirmer un recu; ne relancez pas automatiquement la reception.' $result
   }
   default{throw 'Etat inconnu.'}
  }
 }catch{
  [Windows.Forms.MessageBox]::Show('Reception ou confirmation non validee. Conservez les fichiers du coffre. Si un recu existe, utilisez Confirmer un recu; sinon choisissez explicitement Reprendre reception.','Resultat incertain','OK','Warning')|Out-Null
 }
}
function Show-ReceivedText([string]$Info,$Result){
 $dialog=New-Object Windows.Forms.Form
 $dialog.Text='Quantic Mail | Message authentifie'
 $dialog.StartPosition='CenterParent';$dialog.ClientSize=New-Object Drawing.Size(620,510)
 $notice=New-Object Windows.Forms.Label;$notice.Text=$Info;$notice.SetBounds(18,15,584,70);$dialog.Controls.Add($notice)
 $message=New-Object Windows.Forms.TextBox;$message.Multiline=$true;$message.ReadOnly=$true;$message.ScrollBars='Vertical';$message.SetBounds(18,90,584,340);$message.Text=$Result.display;$dialog.Controls.Add($message)
 $fileLabel=New-Object Windows.Forms.Label;$fileLabel.Text='Copie locale chiffree et authentifiee';$fileLabel.SetBounds(18,437,584,25);$dialog.Controls.Add($fileLabel)
 $close=New-Object Windows.Forms.Button;$close.Text='Fermer';$close.SetBounds(452,464,150,30);$close.Add_Click({$dialog.Close()});$dialog.Controls.Add($close)
 try{[void]$dialog.ShowDialog($form)}finally{$dialog.Dispose()}
}
$receiveButton.Add_Click({Invoke-Receive 'receive' ''})
$recoverButton.Add_Click({Invoke-Receive 'recover-receive' ''})
$confirmButton.Add_Click({
 if(-not $script:privateDirectory){[Windows.Forms.MessageBox]::Show('Choisissez un coffre de test.','Messages recus','OK','Warning')|Out-Null;return}
 $dialog=$null
 try{
  $items=Invoke-Composer $script:privateDirectory '' $false $false $false 'receipt-list'
  if($items.status -cne 'authenticated-local-receipts' -or $items.deliveryVerified -ne $false -or @($items.items).Count -gt 64){throw 'Inventaire invalide'}
  $rows=@($items.items)
  foreach($item in $rows){
   if($item.file -cnotmatch '^receipt-[a-z0-9-]{1,48}\.json$' -or $item.subject -isnot [string] -or $item.subject.Length -gt 240){throw 'Message invalide'}
  }
  if($rows.Count -eq 0){
   [Windows.Forms.MessageBox]::Show(('Aucun message local authentifie. Messages refuses : '+$items.refused),'Messages recus','OK','Information')|Out-Null;return
  }
  $dialog=New-Object Windows.Forms.Form
  $dialog.Text='Quantic Mail | Messages recus';$dialog.StartPosition='CenterParent';$dialog.ClientSize=New-Object Drawing.Size(650,500)
  $note=New-Object Windows.Forms.Label;$note.SetBounds(16,12,618,45)
  $note.Text=('Copies locales authentifiees. Confirmation distante non verifiee. Refuses : '+$items.refused+' ; non listes : '+$items.remaining)
  $dialog.Controls.Add($note)
  $list=New-Object Windows.Forms.ListBox;$list.SetBounds(16,62,618,160);$dialog.Controls.Add($list)
  foreach($item in $rows){[void]$list.Items.Add($item.subject)}
  $view=New-Object Windows.Forms.TextBox;$view.Multiline=$true;$view.ReadOnly=$true;$view.ScrollBars='Vertical';$view.SetBounds(16,230,618,195);$dialog.Controls.Add($view)
  $open=New-Object Windows.Forms.Button;$open.Text='Lire le message';$open.SetBounds(16,444,180,38);$dialog.Controls.Add($open)
  $ack=New-Object Windows.Forms.Button;$ack.Text='Confirmer la reception';$ack.SetBounds(206,444,238,38);$ack.Enabled=$false;$dialog.Controls.Add($ack)
  $close=New-Object Windows.Forms.Button;$close.Text='Fermer';$close.SetBounds(454,444,180,38);$dialog.Controls.Add($close)
  $selected=@{file=$null;busy=$false;confirm=$null}
  $list.Add_SelectedIndexChanged({$selected.file=$null;$ack.Enabled=$false;$view.Clear()})
  $open.Add_Click({
   if($selected.busy -or $list.SelectedIndex -lt 0){return}
   $selected.busy=$true;$list.Enabled=$false;$open.Enabled=$false;$close.Enabled=$false;$dialog.ControlBox=$false;$ack.Enabled=$false
   try{
    $file=$rows[$list.SelectedIndex].file
    $message=Invoke-Composer $script:privateDirectory $file $false $false $false 'receipt-read'
    if($message.status -cne 'authenticated-local-receipt' -or $message.receiptFile -cne $file -or $message.display -isnot [string] -or $message.deliveryVerified -ne $false){throw 'Lecture invalide'}
    $view.Text=$message.display;$selected.file=$file;$ack.Enabled=$true
   }catch{$view.Text='Lecture non confirmee. Aucun message modifie.';$selected.file=$null}
   finally{$selected.busy=$false;$list.Enabled=$true;$open.Enabled=$true;$close.Enabled=$true;$dialog.ControlBox=$true}
  })
  $ack.Add_Click({
   if($selected.busy -or -not $selected.file){return}
   $selected.confirm=$selected.file;$dialog.Close()
  })
  $close.Add_Click({$dialog.Close()})
  $list.SelectedIndex=0
  [void]$dialog.ShowDialog($form)
  $file=$selected.confirm
  $dialog.Dispose();$dialog=$null
  if($file){Invoke-Receive 'confirm-receipt' $file}
 }catch{[Windows.Forms.MessageBox]::Show('Les messages locaux ne sont pas disponibles. Aucun renvoi automatique.','Messages recus','OK','Warning')|Out-Null}
 finally{if($dialog){$dialog.Dispose()}}
})

# The addresses and public pins are independently issued by the lab operator.
# No passwords are entered into WinForms or passed to Node.
Add-Type -AssemblyName Microsoft.VisualBasic
function Pick-SetupFolder([string]$Description){
 $f=New-Object Windows.Forms.FolderBrowserDialog
 $f.Description=$Description
 try{if($f.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK){return $f.SelectedPath}}finally{$f.Dispose()}
}
function Request-SetupText([string]$Prompt,[string]$Title){
 return [Microsoft.VisualBasic.Interaction]::InputBox($Prompt,$Title,'')
}
$newVault.Add_Click({
 try{
  $notice=[Windows.Forms.MessageBox]::Show('Creer un nouveau coffre fictif sur ce PC. Vous devez disposer de l adresse et de l empreinte du quorum transmises par le responsable du laboratoire. Les phrases secretes seront saisies uniquement dans des fenetres Windows protegees. Ce coffre ne sera pas encore connecte. Continuer ?','Nouveau coffre','YesNo','Information')
  if($notice -ne [Windows.Forms.DialogResult]::Yes){return}
  $parent=Pick-SetupFolder 'Choisissez ou conserver le nouveau coffre local.'
  if(-not $parent){return}
  $address=Request-SetupText 'Adresse de test attribuee par le responsable du laboratoire.' 'Adresse de test'
  if(-not $address){return}
  if($address -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$'){throw 'Adresse invalide.'}
  $pin=Request-SetupText 'Empreinte SHA256 du quorum obtenue par un canal de confiance independant.' 'Verification du quorum'
  if(-not $pin){return}
  $pin=$pin.Trim().ToLowerInvariant()
  if($pin -cnotmatch '^[a-f0-9]{64}$' -or $pin -match '^0+$'){throw 'Empreinte invalide.'}
  $dir=Join-Path $parent ('Quantic-'+[Guid]::NewGuid().ToString('N').Substring(0,12))
  $payload=ConvertTo-Json -InputObject @{address=$address;quorumPin=$pin} -Compress
  $result=Invoke-Composer $dir $payload $false $false $false 'provision'
  if($result.status -cne 'local-vault-created-not-enrolled' -or $result.identity.address -cne $address -or $result.quorumPin -cne $pin -or $result.liveAccountEnrollmentAuthorized -ne $false -or $result.remoteAuthoritiesConfigured -ne $false){throw 'Resultat invalide.'}
  # The native code already retained the public enrollment record in the
  # private vault. Export only validated public material, never a private key.
  $picker=New-Object Windows.Forms.SaveFileDialog
  $picker.Title='Exporter les informations publiques du nouveau coffre'
  $picker.Filter='Identite publique (*.json)|*.json';$picker.FileName='quantic-identite-publique.json';$picker.OverwritePrompt=$true
  try{
   if($picker.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK){
    $public=ConvertTo-Json -InputObject @{identity=$result.identity;quorumPin=$result.quorumPin;labOnly=$true} -Depth 12 -Compress
    $data=[Text.Encoding]::UTF8.GetBytes($public)
    $f=[IO.File]::Open($picker.FileName,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$f.Write($data,0,$data.Length);$f.Flush($true)}finally{$f.Dispose()}
   }
  }catch{
   [Windows.Forms.MessageBox]::Show('Export public non termine. Les informations publiques ont ete conservees dans le coffre. Aucun fichier existant remplace.','Export','OK','Warning')|Out-Null
  }finally{$picker.Dispose()}
  [Windows.Forms.MessageBox]::Show(('Coffre cree, non connecte. Dossier : '+$dir+'. Transmettez uniquement les informations PUBLIQUES au responsable pour la preparation des autorisations. Aucun compte distant cree.'),'Coffre local cree','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Creation refusee, annulee ou incomplete. Conservez tout dossier partiel et ne le remplacez pas. Verifiez les informations fournies.','Coffre non confirme','OK','Warning')|Out-Null
 }
})
$connectionButton.Add_Click({
 try{
  $dir=Pick-SetupFolder 'Choisissez le coffre de test deja configure.'
  if(-not $dir){return}
  $carrier=Pick-SetupFolder 'Choisissez le dossier de transport prepare par le responsable.'
  if(-not $carrier){return}
  $picker=New-Object Windows.Forms.OpenFileDialog
  $picker.Title='Selectionner la fiche de confiance publique preparee';$picker.Filter='Fiche de confiance (*.json)|*.json';$picker.CheckFileExists=$true
  try{if($picker.ShowDialog($form) -ne [Windows.Forms.DialogResult]::OK){return};$trust=$picker.FileName}finally{$picker.Dispose()}
  $pin=Request-SetupText 'Empreinte SHA256 de cette fiche, obtenue par un canal de confiance independant.' 'Verifier la fiche de confiance'
  if(-not $pin){return};$pin=$pin.Trim().ToLowerInvariant()
  if($pin -cnotmatch '^[a-f0-9]{64}$' -or $pin -match '^0+$'){throw 'Empreinte invalide.'}
  $decision=[Windows.Forms.MessageBox]::Show('Verifier les attestations des autorites en direct ? Oui : controle des signatures et connexions mTLS. Non : verification locale hors ligne. Annuler : quitter. Aucun message transmis.','Verification des autorites','YesNoCancel','Question')
  if($decision -eq [Windows.Forms.DialogResult]::Cancel){return}
  $live=($decision -eq [Windows.Forms.DialogResult]::Yes)
  $payload=ConvertTo-Json -InputObject @{carrierDir=$carrier;trustFile=$trust;trustSha256=$pin;live=$live} -Compress
  $result=Invoke-Composer $dir $payload $false $false $false 'readiness'
  if($result.liveAccountEnrollmentAuthorized -ne $false -or $result.remoteTransportVerified -ne $false -or $result.contactPinsVerified -ne $true -or $result.authorityCount -ne 4){throw 'Resultat invalide.'}
  if($live){
   if($result.status -cne 'fresh-mtls-3-of-4-quorum-and-contact-verified' -or $result.authorityQuorumVerified -ne $true){throw 'Quorum non confirme.'}
   $text='Autorites : quorum et contact confirmes par attestations fraiches. Transport distant non encore verifie.'
  }else{
   if($result.status -cne 'offline-public-anchors-verified' -or $result.authorityQuorumVerified -ne $false){throw 'Verification locale non confirmee.'}
   $text='Configuration publique et contact verifies localement. Aucun quorum distant ni transport confirme.'
  }
  [Windows.Forms.MessageBox]::Show($text,'Verification de connexion','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Connexion non confirmee. Le coffre, le transport et la fiche de confiance doivent avoir ete prepares par le responsable. Aucune inscription ni modification automatique.','Configuration indisponible','OK','Warning')|Out-Null
 }
})

$cancel.Add_Click({$form.Close()})
$statusButton.Add_Click({
 try {
  if(-not $script:privateDirectory){throw 'Coffre de test non choisi.'}
  $result=Invoke-Composer $script:privateDirectory '' $false $false $true
  if($result.status -cne 'local-files-only-unverified' -or $result.deliveryVerified){throw 'Etat non fiable.'}
  $items=@($result.items)
  $lines=@('Lecture locale seulement - aucune livraison distante verifiee.','')
  if($items.Count -eq 0){$lines+='Aucun essai trouve.'}
  $n=[Math]::Min($items.Count,10)
  for($i=0;$i -lt $n;$i++){
   $item=$items[$i]
   $desc=if($item.wire){'Enveloppe presente - livraison inconnue'}else{'Brouillon protege - non envoye'}
   $lines+=('Essai '+($i+1)+' : '+$desc)
  }
  if($items.Count -gt $n){$lines+=('Autres essais : '+($items.Count-$n))}
  [Windows.Forms.MessageBox]::Show(($lines -join [Environment]::NewLine),'Mes essais locaux','OK','Information')|Out-Null
 }catch{
  [Windows.Forms.MessageBox]::Show('Etat local indisponible. Aucun fichier supprime ou renvoye.','Mes essais locaux','OK','Warning')|Out-Null
 }
})
$choose.Add_Click({
 $picker=New-Object Windows.Forms.FolderBrowserDialog
 $picker.Description='Selectionnez votre coffre de test existant.'
 try{
  if($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return}
  $dir=$picker.SelectedPath
  $result=Invoke-Composer $dir '' $true
  if($result.status -cne 'contacts' -or @($result.recipients).Count -lt 1){throw 'Aucun contact.'}
  $script:privateDirectory=$dir
  $chosen.Text='Coffre de test selectionne'
  $recipient.Items.Clear()
  foreach($a in @($result.recipients)){[void]$recipient.Items.Add([string]$a)}
  $recipient.SelectedIndex=0
 }catch{
  $script:privateDirectory=$null;$chosen.Clear();$recipient.Items.Clear()
  [Windows.Forms.MessageBox]::Show('Ce coffre ne contient pas de contact de test valide. Aucune modification.','Coffre indisponible','OK','Warning')|Out-Null
 }finally{$picker.Dispose()}
})
$save.Add_Click({
 try{
  if(-not $script:privateDirectory -or $recipient.SelectedIndex -lt 0){throw 'Coffre et contact requis.'}
  if([string]::IsNullOrWhiteSpace($subject.Text) -or [string]::IsNullOrWhiteSpace($body.Text)){throw 'Objet et texte requis.'}
  $informed=[Windows.Forms.MessageBox]::Show('Ce brouillon de test sera chiffre sur disque avec la protection du profil Windows actuel (DPAPI). Il n est pas chiffre de bout en bout, ne quitte pas cet ordinateur et n est pas encore envoye. Non portable et non post-quantique. Continuer ?','Avertissement sur le stockage','YesNo','Warning')
  if($informed -ne [Windows.Forms.DialogResult]::Yes){return}
  $fields=@{to=[string]$recipient.SelectedItem;subject=$subject.Text;body=$body.Text}
  $json=ConvertTo-Json -InputObject $fields -Compress -Depth 3
  $result=Invoke-Composer $script:privateDirectory $json $false
  if($result.status -cne 'draft-saved-not-sent' -or $result.remoteDeliveryVerified -or $result.liveAccountEnrollmentAuthorized){throw 'Brouillon non confirme.'}
  [Windows.Forms.MessageBox]::Show('Brouillon de test chiffre au repos par Windows DPAPI. Il n est pas chiffre pour un destinataire et n est pas envoye. Vous pouvez chiffrer et deposer un nouveau message depuis cet ecran.','Brouillon enregistre','OK','Information')|Out-Null
  $form.Close()
 }catch{
  [Windows.Forms.MessageBox]::Show('Enregistrement refuse : verifiez le coffre, le contact et la longueur du texte. Aucun message envoye.','Operation non confirmee','OK','Warning')|Out-Null
 }
})
$send.Add_Click({
 try{
  if(-not $script:privateDirectory -or $recipient.SelectedIndex -lt 0){throw 'Selectionnez un coffre et un contact deja approuves.'}
  if([string]::IsNullOrWhiteSpace($subject.Text) -or [string]::IsNullOrWhiteSpace($body.Text)){throw 'Objet et texte requis.'}
  if([System.Text.Encoding]::UTF8.GetByteCount($body.Text) -gt 800){
   throw 'Cet essai graphique limite le texte a 800 octets pour une confirmation integrale.'
  }
  $warn=[Windows.Forms.MessageBox]::Show('TEST FICTIF : le coffre natif demandera deux phrases secretes par fenetre Windows puis des confirmations. Si le depot est incertain, aucun renvoi automatique. Aucun paiement ou compte reel. Continuer ?','Essai de transmission','YesNo','Warning')
  if($warn -ne [Windows.Forms.DialogResult]::Yes){return}
  $fields=@{to=[string]$recipient.SelectedItem;subject=$subject.Text;body=$body.Text}
  $json=ConvertTo-Json -InputObject $fields -Compress -Depth 3
  $result=Invoke-Composer $script:privateDirectory $json $false $true
  switch($result.status){
   'deposited' {
    [Windows.Forms.MessageBox]::Show('Enveloppe chiffree et conservee ; depot confirme par le relais local. Cela ne prouve PAS la livraison ni la lecture distante. Ne renvoyez pas automatiquement.','Depot local de test','OK','Information')|Out-Null
    $form.Close()
   }
   'saved-not-sent' {
    [Windows.Forms.MessageBox]::Show('Enveloppe chiffree conservee. Depot refuse par vous : aucun message transmis.','Non envoye','OK','Information')|Out-Null
   }
   'cancelled-before-seal' {
    [Windows.Forms.MessageBox]::Show('Brouillon chiffre au repos conserve. Signature et depot annules.','Action annulee','OK','Information')|Out-Null
   }
   default {throw 'Statut du coffre inconnu.'}
  }
 }catch{
  [Windows.Forms.MessageBox]::Show('Envoi non confirme. Un brouillon ou une enveloppe peut deja etre conserve. Ne recommencez pas automatiquement. Utilisez le diagnostic de laboratoire et conservez les originaux.','Resultat incertain','OK','Warning')|Out-Null
 }
})
if($SelfTest){
 if($newVault.Text -notmatch 'Creer' -or $connectionButton.Text -notmatch 'connexion'){throw 'Setup buttons missing'}
 if($recipient.DropDownStyle -ne 'DropDownList' -or -not $body.Multiline -or -not $chosen.ReadOnly -or $save.Text -notmatch 'brouillon' -or $send.Text -notmatch 'deposer' -or $statusButton.Text -notmatch 'essais' -or $receiveButton.Text -notmatch 'Recevoir' -or $confirmButton.Text -notmatch 'Confirmer'){throw 'Composer self-test failed'}
 $form.Dispose();Write-Output 'Private GUI composer passed';return
}
try{[void]$form.ShowDialog()}finally{$form.Dispose()}
