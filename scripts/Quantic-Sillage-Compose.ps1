# Native GUI-only lab composer. No email is sent by this screen.
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
function Invoke-Composer([string]$Directory,[string]$Payload,[bool]$List){
 if($Directory -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Dossier prive non valide.'}
 foreach($part in $Directory.Substring(3).Split('\')){
  if($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'Chemin ambigu.'}
 }
 $psi=New-Object System.Diagnostics.ProcessStartInfo
 $psi.FileName=$node
 $psi.Arguments= ('"{0}" "{1}" {2} "{3}"{4}' -f $helper,$vault,$TrustedBinarySha256.ToLowerInvariant(),$Directory,$(if($List){' --list'}else{''}))
 $psi.WorkingDirectory=$root
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.StandardInputEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.StandardOutputEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.StandardErrorEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $p=New-Object System.Diagnostics.Process
 $p.StartInfo=$psi
 try{
  if(-not $p.Start()){throw 'Demarrage refuse.'}
  if(-not $List){$p.StandardInput.Write($Payload)}
  $p.StandardInput.Close()
  if(-not $p.WaitForExit(15000)){$p.Kill();throw 'Coffre indisponible.'}
  if($p.ExitCode -ne 0){throw 'Operation privee refusee.'}
  $answer=$p.StandardOutput.ReadToEnd()
  if($answer.Length -lt 1 -or $answer.Length -gt 2048){throw 'Reponse privee invalide.'}
  return ConvertFrom-Json -InputObject $answer
 }finally{$p.Dispose()}
}
# A two-phase private pipe: the GUI approves sealing up front, then approves
# depositing the already durable signed wire. No message text in argv or log.
function Invoke-GUISend([string]$Directory,[string]$Payload) {
 if($Directory -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Dossier de test refuse.'}
 foreach($part in $Directory.Substring(3).Split('\')) {
  if($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'Chemin ambigu.'}
 }
 $psi=New-Object System.Diagnostics.ProcessStartInfo
 $psi.FileName=$node
 $helperSend=Join-Path $root 'scripts\native-windows-compose-send.mjs'
 $psi.Arguments=('"{0}" "{1}" {2} "{3}"' -f $helperSend,$vault,$TrustedBinarySha256.ToLowerInvariant(),$Directory)
 $psi.WorkingDirectory=$root
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.StandardInputEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.StandardOutputEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.StandardErrorEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $p=New-Object System.Diagnostics.Process;$p.StartInfo=$psi
 try{
  if(-not $p.Start()){throw 'Demarrage prive refuse.'}
  $p.StandardInput.WriteLine($Payload)
  $first=Read-GUIReply $p
  if($first.phase -cne 'draft-saved'){throw 'Brouillon non confirme.'}
  $second=Read-GUIReply $p
  if($second.phase -ceq 'sealed-awaiting-deposit-approval'){
   $choice=[Windows.Forms.MessageBox]::Show('L enveloppe chiffree et signee a ete conservee et reverifiee. La deposer une fois sur le relais LOCAL de test ? Cela ne prouve pas sa reception sur un autre PC.','Autoriser le depot local','YesNo','Warning')
   $p.StandardInput.WriteLine($(if($choice -eq [Windows.Forms.DialogResult]::Yes){'SEND'}else{'CANCEL'}))
   $result=Read-GUIReply $p
  }else{$result=$second}
  $p.StandardInput.Close()
  if(-not $p.WaitForExit(10000)){$p.Kill();throw 'Etat de depot inconnu : conserver le brouillon et le message chiffre.'}
  if($result.phase -cne 'result' -or $result.remoteDeliveryVerified){throw 'Confirmation invalide.'}
  return $result
 }finally{
  if(-not $p.HasExited){$p.Kill()}
  $p.Dispose()
 }
}
function Read-GUIReply([Diagnostics.Process]$Proc) {
 $task=$Proc.StandardOutput.ReadLineAsync()
 if(-not $task.Wait(180000)){$Proc.Kill();throw 'Operation interrompue : ne pas envoyer automatiquement de nouveau.'}
 $line=$task.Result
 if(-not $line -or $line.Length -gt 512){throw 'Reponse locale invalide.'}
 return ConvertFrom-Json -InputObject $line
}
$form=New-Object Windows.Forms.Form
$form.Text='Quantic Mail | Nouveau message'
$form.StartPosition='CenterParent';$form.ClientSize=New-Object Drawing.Size(710,705)
$form.BackColor=[Drawing.Color]::FromArgb(19,25,35);$form.ForeColor=[Drawing.Color]::WhiteSmoke
$form.Font=New-Object Drawing.Font('Segoe UI',10)
function Label-At([string]$Text,[int]$Y){
 $l=New-Object Windows.Forms.Label;$l.Text=$Text;$l.SetBounds(24,$Y,660,24);$form.Controls.Add($l)
}
Label-At 'NOUVEAU MESSAGE DE TEST' 18
Label-At 'TEST UNIQUEMENT : le brouillon est en clair dans un dossier prive NTFS. Pas de donnees reelles.' 55
Label-At 'Mon coffre de test' 98
$chosen=New-Object Windows.Forms.TextBox;$chosen.SetBounds(24,128,464,29);$chosen.ReadOnly=$true;$form.Controls.Add($chosen)
$choose=New-Object Windows.Forms.Button;$choose.Text='Choisir mon coffre';$choose.SetBounds(500,125,180,35);$form.Controls.Add($choose)
Label-At 'Destinataire dans mon carnet local' 178
$recipient=New-Object Windows.Forms.ComboBox;$recipient.DropDownStyle='DropDownList'
$recipient.SetBounds(24,208,656,30);$form.Controls.Add($recipient)
Label-At 'Objet' 254
$subject=New-Object Windows.Forms.TextBox;$subject.SetBounds(24,284,656,30);$subject.MaxLength=160;$form.Controls.Add($subject)
Label-At 'Message' 332
$body=New-Object Windows.Forms.TextBox;$body.Multiline=$true;$body.ScrollBars='Vertical'
$body.MaxLength=7500;$body.SetBounds(24,361,656,162);$form.Controls.Add($body)
$save=New-Object Windows.Forms.Button;$save.Text='Enregistrer mon brouillon';$save.SetBounds(24,546,656,39)
$save.BackColor=[Drawing.Color]::FromArgb(196,223,244);$save.ForeColor=[Drawing.Color]::Black;$form.Controls.Add($save)
$send=New-Object Windows.Forms.Button;$send.Text='Chiffrer et deposer (test uniquement)';$send.SetBounds(24,599,437,45)
$send.BackColor=[Drawing.Color]::FromArgb(192,212,200);$send.ForeColor=[Drawing.Color]::Black;$form.Controls.Add($send)
$cancel=New-Object Windows.Forms.Button;$cancel.Text='Fermer';$cancel.SetBounds(481,599,199,45);$form.Controls.Add($cancel)
$cancel.Add_Click({$form.Close()})
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
  $informed=[Windows.Forms.MessageBox]::Show('Ce brouillon de test sera stocke en clair dans le coffre prive Windows. Il ne sera ni chiffre ni envoye. Ne saisissez aucune donnee reelle. Continuer ?','Avertissement sur le stockage','YesNo','Warning')
  if($informed -ne [Windows.Forms.DialogResult]::Yes){return}
  $fields=@{to=[string]$recipient.SelectedItem;subject=$subject.Text;body=$body.Text}
  $json=ConvertTo-Json -InputObject $fields -Compress -Depth 3
  $result=Invoke-Composer $script:privateDirectory $json $false
  if($result.status -cne 'draft-saved-not-sent' -or $result.remoteDeliveryVerified -or $result.liveAccountEnrollmentAuthorized){throw 'Brouillon non confirme.'}
  [Windows.Forms.MessageBox]::Show('Brouillon de test conserve en clair dans le dossier prive NTFS. Il n est ni chiffre ni envoye. Le parcours d envoi graphique reste en developpement.','Brouillon enregistre','OK','Information')|Out-Null
  $form.Close()
 }catch{
  [Windows.Forms.MessageBox]::Show('Enregistrement refuse : verifiez le coffre, le contact et la longueur du texte. Aucun message envoye.','Operation non confirmee','OK','Warning')|Out-Null
 }
})
$send.Add_Click({
 try{
  if(-not $script:privateDirectory -or $recipient.SelectedIndex -lt 0){throw 'Coffre et destinataire requis.'}
  if([string]::IsNullOrWhiteSpace($subject.Text) -or [string]::IsNullOrWhiteSpace($body.Text)){throw 'Texte requis.'}
  $consent=[Windows.Forms.MessageBox]::Show('ALPHA DE LABORATOIRE : deux secrets seront demandes par une fenetre Windows native, sans terminal. Le message sera d abord enregistre en clair dans le coffre de test, puis chiffre PQ et conserve. Un relais local doit etre configure. Aucune livraison distante garantie. Ne saisissez aucune donnee reelle. Continuer ?','Essai chiffre uniquement','YesNo','Warning')
  if($consent -ne [Windows.Forms.DialogResult]::Yes){return}
  $fields=@{to=[string]$recipient.SelectedItem;subject=$subject.Text;body=$body.Text}
  $json=ConvertTo-Json -InputObject $fields -Compress -Depth 3
  $send.Enabled=$false
  try{$result=Invoke-GUISend $script:privateDirectory $json}finally{$send.Enabled=$true}
  switch -CaseSensitive ([string]$result.status){
   'queued-on-local-relay' { $message='Enveloppe chiffree deposee une fois sur le relais LOCAL de test. Reception distante NON prouvee.' }
   'acknowledged-by-local-relay' { $message='Relais local confirme cette enveloppe. Cela ne prouve PAS une lecture sur un second appareil.' }
   'encrypted-saved-not-sent' { $message='Message chiffre et conserve. Depot refuse ; aucun envoi effectue.' }
   'delivery-unknown' { $message='RETOUR DU RELAIS INCERTAIN. Conserver les fichiers prives. Ne PAS tenter un second envoi automatique.' }
   default { $message='Envoi non confirme. Le brouillon, s il existe, reste dans le coffre de test. Aucune relance automatique.' }
  }
  [Windows.Forms.MessageBox]::Show($message,'Resultat du laboratoire','OK',$(if($result.status -like '*unknown*'){'Warning'}else{'Information'}))|Out-Null
  if($result.status -in @('queued-on-local-relay','acknowledged-by-local-relay')){$form.Close()}
 }catch{
  [Windows.Forms.MessageBox]::Show('Operation non confirmee. Un brouillon ou une enveloppe peut avoir ete conserve ; ne pas relancer automatiquement. Aucun compte reel modifie.','Etat du depot inconnu','OK','Warning')|Out-Null
 }
})
if($SelfTest){
 if($recipient.DropDownStyle -ne 'DropDownList' -or -not $body.Multiline -or -not $chosen.ReadOnly -or $save.Text -notmatch 'brouillon' -or $send.Text -notmatch 'Chiffrer' -or $send.Top -le $save.Top){throw 'Composer self-test failed'}
 $form.Dispose();Write-Output 'Private GUI composer passed';return
}
try{[void]$form.ShowDialog()}finally{$form.Dispose()}
){throw 'Dossier de test refuse.'}
 foreach($part in $Directory.Substring(3).Split('\')) {
  if($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'Chemin ambigu.'}
 }
 $psi=New-Object System.Diagnostics.ProcessStartInfo
 $psi.FileName=$node
 $helperSend=Join-Path $root 'scripts\native-windows-compose-send.mjs'
 $psi.Arguments=('"{0}" "{1}" {2} "{3}"' -f $helperSend,$vault,$TrustedBinarySha256.ToLowerInvariant(),$Directory)
 $psi.WorkingDirectory=$root
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.StandardInputEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.StandardOutputEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.StandardErrorEncoding=[System.Text.UTF8Encoding]::new($false)
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $p=New-Object System.Diagnostics.Process;$p.StartInfo=$psi
 try{
  if(-not $p.Start()){throw 'Demarrage prive refuse.'}
  $p.StandardInput.WriteLine($Payload)
  $first=Read-GUIReply $p
  if($first.phase -cne 'draft-saved'){throw 'Brouillon non confirme.'}
  $second=Read-GUIReply $p
  if($second.phase -ceq 'sealed-awaiting-deposit-approval'){
   $choice=[Windows.Forms.MessageBox]::Show('L enveloppe chiffree et signee a ete conservee et reverifiee. La deposer une fois sur le relais LOCAL de test ? Cela ne prouve pas sa reception sur un autre PC.','Autoriser le depot local','YesNo','Warning')
   $p.StandardInput.WriteLine($(if($choice -eq [Windows.Forms.DialogResult]::Yes){'SEND'}else{'CANCEL'}))
   $result=Read-GUIReply $p
  }else{$result=$second}
  $p.StandardInput.Close()
  if(-not $p.WaitForExit(10000)){$p.Kill();throw 'Etat de depot inconnu : conserver le brouillon et le message chiffre.'}
  if($result.phase -cne 'result' -or $result.remoteDeliveryVerified){throw 'Confirmation invalide.'}
  return $result
 }finally{
  if(-not $p.HasExited){$p.Kill()}
  $p.Dispose()
 }
}
function Read-GUIReply([Diagnostics.Process]$Proc) {
 $task=$Proc.StandardOutput.ReadLineAsync()
 if(-not $task.Wait(180000)){$Proc.Kill();throw 'Operation interrompue : ne pas envoyer automatiquement de nouveau.'}
 $line=$task.Result
 if(-not $line -or $line.Length -gt 512){throw 'Reponse locale invalide.'}
 return ConvertFrom-Json -InputObject $line
}

$form=New-Object Windows.Forms.Form
$form.Text='Quantic Mail | Nouveau message'
$form.StartPosition='CenterParent';$form.ClientSize=New-Object Drawing.Size(710,630)
$form.BackColor=[Drawing.Color]::FromArgb(19,25,35);$form.ForeColor=[Drawing.Color]::WhiteSmoke
$form.Font=New-Object Drawing.Font('Segoe UI',10)
function Label-At([string]$Text,[int]$Y){
 $l=New-Object Windows.Forms.Label;$l.Text=$Text;$l.SetBounds(24,$Y,660,24);$form.Controls.Add($l)
}
Label-At 'NOUVEAU MESSAGE DE TEST' 18
Label-At 'TEST UNIQUEMENT : le brouillon est en clair dans un dossier prive NTFS. Pas de donnees reelles.' 55
Label-At 'Mon coffre de test' 98
$chosen=New-Object Windows.Forms.TextBox;$chosen.SetBounds(24,128,464,29);$chosen.ReadOnly=$true;$form.Controls.Add($chosen)
$choose=New-Object Windows.Forms.Button;$choose.Text='Choisir mon coffre';$choose.SetBounds(500,125,180,35);$form.Controls.Add($choose)
Label-At 'Destinataire dans mon carnet local' 178
$recipient=New-Object Windows.Forms.ComboBox;$recipient.DropDownStyle='DropDownList'
$recipient.SetBounds(24,208,656,30);$form.Controls.Add($recipient)
Label-At 'Objet' 254
$subject=New-Object Windows.Forms.TextBox;$subject.SetBounds(24,284,656,30);$subject.MaxLength=160;$form.Controls.Add($subject)
Label-At 'Message' 332
$body=New-Object Windows.Forms.TextBox;$body.Multiline=$true;$body.ScrollBars='Vertical'
$body.MaxLength=7500;$body.SetBounds(24,361,656,162);$form.Controls.Add($body)
$save=New-Object Windows.Forms.Button;$save.Text='Enregistrer mon brouillon';$save.SetBounds(24,558,435,43)
$save.BackColor=[Drawing.Color]::FromArgb(196,223,244);$save.ForeColor=[Drawing.Color]::Black;$form.Controls.Add($save)
$cancel=New-Object Windows.Forms.Button;$cancel.Text='Fermer';$cancel.SetBounds(481,558,199,43);$form.Controls.Add($cancel)
$cancel.Add_Click({$form.Close()})
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
  $informed=[Windows.Forms.MessageBox]::Show('Ce brouillon de test sera stocke en clair dans le coffre prive Windows. Il ne sera ni chiffre ni envoye. Ne saisissez aucune donnee reelle. Continuer ?','Avertissement sur le stockage','YesNo','Warning')
  if($informed -ne [Windows.Forms.DialogResult]::Yes){return}
  $fields=@{to=[string]$recipient.SelectedItem;subject=$subject.Text;body=$body.Text}
  $json=ConvertTo-Json -InputObject $fields -Compress -Depth 3
  $result=Invoke-Composer $script:privateDirectory $json $false
  if($result.status -cne 'draft-saved-not-sent' -or $result.remoteDeliveryVerified -or $result.liveAccountEnrollmentAuthorized){throw 'Brouillon non confirme.'}
  [Windows.Forms.MessageBox]::Show('Brouillon de test conserve en clair dans le dossier prive NTFS. Il n est ni chiffre ni envoye. Le parcours d envoi graphique reste en developpement.','Brouillon enregistre','OK','Information')|Out-Null
  $form.Close()
 }catch{
  [Windows.Forms.MessageBox]::Show('Enregistrement refuse : verifiez le coffre, le contact et la longueur du texte. Aucun message envoye.','Operation non confirmee','OK','Warning')|Out-Null
 }
})
if($SelfTest){
 if($recipient.DropDownStyle -ne 'DropDownList' -or -not $body.Multiline -or -not $chosen.ReadOnly -or $save.Text -notmatch 'brouillon'){throw 'Composer self-test failed'}
 $form.Dispose();Write-Output 'Private GUI composer passed';return
}
try{[void]$form.ShowDialog()}finally{$form.Dispose()}
