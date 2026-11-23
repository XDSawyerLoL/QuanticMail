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
function Invoke-Composer([string]$Directory,[string]$Payload,[bool]$List,[bool]$Send=$false){
 if($Directory -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Dossier prive non valide.'}
 foreach($part in $Directory.Substring(3).Split('\')){
  if($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'Chemin ambigu.'}
 }
 $psi=New-Object System.Diagnostics.ProcessStartInfo
 $psi.FileName=$node
 $psi.Arguments= ('"{0}" "{1}" {2} "{3}"{4}' -f $helper,$vault,$TrustedBinarySha256.ToLowerInvariant(),$Directory,$(if($List){' --list'}elseif($Send){' --send'}else{''}))
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
  if(-not $p.WaitForExit($(if($Send){300000}else{15000}))){$p.Kill();throw 'Coffre indisponible.'}
  if($p.ExitCode -ne 0){throw 'Operation privee refusee.'}
  $answer=$p.StandardOutput.ReadToEnd()
  if($answer.Length -lt 1 -or $answer.Length -gt 2048){throw 'Reponse privee invalide.'}
  return ConvertFrom-Json -InputObject $answer
 }finally{$p.Dispose()}
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
Label-At 'TEST : brouillon chiffre par Windows DPAPI (utilisateur local). Pas de donnees reelles.' 55
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
$save=New-Object Windows.Forms.Button;$save.Text='Enregistrer mon brouillon';$save.SetBounds(24,558,240,43)
$save.BackColor=[Drawing.Color]::FromArgb(196,223,244);$save.ForeColor=[Drawing.Color]::Black;$form.Controls.Add($save)
$cancel=New-Object Windows.Forms.Button;$cancel.Text='Fermer';$cancel.SetBounds(495,558,185,43);$form.Controls.Add($cancel)
$send=New-Object Windows.Forms.Button
$send.Text='Chiffrer et deposer (test)'
$send.SetBounds(276,558,208,43)
$form.Controls.Add($send)
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
  $informed=[Windows.Forms.MessageBox]::Show('Ce brouillon de test sera chiffre sur disque avec la protection du profil Windows actuel (DPAPI). Il n est pas chiffre de bout en bout, ne quitte pas cet ordinateur et n est pas encore envoye. Non portable et non post-quantique. Continuer ?','Avertissement sur le stockage','YesNo','Warning')
  if($informed -ne [Windows.Forms.DialogResult]::Yes){return}
  $fields=@{to=[string]$recipient.SelectedItem;subject=$subject.Text;body=$body.Text}
  $json=ConvertTo-Json -InputObject $fields -Compress -Depth 3
  $result=Invoke-Composer $script:privateDirectory $json $false
  if($result.status -cne 'draft-saved-not-sent' -or $result.remoteDeliveryVerified -or $result.liveAccountEnrollmentAuthorized){throw 'Brouillon non confirme.'}
  [Windows.Forms.MessageBox]::Show('Brouillon de test chiffre au repos par Windows DPAPI. Il n est pas chiffre pour un destinataire et n est pas envoye. Le parcours d envoi graphique reste en developpement.','Brouillon enregistre','OK','Information')|Out-Null
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
 if($recipient.DropDownStyle -ne 'DropDownList' -or -not $body.Multiline -or -not $chosen.ReadOnly -or $save.Text -notmatch 'brouillon' -or $send.Text -notmatch 'deposer'){throw 'Composer self-test failed'}
 $form.Dispose();Write-Output 'Private GUI composer passed';return
}
try{[void]$form.ShowDialog()}finally{$form.Dispose()}
