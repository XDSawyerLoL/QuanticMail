# Prepared private test schedule, hidden runtime, separate modeless operator
# window. No automatic configuration of external authorities or firewall.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$TrustedBinarySha256,
 [switch]$SelfTest
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
$root=$PSScriptRoot
$node=Join-Path $root 'runtime\node.exe'
$helper=Join-Path $root 'scripts\run-windows-direct-mail.mjs'
$vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
$manifest=Join-Path $root 'SHA256SUMS.txt'
$verifier=Join-Path $root 'Test-Windows-PQ-Package.ps1'
function Quote-Arg([string]$v){
 if($v.Contains('"') -or $v.Contains([char]10) -or $v.Contains([char]13) -or $v.EndsWith('\')){throw 'Argument invalide'}
 return '"'+$v+'"'
}
if($SelfTest){
 if((Quote-Arg 'C:\Quantic Lab\test') -cne '"C:\Quantic Lab\test"' -or $helper -notlike '*run-windows-direct-mail.mjs'){throw 'Scattering UI contract'}
 Write-Output 'Direct mail UI argument contract verified';return
}
$proc=$null
$form=$null
try{
 if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256){throw 'Manifeste invalide'}
 $lines=@(Get-Content -LiteralPath $manifest)
 $row=@($lines|Where-Object{$_ -cmatch '^[a-f0-9]{64} \*\./Test-Windows-PQ-Package\.ps1$'})
 if($row.Count -ne 1 -or (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash -ine $row[0].Substring(0,64)){throw 'Verificateur invalide'}
 & $verifier -PackageDirectory $root -ExpectedManifestSha256 $ExpectedManifestSha256 | Out-Null
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Coffre invalide'}
 $row=@($lines|Where-Object{$_ -cmatch '^[a-f0-9]{64} \*\./bin/Scattering-Pacer\.exe$'})
 if($row.Count -ne 1){throw 'Pacer manquant'}
 $pacerPin=$row[0].Substring(0,64)
 $choice=New-Object Windows.Forms.FolderBrowserDialog
 $choice.Description='Selectionnez votre liaison privee de test preparee par le responsable.'
 try{if($choice.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return};$dir=$choice.SelectedPath}finally{$choice.Dispose()}
 $pin=[Microsoft.VisualBasic.Interaction]::InputBox('Empreinte du profil de liaison obtenue par un canal de confiance independant.','Confirmer ma liaison','')
 if(-not $pin){return}
 $pin=$pin.Trim().ToLowerInvariant()
 if($pin -cnotmatch '^[a-f0-9]{64}$' -or $pin -match '^0+$'){throw 'Empreinte invalide'}
 $consent=[Windows.Forms.MessageBox]::Show('Demarrer la liaison UDP directe de laboratoire entre deux PC ? Les anciennes sessions ne seront jamais reutilisees. Aucun compte reel, changement de pare-feu ou renvoi automatique.','Scattering','YesNo','Information')
 if($consent -ne [Windows.Forms.DialogResult]::Yes){return}
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$node
 $psi.Arguments=((Quote-Arg $helper),(Quote-Arg $vault),$TrustedBinarySha256.ToLowerInvariant(),$pacerPin,(Quote-Arg $dir),$pin) -join ' '
 $psi.WorkingDirectory=$root;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $proc=New-Object Diagnostics.Process;$proc.StartInfo=$psi
 $form=New-Object Windows.Forms.Form;$form.Text='Quantic Mail | Liaison directe'
 $form.StartPosition='CenterScreen';$form.ClientSize=New-Object Drawing.Size(520,330)
 $form.Font=New-Object Drawing.Font('Segoe UI',10)
 $status=New-Object Windows.Forms.Label;$status.SetBounds(20,20,480,82);$status.Text='Preparation de la liaison. Attente du profil de liaison autorise.';$form.Controls.Add($status)
 $note=New-Object Windows.Forms.Label;$note.SetBounds(20,108,480,40);$note.Text='Test direct : aucun relais heberge. Depot chiffre distinct de la lecture distante.';$form.Controls.Add($note)
 $stop=New-Object Windows.Forms.Button;$stop.SetBounds(310,275,190,35);$stop.Text='Arreter la liaison';$form.Controls.Add($stop)
 $list=New-Object Windows.Forms.ListBox;$list.SetBounds(20,156,480,80);$form.Controls.Add($list)
 $send=New-Object Windows.Forms.Button;$send.SetBounds(20,275,275,35);$send.Text='Deposer le message selectionne';$send.Enabled=$false;$form.Controls.Add($send)
 $state=@{started=$false;stopping=$false;done=$false;line=$null;err=$null;last=$null;role=$null;seen=$false;busy=$false;items=@()}
 $list.Add_SelectedIndexChanged({$send.Enabled=($state.role -eq 'sender' -and $state.seen -and -not $state.busy -and -not $state.stopping -and -not $state.done -and $list.SelectedIndex -ge 0)})
 $send.Add_Click({
  if($state.busy -or $state.stopping -or -not $state.seen -or $list.SelectedIndex -lt 0){return}
  $id=$state.items[$list.SelectedIndex]
  if($id -cnotmatch '^[a-f0-9]{32}$'){return}
  $state.busy=$true;$send.Enabled=$false;$list.Enabled=$false
  $status.Text='Depot direct en cours. Confirmez dans la fenetre du coffre.'
  try{
   $b=[Text.Encoding]::ASCII.GetBytes('SEND '+$id+[char]10)
   $proc.StandardInput.BaseStream.Write($b,0,$b.Length);$proc.StandardInput.BaseStream.Flush()
  }catch{Request-Stop}
 })
 function Request-Stop {
  if(-not $state.started -or $state.done -or $state.stopping){return}
  $state.stopping=$true;$stop.Enabled=$false;$send.Enabled=$false;$list.Enabled=$false
  $status.Text='Arret controle en cours. Aucune session ne sera reutilisee.'
  try{
   $b=[Text.Encoding]::ASCII.GetBytes("STOP"+[char]10)
   $proc.StandardInput.BaseStream.Write($b,0,$b.Length);$proc.StandardInput.BaseStream.Close()
  }catch{}
 }
 $timer=New-Object Windows.Forms.Timer;$timer.Interval=200
 $stop.Add_Click({if($state.done){$form.Close()}else{Request-Stop}})
 $form.Add_FormClosing({param($sender,$e) if($state.started -and -not $state.done){$e.Cancel=$true;Request-Stop}})
 $timer.Add_Tick({
  try{
   for($i=0;$i -lt 26 -and $null -ne $state.line -and $state.line.IsCompleted;$i++){
    $line=$state.line.GetAwaiter().GetResult()
    if($null -eq $line){$state.line=$null;break}
    if($line.Length -gt 8192){throw 'Reponse invalide'}
    $msg=ConvertFrom-Json -InputObject $line
    switch -CaseSensitive ($msg.status){
     'direct-listening'{
      if($msg.hostedRelay -ne $false -or $msg.role -notin @('sender','recipient')){throw 'Statut invalide'}
      $state.role=$msg.role
      $status.Text=if($state.role -eq 'sender'){'Emetteur : attente du destinataire direct.'}else{'Destinataire : attente de messages signes. Le depot est local et chiffre.'}
     }
     'outgoing'{
      if($state.role -ne 'sender' -or @($msg.items).Count -gt 64){throw 'Liste invalide'}
      $state.items=@($msg.items);$list.Items.Clear()
      for($j=0;$j -lt $state.items.Count;$j++){
       if($state.items[$j] -cnotmatch '^[a-f0-9]{32}$'){throw 'Message invalide'}
       [void]$list.Items.Add(('Message signe '+($j+1)+' - '+$state.items[$j].Substring(0,8)))
      }
      if($list.Items.Count -gt 0){$list.SelectedIndex=0}
     }
     'direct-peer-cells-observed'{
      if($msg.remoteDeliveryVerified -ne $false){throw 'Statut invalide'}
      $state.seen=$true
      if(-not $state.stopping){$status.Text='Liaison authentifiee observee. Aucun relais heberge.'}
     }
     {$_ -in @('peer-stored','cancelled','deposit-not-confirmed')}{
      if($msg.readVerified -ne $false -or $msg.noAutomaticRetry -ne $true){throw 'Statut invalide'}
      $state.busy=$false
      if(-not $state.stopping){
       $list.Enabled=$true
       $status.Text=switch($msg.status){
        'peer-stored'{'Enveloppe conservee sur le PC destinataire. Lecture non prouvee.'}
        'cancelled'{'Depot annule. Message original conserve.'}
        default{'Depot non confirme. Ne renvoyez pas automatiquement.'}
       }
      }
     }
     'stopped'{$state.last='stopped'}
     default{throw 'Statut inconnu'}
    }
    $send.Enabled=($state.role -eq 'sender' -and $state.seen -and -not $state.busy -and -not $state.stopping -and -not $state.done -and $list.SelectedIndex -ge 0)
    $state.line=$proc.StandardOutput.ReadLineAsync()
   }
   if($proc.HasExited -and $null -eq $state.line){
    $state.done=$true;$timer.Stop();$send.Enabled=$false;$stop.Enabled=$true;$stop.Text='Fermer'
    if($proc.ExitCode -eq 0 -and $state.last -in @('stopped','overlap-schedule-complete')){$status.Text='Liaison arretee. Sessions consommees conservees.'}
    else{$status.Text='Liaison non confirmee. Ne pas reutiliser le profil de liaison. Contactez le responsable.'}
   }
  }catch{
   $status.Text='Statut invalide. Arret de securite demande.'
   Request-Stop
   if($proc.HasExited){$state.done=$true;$timer.Stop();$stop.Enabled=$true;$stop.Text='Fermer'}
  }
 })
 if(-not $proc.Start()){throw 'Demarrage refuse'}
 $state.started=$true
 $state.line=$proc.StandardOutput.ReadLineAsync();$state.err=$proc.StandardError.ReadToEndAsync()
 $timer.Start();$null=$form.ShowDialog();$timer.Dispose()
}catch{
 [Windows.Forms.MessageBox]::Show('Liaison non disponible. Verifiez le profil de liaison et la configuration preparee. Aucun renvoi automatique.','Scattering','OK','Warning')|Out-Null
}finally{
 if($proc){
  try{if(-not $proc.HasExited){$proc.StandardInput.BaseStream.Close();$null=$proc.WaitForExit(15000)}}catch{}
  $proc.Dispose()
 }
 if($form){$form.Dispose()}
}
