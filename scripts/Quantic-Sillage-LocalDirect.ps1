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
$vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
$helper=Join-Path $root 'scripts\native-windows-local-direct.mjs'
$script:dir=$null
$script:pin=$null
$script:protected=$true
$script:busy=$false
function Ask([string]$Text,[string]$Title){
 [Microsoft.VisualBasic.Interaction]::InputBox($Text,$Title,'')
}
function Folder([string]$Text){
 $d=New-Object Windows.Forms.FolderBrowserDialog;$d.Description=$Text
 try{if($d.ShowDialog() -eq [Windows.Forms.DialogResult]::OK){return $d.SelectedPath}}finally{$d.Dispose()}
}
function Native([string]$Action,$Fields){
 if($script:busy -or -not $script:dir -or $script:dir -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Coffre invalide'}
 if($Action -notin @('create','card','import','list','seal','recover-seal','open','recover-open','initialize','status','revoke','roster','pair')){throw 'Operation invalide'}
 if($script:protected){$Action='protected-'+$Action}
 $raw=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Fields -Compress -Depth 5))
 if($raw.Length -gt 131072){throw 'Donnees trop grandes'}
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$node;$psi.Arguments=('"{0}" "{1}" {2} "{3}" {4}' -f $helper,$vault,$TrustedBinarySha256.ToLowerInvariant(),$script:dir,$Action)
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.WorkingDirectory=$root;$psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
 $psi.EnvironmentVariables.Clear();$psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot;$psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $p=New-Object Diagnostics.Process;$p.StartInfo=$psi
 $script:busy=$true;$form.Enabled=$false
 try{
  if(-not $p.Start()){throw 'Demarrage refuse'}
  $p.StandardInput.BaseStream.Write($raw,0,$raw.Length);$p.StandardInput.BaseStream.Close()
  $o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync()
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while(-not $p.WaitForExit(100)){[Windows.Forms.Application]::DoEvents();if($clock.ElapsedMilliseconds -gt 320000){$p.Kill();throw 'Delai depasse'}}
  if($p.ExitCode -ne 0){throw 'Operation refusee'}
  $out=$o.GetAwaiter().GetResult();$null=$e.GetAwaiter().GetResult()
  if($out.Length -lt 2 -or $out.Length -gt 65536){throw 'Reponse invalide'}
  return ConvertFrom-Json -InputObject $out
 }finally{[Array]::Clear($raw,0,$raw.Length);$p.Dispose();$script:busy=$false;$form.Enabled=$true}
}
function Warn([string]$Text){[Windows.Forms.MessageBox]::Show($Text,'Quantic Mail direct','OK','Warning')|Out-Null}
function Info([string]$Text){[Windows.Forms.MessageBox]::Show($Text,'Quantic Mail direct','OK','Information')|Out-Null}
function Pin{
 if(-not $script:pin){
  $x=Ask 'Empreinte du carnet approuvee independamment lors de son import (64 caracteres).' 'Carnet de confiance'
  if($x -cnotmatch '^[a-fA-F0-9]{64}$'){throw 'Empreinte invalide'}
  $script:pin=$x.ToLowerInvariant()
 }
 return $script:pin
}
function PickWitnessCards {
 $d=New-Object Windows.Forms.OpenFileDialog
 $d.Filter='Cartes publiques des temoins (*.json)|*.json';$d.Multiselect=$true
 try{
  if($d.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return}
  if($d.FileNames.Count -ne 4){throw 'Quatre cartes requises'}
  $parts=@()
  foreach($f in $d.FileNames){
   if((Get-Item -LiteralPath $f).Length -gt 4096){throw 'Carte trop grande'}
   $expected=Ask ('Empreinte SHA256 recue independamment pour '+[IO.Path]::GetFileName($f)) 'Verifier le temoin'
   if($expected -cnotmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine $expected){throw 'Empreinte non confirmee'}
   $parts+= [IO.File]::ReadAllText($f,[Text.UTF8Encoding]::new($false,$true))
  }
  return ('['+($parts -join ',')+']')
 }finally{$d.Dispose()}
}
# Witness mode uses the verified native executable directly. It exposes only
# public cards and encrypted pairing capsules, not private credentials.
function WitnessProcess([string]$Command,[string]$Dir,[string]$PinValue=''){
 if($Command -notin @('--windows-witness-create-gui-lab','--windows-witness-enroll-gui-lab','--windows-witness-serve-lab')){throw 'Operation invalide'}
 if($Dir -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$'){throw 'Dossier invalide'}
 if($Command -eq '--windows-witness-enroll-gui-lab' -and $PinValue -cnotmatch '^[a-f0-9]{64}$'){throw 'Empreinte invalide'}
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Binaire invalide'}
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$vault;$psi.Arguments=('{0} "{1}"' -f $Command,$Dir)
 if($Command -eq '--windows-witness-enroll-gui-lab'){$psi.Arguments+=' '+$PinValue}
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=(Split-Path -Parent $vault)
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
 $psi.EnvironmentVariables.Clear();$psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot;$psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Split-Path -Parent $vault)+';'+(Join-Path $env:SystemRoot 'System32')
 $proc=New-Object Diagnostics.Process;$proc.StartInfo=$psi
 return $proc
}
function WitnessRequest([string]$Command,[string]$Dir,[byte[]]$Raw,[string]$PinValue=''){
 if($Raw.Length -gt 16384){throw 'Paquet trop grand'}
 $proc=WitnessProcess $Command $Dir $PinValue
 try{
  if(-not $proc.Start()){throw 'Demarrage refuse'}
  $proc.StandardInput.BaseStream.Write($Raw,0,$Raw.Length);$proc.StandardInput.BaseStream.Close()
  $out=$proc.StandardOutput.ReadToEndAsync();$err=$proc.StandardError.ReadToEndAsync()
  if(-not $proc.WaitForExit(300000)){$proc.Kill();throw 'Delai depasse'}
  if($proc.ExitCode -ne 0){throw 'Operation refusee'}
  $response=$out.GetAwaiter().GetResult();$null=$err.GetAwaiter().GetResult()
  if($response.Length -gt 16384){throw 'Reponse invalide'}
  return $response
 }finally{$proc.Dispose()}
}
function WitnessDialog([switch]$CheckOnly){
 $w=New-Object Windows.Forms.Form;$w.Text='Quantic Sillage | Temoin independant'
 $w.StartPosition='CenterParent';$w.ClientSize=New-Object Drawing.Size(620,345)
 $w.Font=New-Object Drawing.Font('Segoe UI',10)
 $state=New-Object PSObject -Property @{Dir=$null;Process=$null;Out=$null;Err=$null}
 $title=New-Object Windows.Forms.Label;$title.Text='Un temoin sur une machine et un domaine de sauvegarde independants. Ne jamais restaurer son journal pour resoudre une erreur.';$title.SetBounds(16,12,588,54);$w.Controls.Add($title)
 $status=New-Object Windows.Forms.Label;$status.Text='Aucun dossier temoin selectionne';$status.SetBounds(16,73,588,45);$w.Controls.Add($status)
 $buttons=@()
 foreach($label in @('Creer mon temoin','Ouvrir un temoin','Associer le paquet chiffre','Demarrer le temoin','Arreter le temoin','Fermer')){
  $b=New-Object Windows.Forms.Button;$b.Text=$label;$idx=$buttons.Count
  $b.SetBounds((16+($idx%2)*300),(128+[Math]::Floor($idx/2)*54),288,42)
  $w.Controls.Add($b);$buttons+= $b
 }
 $create,$choose,$enroll,$start,$stop,$exit=$buttons
 $stop.Enabled=$false
 $timer=New-Object Windows.Forms.Timer;$timer.Interval=500
 $timer.Add_Tick({
  if($state.Process -and $state.Process.HasExited){
   $timer.Stop();$state.Process.Dispose();$state.Process=$null
   $status.Text='Temoin arrete. Aucun redemarrage automatique.'
   $create.Enabled=$true;$choose.Enabled=$true;$enroll.Enabled=$true;$start.Enabled=$true;$stop.Enabled=$false
  }
 })
 $create.Add_Click({
  try{
   $parent=Folder 'Emplacement prive du nouveau temoin';if(-not $parent){return}
   $ip=Ask 'Adresse IPv4 privee de CETTE machine (reseau local).' 'Adresse du temoin'
   $lp=Ask 'Port UDP du journal de contact (1024 a 65535).' 'Port contact'
   $mp=Ask 'Autre port UDP pour le journal de messagerie.' 'Port messagerie'
   if($ip -cnotmatch '^[0-9.]{7,15}$' -or $lp -cnotmatch '^[0-9]{4,5}$' -or $mp -cnotmatch '^[0-9]{4,5}$'){return}
   $dir=Join-Path $parent ('temoin-'+[Guid]::NewGuid().ToString('N').Substring(0,12))
   $raw=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress @{IP=$ip;LeasePort=[int]$lp;MailPort=[int]$mp}))
   $response=WitnessRequest '--windows-witness-create-gui-lab' $dir $raw
   $card=ConvertFrom-Json -InputObject $response
   if($card.Format -cne 'quantic-witness-card/v1'){throw 'Carte invalide'}
   $state.Dir=$dir;$status.Text='Temoin cree. Association requise.'
   $d=New-Object Windows.Forms.SaveFileDialog;$d.Filter='Carte publique de temoin (*.json)|*.json';$d.FileName='carte-temoin.json'
   try{
    if($d.ShowDialog($w) -ne [Windows.Forms.DialogResult]::OK){return}
    $file=[IO.File]::Open($d.FileName,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.Encoding]::UTF8.GetBytes($response.Trim());$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    Info ('Carte publique uniquement. Transmettez cette empreinte independamment : '+(Get-FileHash -LiteralPath $d.FileName -Algorithm SHA256).Hash.ToLowerInvariant())
   }finally{$d.Dispose()}
  }catch{Warn 'Creation ou export non confirme. Conservez le dossier temoin.'}
 })
 $choose.Add_Click({
  $dir=Folder 'Dossier prive du temoin existant'
  if($dir){$state.Dir=$dir;$status.Text='Dossier selectionne. Verification native au demarrage.'}
 })
 $enroll.Add_Click({
  if(-not $state.Dir){Warn 'Selectionnez un temoin.';return}
  $d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='Paquet chiffre Quantic (*.json)|*.json'
  try{
   if($d.ShowDialog($w) -ne [Windows.Forms.DialogResult]::OK){return}
   if((Get-Item -LiteralPath $d.FileName).Length -gt 16384){throw 'Paquet trop grand'}
   $pin=Ask 'Empreinte SHA256 confirmee par le proprietaire du coffre via un canal independant.' 'Verifier le paquet'
   if($pin -cnotmatch '^[a-fA-F0-9]{64}$'){return}
   $raw=[IO.File]::ReadAllBytes($d.FileName)
   $null=WitnessRequest '--windows-witness-enroll-gui-lab' $state.Dir $raw $pin.ToLowerInvariant()
   $status.Text='Association terminee. Demarrage possible.'
  }catch{Warn 'Association refusee. Aucun journal existant ecrase.'}finally{$d.Dispose()}
 })
 $start.Add_Click({
  if(-not $state.Dir -or $state.Process){return}
  try{
   $proc=WitnessProcess '--windows-witness-serve-lab' $state.Dir
   if(-not $proc.Start()){$proc.Dispose();throw 'Demarrage refuse'}
   $proc.StandardInput.Close()
   $state.Out=$proc.StandardOutput.ReadToEndAsync();$state.Err=$proc.StandardError.ReadToEndAsync()
   $state.Process=$proc
   $create.Enabled=$false;$choose.Enabled=$false;$enroll.Enabled=$false;$start.Enabled=$false;$stop.Enabled=$true
   $status.Text='Processus lance. Seule la verification du quorum depuis le coffre confirme sa disponibilite.'
   $timer.Start()
  }catch{Warn 'Demarrage non confirme.'}
 })
 $stopAction={
  if($state.Process){
   $timer.Stop()
   try{if(-not $state.Process.HasExited){$state.Process.Kill();if(-not $state.Process.WaitForExit(5000)){throw 'Arret non confirme'}}}
   catch{Warn 'Arret non confirme. Ne redemarrez pas.';return}
   $state.Process.Dispose();$state.Process=$null
   $status.Text='Temoin arrete. Les journaux sont conserves.'
   $create.Enabled=$true;$choose.Enabled=$true;$enroll.Enabled=$true;$start.Enabled=$true;$stop.Enabled=$false
  }
 }
 $stop.Add_Click($stopAction)
 $exit.Add_Click({$w.Close()})
 $w.Add_FormClosing({param($sender,$event)if($state.Process){$event.Cancel=$true;Warn 'Arretez explicitement le temoin avant de fermer.'}})
 try{
  if($CheckOnly){if($buttons.Count -ne 6 -or $stop.Enabled){throw 'Witness UI contract'};return}
  [void]$w.ShowDialog($form)
 }finally{$timer.Stop();$timer.Dispose();$w.Dispose()}
}

$form=New-Object Windows.Forms.Form;$form.Text='Quantic Mail | Coffre autonome protege'
$form.StartPosition='CenterScreen';$form.ClientSize=New-Object Drawing.Size(720,650)
$form.Font=New-Object Drawing.Font('Segoe UI',10)
function Label([string]$Text,[int]$X,[int]$Y,[int]$W,[int]$H){
 $l=New-Object Windows.Forms.Label;$l.Text=$Text;$l.SetBounds($X,$Y,$W,$H);$form.Controls.Add($l);return $l
}
function Btn([string]$Text,[int]$X,[int]$Y,[int]$W){
 $b=New-Object Windows.Forms.Button;$b.Text=$Text;$b.SetBounds($X,$Y,$W,38);$form.Controls.Add($b);return $b
}
$mode=New-Object Windows.Forms.CheckBox;$mode.Text='Coffre protege (quorum independant obligatoire)';$mode.Checked=$true;$mode.SetBounds(16,12,688,40);$form.Controls.Add($mode)
$new=Btn 'Creer mon identite' 16 62 220
$select=Btn 'Ouvrir mon coffre' 248 62 220
$card=Btn 'Exporter ma carte publique' 480 62 224
$identity=Label 'Aucun coffre selectionne' 16 110 688 28
$import=Btn 'Ajouter un correspondant' 16 150 220
$pair=Btn 'Associer les temoins' 248 150 220
$activate=Btn 'Activer le contact' 480 150 224
$revoke=Btn 'Revoquer le contact' 16 598 220
$mode.Add_CheckedChanged({$script:protected=$mode.Checked;$script:dir=$null;$script:pin=$null;$identity.Text='Aucun coffre selectionne';$activate.Enabled=$mode.Checked;$revoke.Enabled=$mode.Checked;$pair.Enabled=$mode.Checked;if(-not $mode.Checked){Warn 'Mode local historique : aucune garantie anti-restauration.'}})
$null=Label 'Objet' 16 203 688 22
$subject=New-Object Windows.Forms.TextBox;$subject.SetBounds(16,228,688,28);$subject.MaxLength=160;$form.Controls.Add($subject)
$null=Label 'Message (un correspondant approuve)' 16 270 688 22
$body=New-Object Windows.Forms.TextBox;$body.Multiline=$true;$body.ScrollBars='Vertical';$body.SetBounds(16,295,688,155);$body.MaxLength=7500;$form.Controls.Add($body)
$seal=Btn 'Preparer le message chiffre' 16 466 335
$inbox=Btn 'Lire les messages recus' 369 466 335
$note=Label 'Une fois prepare, le message est depose via Messagerie directe entre deux PC (liaison configuree). Aucun envoi automatique.' 16 530 688 65
$close=Btn 'Fermer' 484 598 220
$witness=Btn 'Mode temoin independant' 248 598 220
$witness.Add_Click({WitnessDialog})
$new.Add_Click({
 try{
  $parent=Folder 'Emplacement du nouveau coffre prive';if(-not $parent){return}
  $alias=Ask 'Nom local de 3 a 32 caracteres minuscules (lettres, chiffres, point, tiret, soulignement).' 'Nouvelle identite'
  if($alias -cnotmatch '^[a-z0-9][a-z0-9._-]{2,31}$'){return}
  $script:dir=Join-Path $parent ('quantic-'+[Guid]::NewGuid().ToString('N').Substring(0,12));$script:pin=$null
  $fields=@{alias=$alias}
  if($script:protected){
   $cards=PickWitnessCards
   if(-not $cards){return}
   $r=Native 'roster' @{cards=$cards}
   if($r.rosterPin -cnotmatch '^[a-f0-9]{64}$'){throw 'Quorum invalide'}
   $fields.roster=$r.rosterPin
  }
  $r=Native 'create' $fields
  if($r.status -cne 'direct-created'){throw 'Creation refusee'}
  $identity.Text=$r.address;Info 'Identite creee. Exportez sa carte publique pour votre correspondant. En mode protege, associez les temoins avant activation.'
 }catch{$script:dir=$null;$identity.Text='Aucun coffre selectionne';Warn 'Creation non confirmee. Conservez le dossier partiel.'}
})
$select.Add_Click({
 try{
  $d=Folder 'Choisir votre coffre autonome';if(-not $d){return}
  $script:dir=$d;$script:pin=$null
  $r=Native 'card' @{};if($r.status -cne 'direct-public-card'){throw 'Coffre refuse'}
  $identity.Text=$r.address
 }catch{$script:dir=$null;$identity.Text='Aucun coffre selectionne';Warn 'Ce coffre local direct ne peut pas etre ouvert.'}
})
$card.Add_Click({
 try{
  $r=Native 'card' @{};if($r.status -cne 'direct-public-card' -or $r.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Carte invalide'}
  $d=New-Object Windows.Forms.SaveFileDialog;$d.Filter='Carte publique Quantic (*.json)|*.json';$d.FileName='carte-quantic.json'
  try{
   if($d.ShowDialog($form) -ne [Windows.Forms.DialogResult]::OK){return}
   $f=[IO.File]::Open($d.FileName,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$b=[Text.Encoding]::UTF8.GetBytes([string]$r.card);$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
  }finally{$d.Dispose()}
  Info ('Carte publique uniquement. Communiquez son empreinte par un canal independant : '+$r.sha256+' . Validite maximale : 23 heures.')
 }catch{Warn 'Export non confirme. Aucun fichier existant ecrase.'}
})
$import.Add_Click({
 $d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='Carte publique Quantic (*.json)|*.json'
 try{
  if($d.ShowDialog($form) -ne [Windows.Forms.DialogResult]::OK){return}
  if((Get-Item -LiteralPath $d.FileName).Length -gt 131072){throw 'Carte trop grande'}
  $pin=Ask 'Empreinte confirmee par votre correspondant par un canal independant.' 'Verifier la carte'
  if($pin -cnotmatch '^[a-fA-F0-9]{64}$'){return}
  $r=Native 'import' @{card=[IO.File]::ReadAllText($d.FileName,[Text.UTF8Encoding]::new($false,$true));pin=$pin.ToLowerInvariant()}
  if($r.status -cne 'direct-contact-imported'){throw 'Import refuse'}
  $script:pin=$pin.ToLowerInvariant();Info 'Correspondant approuve localement. Aucun annuaire central.'
 }catch{Warn 'Carte refusee, expiree, ou carnet existant. Aucun ecrasement.'}finally{$d.Dispose()}
})
$pair.Add_Click({
 try{
  $cards=PickWitnessCards;if(-not $cards){return}
  $target=Folder 'Choisir le dossier de destination des quatre paquets chiffres';if(-not $target){return}
  $r=Native 'pair' @{pin=(Pin);cards=$cards}
  if($r.status -cne 'direct-witness-pairing' -or @($r.capsules).Count -ne 4){throw 'Association refusee'}
  $i=0;$lines=@()
  foreach($cap in $r.capsules){
   $i++;if($cap.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Paquet invalide'}
   $f=[IO.File]::Open((Join-Path $target ('temoin-'+$i+'.json')),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$b=[Text.Encoding]::UTF8.GetBytes([string]$cap.card);$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
   $lines+= ('Temoin '+$i+' : '+$cap.sha256)
  }
  Info ('Transmettez chaque paquet au temoin correspondant et son empreinte par un canal independant.'+[Environment]::NewLine+($lines -join [Environment]::NewLine))
 }catch{Warn 'Association non confirmee. Conservez les fichiers produits; aucune regeneration automatique.'}
})
$activate.Add_Click({try{$r=Native 'initialize' @{pin=(Pin)};if($r.status -cne 'direct-protected-active'){throw 'Activation refusee'};Info 'Contact active par quorum.'}catch{Warn 'Activation non confirmee. Les temoins doivent etre associes et demarres. Aucun mode de secours.'}})
$revoke.Add_Click({try{$r=Native 'revoke' @{pin=(Pin)};if($r.status -cne 'direct-protected-revoked'){throw 'Revocation refusee'};Info 'Contact revoque definitivement.'}catch{Warn 'Revocation non confirmee. Ne poursuivez pas les operations.'}})
$seal.Add_Click({
 try{
  if([string]::IsNullOrWhiteSpace($subject.Text) -or [string]::IsNullOrWhiteSpace($body.Text)){return}
  $fields=@{pin=(Pin);subject=$subject.Text;body=$body.Text}
  if([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $fields -Compress)) -gt 7600){throw 'Message trop grand'}
  if([Windows.Forms.MessageBox]::Show('Preparer exactement le message affiche ? Le coffre demandera votre autorisation. Aucun envoi.','Chiffrement local','YesNo','Warning') -ne [Windows.Forms.DialogResult]::Yes){return}
  $r=Native 'seal' $fields
  if($r.status -cne 'direct-wire-prepared' -or $r.noAutomaticRetry -ne $true){throw 'Resultat invalide'}
  Info 'Message signe et chiffre, conserve localement. Ouvrez ensuite la liaison directe pour le deposer.'
  $subject.Clear();$body.Clear()
 }catch{Warn 'Preparation non confirmee. Conservez le brouillon; ne recommencez pas automatiquement.'}
})
$inbox.Add_Click({
 try{
  $r=Native 'list' @{};if($r.status -cne 'direct-incoming' -or @($r.items).Count -gt 64){throw 'Liste invalide'}
  $files=@($r.items);if($files.Count -eq 0){Info 'Aucun message chiffre en attente.';return}
  $d=New-Object Windows.Forms.Form;$d.Text='Messages recus';$d.ClientSize=New-Object Drawing.Size(620,420)
  $list=New-Object Windows.Forms.ListBox;$list.SetBounds(16,16,588,100);$d.Controls.Add($list)
  for($i=0;$i -lt $files.Count;$i++){if($files[$i] -cnotmatch '^wire-in-[a-f0-9]{40}\.json$'){throw 'Message invalide'};[void]$list.Items.Add(('Message chiffre '+($i+1)))}
  $text=New-Object Windows.Forms.TextBox;$text.Multiline=$true;$text.ReadOnly=$true;$text.ScrollBars='Vertical';$text.SetBounds(16,128,588,220);$d.Controls.Add($text)
  $read=New-Object Windows.Forms.Button;$read.Text='Ouvrir';$read.SetBounds(16,362,180,38);$d.Controls.Add($read)
  $recover=New-Object Windows.Forms.Button;$recover.Text='Relire un message ouvert';$recover.SetBounds(208,362,250,38);$d.Controls.Add($recover)
  $readAction={param($action) if($list.SelectedIndex -lt 0){return};$d.Enabled=$false;try{
    $m=Native $action @{pin=(Pin);file=$files[$list.SelectedIndex]}
    if($m.status -cne 'direct-message-opened'){throw 'Lecture invalide'};$text.Text=$m.display
   }catch{$text.Text='Lecture non confirmee. Pour un message deja ouvert, choisissez Relire.'}finally{$d.Enabled=$true}}
  $read.Add_Click({& $readAction 'open'});$recover.Add_Click({& $readAction 'recover-open'})
  $list.SelectedIndex=0;try{[void]$d.ShowDialog($form)}finally{$d.Dispose()}
 }catch{Warn 'Messages indisponibles. Aucun fichier efface.'}
})
$close.Add_Click({$form.Close()})
$form.Add_FormClosing({param($sender,$e)if($script:busy){$e.Cancel=$true}})
if($SelfTest){WitnessDialog -CheckOnly;if($witness.Text -cne 'Mode temoin independant'){throw 'Witness entry missing'};if($new.Text -cne 'Creer mon identite' -or $seal.Text -cne 'Preparer le message chiffre'){throw 'Direct UI contract'};$form.Dispose();Write-Output 'Local direct vault UI contract verified';return}
try{
 $verifier=Join-Path $root 'Test-Windows-PQ-Package.ps1';$manifest=Join-Path $root 'SHA256SUMS.txt'
 if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256){throw 'Manifeste invalide'}
 $row=@(Get-Content -LiteralPath $manifest|Where-Object{$_ -cmatch '^[a-f0-9]{64} \*\./Test-Windows-PQ-Package\.ps1$'})
 if($row.Count -ne 1 -or (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash -ine $row[0].Substring(0,64)){throw 'Verificateur invalide'}
 & $verifier -PackageDirectory $root -ExpectedManifestSha256 $ExpectedManifestSha256|Out-Null
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Binaire invalide'}
 [void]$form.ShowDialog()
}catch{Warn 'Paquet non verifie. Aucune operation privee.'}finally{$form.Dispose()}
