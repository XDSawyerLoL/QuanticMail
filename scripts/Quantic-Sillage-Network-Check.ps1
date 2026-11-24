# Two-PC synthetic UDP proof, with local Windows dialogs only.
# No Quantic identity, real email, relay, firewall changes or web client.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$TrustedBinarySha256,
 [switch]$SelfTest
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
$root=$PSScriptRoot
$node=Join-Path $root 'runtime\node.exe'
$helper=Join-Path $root 'scripts\native-two-host-network-lab.mjs'
$manifest=Join-Path $root 'SHA256SUMS.txt'
$vault=Join-Path $root 'bin\Vault-PQ-lab.exe'
$port=49123
if($SelfTest){
 if($port -ne 49123 -or $helper -notlike '*native-two-host-network-lab.mjs'){throw 'Network proof contract failed'}
 Write-Output 'Native two-host GUI contract verified, physical network not tested'
 return
}
function Verify-NativeLab {
 foreach($name in @($manifest,$vault,$node,$helper)){
  if(-not (Test-Path -LiteralPath $name -PathType Leaf)){throw 'Paquet du test incomplet'}
 }
 if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256){throw 'Manifeste non fiable'}
 if((Get-FileHash -LiteralPath $vault -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Coffre natif non fiable'}
}
function New-TestProcess([string]$Mode,[string]$IP){
 $pinfo=[Diagnostics.ProcessStartInfo]::new()
 $pinfo.FileName=$node
 $pinfo.Arguments=if($Mode -eq 'receive'){'"'+$helper+'" receive '+$port+' 90'}else{'"'+$helper+'" send '+$IP+' '+$port+' 25'}
 $pinfo.UseShellExecute=$false
 $pinfo.CreateNoWindow=$true
 $pinfo.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $pinfo.WorkingDirectory=$root
 $pinfo.RedirectStandardInput=$true
 $pinfo.RedirectStandardOutput=$true
 $pinfo.RedirectStandardError=$true
 $pinfo.StandardInputEncoding=[Text.UTF8Encoding]::new($false)
 $pinfo.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
 $pinfo.EnvironmentVariables.Clear()
 $pinfo.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $pinfo.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $pinfo.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $proc=[Diagnostics.Process]::new();$proc.StartInfo=$pinfo
 return $proc
}
function Wait-Test([Diagnostics.Process]$Proc,[int]$MaxMilliseconds){
 $clock=[Diagnostics.Stopwatch]::StartNew()
 while(-not $Proc.WaitForExit(100)){
  [Windows.Forms.Application]::DoEvents()
  if($clock.ElapsedMilliseconds -gt $MaxMilliseconds){
   $Proc.Kill()
   throw 'Test reseau expire : aucune preuve.'
  }
 }
 if($Proc.ExitCode -ne 0){throw 'Reponse reseau non authentifiee'}
 $line=$Proc.StandardOutput.ReadLine()
 if([string]::IsNullOrEmpty($line) -or $line.Length -gt 1024){throw 'Resultat reseau invalide'}
 return ConvertFrom-Json -InputObject $line
}
try{
 Verify-NativeLab
 $decision=[Windows.Forms.MessageBox]::Show(
  'Diagnostic du reseau sur deux PC : aucune cle Quantic et aucun message reel. Oui : ce PC recoit. Non : ce PC envoie. Annuler : quitter.',
  'Quantic - essai physique du reseau','YesNoCancel','Information')
 if($decision -eq [Windows.Forms.DialogResult]::Cancel){return}
 if($decision -eq [Windows.Forms.DialogResult]::Yes){
  $p=New-TestProcess 'receive' ''
  try{
   if(-not $p.Start()){throw 'Reception indisponible'}
   $p.StandardInput.Close()
   $first=$p.StandardOutput.ReadLine()
   if([string]::IsNullOrEmpty($first) -or $first.Length -gt 512){throw 'Reception non initialisee'}
   $ready=ConvertFrom-Json -InputObject $first
   if($ready.status -cne 'receiver-ready' -or [string]$ready.code -cnotmatch '^[a-f0-9]{24}$' -or $ready.port -ne $port -or $ready.realMailProven){throw 'Code de test invalide'}
   [Windows.Forms.MessageBox]::Show(
    ('Ce PC attend sur UDP '+$port+'. Communiquez au deuxieme PC son adresse IPv4 locale et ce code temporaire : '+$ready.code+'. Sur le second PC, lancez le meme diagnostic en choisissant Non. Ne transmettez aucun secret reel. Fermez ce message apres avoir lance le second PC.'),
    'PC recepteur : code de test','OK','Information')|Out-Null
   $result=Wait-Test $p 110000
   if($result.status -cne 'synthetic-udp-acknowledged' -or $result.cryptographicMailDelivered -or $result.distinctPhysicalComputersVerified){throw 'Reponse non conforme'}
  }finally{
   if(-not $p.HasExited){$p.Kill()}
   $p.Dispose()
  }
 }else{
  $ip=[Microsoft.VisualBasic.Interaction]::InputBox('Adresse IPv4 autorisee du PC recepteur (LAN/VPN explicite).','PC emetteur','')
  if([string]::IsNullOrWhiteSpace($ip)){return}
  $parsed=$null
  if(-not [Net.IPAddress]::TryParse($ip,[ref]$parsed) -or
    $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsed.ToString() -cne $ip -or $ip.StartsWith('127.') -or $ip -eq '0.0.0.0' -or $ip.StartsWith('224.') -or $ip.StartsWith('255.')){throw 'Adresse IPv4 de test invalide'}
  $code=[Microsoft.VisualBasic.Interaction]::InputBox('Code temporaire de 24 caracteres affiche sur le PC recepteur. Jamais de mot de passe reel.','Code de test','')
  if([string]::IsNullOrWhiteSpace($code)){return}
  if($code -cnotmatch '^[a-f0-9]{24}$'){throw 'Code temporaire invalide'}
  $p=New-TestProcess 'send' $ip
  try{
   if(-not $p.Start()){throw 'Emission indisponible'}
   $p.StandardInput.Write($code)
   $p.StandardInput.Close()
   $code=$null
   $result=Wait-Test $p 35000
   if($result.status -cne 'synthetic-udp-mutual-proof' -or $result.cryptographicMailDelivered -or $result.distinctPhysicalComputersVerified){throw 'Reponse non conforme'}
  }finally{
   if(-not $p.HasExited){$p.Kill()}
   $p.Dispose()
  }
 }
 [Windows.Forms.MessageBox]::Show('L echange UDP fictif a ete authentifie dans les deux sens avec le code partage. Cela ne prouve NI un courrier livre NI deux machines physiques sans verification independante.','Test reseau reussi','OK','Information')|Out-Null
}catch{
 [Windows.Forms.MessageBox]::Show('Test de liaison non confirme. Verifiez les deux machines, le code et le pare-feu UDP 49123. Aucun compte ni mail modifie.','Liaison non verifiee','OK','Warning')|Out-Null
}
