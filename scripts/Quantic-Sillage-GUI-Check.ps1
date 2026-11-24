# Non-destructive interactive native Windows GUI acceptance check.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$TrustedBinarySha256,
 [switch]$SelfTest
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
$root=$PSScriptRoot
$bin=Join-Path $root 'bin\Vault-PQ-lab.exe'
$manifest=Join-Path $root 'SHA256SUMS.txt'
function Check-Pins {
 if(-not (Test-Path -LiteralPath $manifest -PathType Leaf) -or
    -not (Test-Path -LiteralPath $bin -PathType Leaf)){throw 'Fichiers natifs absents'}
 if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSha256){throw 'Empreinte manifeste invalide'}
 if((Get-FileHash -LiteralPath $bin -Algorithm SHA256).Hash -ine $TrustedBinarySha256){throw 'Empreinte coffre invalide'}
}
if($SelfTest){
 if($bin -notlike '*Vault-PQ-lab.exe' -or $manifest -notlike '*SHA256SUMS.txt'){throw 'Native contract mismatch'}
 Write-Output 'Interactive Win32 test contract verified (not performed)'
 return
}
try{
 Check-Pins
 $psi=[Diagnostics.ProcessStartInfo]::new()
 $psi.FileName=$bin
 $psi.Arguments='--windows-gui-operator-check-lab'
 $psi.WorkingDirectory=$root
 $psi.UseShellExecute=$false
 $psi.CreateNoWindow=$true
 $psi.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $psi.RedirectStandardOutput=$true
 $psi.RedirectStandardError=$true
 $psi.EnvironmentVariables.Clear()
 $psi.EnvironmentVariables['SystemRoot']=$env:SystemRoot
 $psi.EnvironmentVariables['WINDIR']=$env:SystemRoot
 $psi.EnvironmentVariables['PATH']=(Join-Path $root 'bin')+';'+(Join-Path $env:SystemRoot 'System32')
 $p=[Diagnostics.Process]::new()
 $p.StartInfo=$psi
 try{
  if(-not $p.Start()){throw 'Demarrage du coffre refuse'}
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while(-not $p.WaitForExit(100)){
   [System.Windows.Forms.Application]::DoEvents()
   if($clock.ElapsedMilliseconds -gt 180000){
    $p.Kill()
    throw 'Test interactif interrompu'
   }
  }
  if($p.ExitCode -ne 0){throw 'Test annule ou refuse'}
  $output=$p.StandardOutput.ReadToEnd()
  if($output.Length -lt 2 -or $output.Length -gt 256){throw 'Reponse native invalide'}
  $report=ConvertFrom-Json -InputObject $output
  if($report.status -cne 'native-windows-operator-check-passed' -or
     -not $report.nativeUIVerified -or -not $report.humanInteractive -or
     $report.liveAccountUsed -or $report.networkUsed){throw 'Validation native invalide'}
  [Windows.Forms.MessageBox]::Show('Verification locale reussie : saisie masquee, autorisation et refus ont ete testes. Aucun compte ni trafic reel.','Fenetres Windows verifiees','OK','Information')|Out-Null
 }finally{$p.Dispose()}
}catch{
 [Windows.Forms.MessageBox]::Show('Test refuse, annule ou impossible sur ce poste. Les boites natives ne sont pas considerees comme validees.','Validation non obtenue','OK','Warning')|Out-Null
}
