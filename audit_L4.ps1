$ErrorActionPreference="SilentlyContinue"

$Base=$PSScriptRoot

$LogDir="$Base\logs"
$BrowserDir="$Base\browser"
$NetDir="$Base\network"
$PersistenceDir="$Base\persistence"
$SigDir="$Base\signatures"
$WinDir="$Base\windows_scan"

New-Item -ItemType Directory -Force -Path $LogDir,$BrowserDir,$NetDir,$PersistenceDir,$SigDir,$WinDir | Out-Null

$Report="$LogDir\Audit_Report.txt"
$ThreatFile="$LogDir\Threat_Report.txt"
$Timeline="$LogDir\timeline.txt"
$SigReport="$SigDir\signature_report.txt"

$RiskScore=0
$ThreatReasons=@()

function Section($name){
"" | Out-File $Report -Append
"=============================" | Out-File $Report -Append
$name | Out-File $Report -Append
"=============================" | Out-File $Report -Append
}

function Add-Threat($points,$reason){
if($ThreatReasons -notcontains $reason){
$script:RiskScore += $points
$script:ThreatReasons += "$points : $reason"
}
}

function Add-Info($msg){
"INFO : $msg" | Out-File $ThreatFile -Append
}

"LEVEL 8.5 SECURITY AUDIT (FIXED)" | Out-File $Report
"Date: $(Get-Date)" | Out-File $Report -Append

# -----------------------------
Section "SYSTEM INFO"
systeminfo | Out-File $Report -Append

# -----------------------------
Section "RUNNING PROCESSES"
$proc=Get-CimInstance Win32_Process
$proc | Select Name,ProcessId,ExecutablePath | Out-File "$LogDir\processes.txt"

if($proc.Count -gt 250){
Add-Info "Large number of processes running"
}

# -----------------------------
Section "TERMINAL ACTIVITY"

$events = Get-WinEvent -FilterHashtable @{
LogName='Security'
Id=4688
StartTime=(Get-Date).AddHours(-6)
} -MaxEvents 300

$termEvents = $events | Where {
$_.Message -match "powershell.exe|cmd.exe"
}

foreach($e in $termEvents | Select -First 20){

$time=$e.TimeCreated
$user = ($e.Message -split "Account Name:\s+")[1] -split "`n" | Select -First 1
$proc = ($e.Message -split "New Process Name:\s+")[1] -split "`n" | Select -First 1
$parent = ($e.Message -split "Creator Process Name:\s+")[1] -split "`n" | Select -First 1
$cmdline = ($e.Message -split "Process Command Line:\s+")[1] -split "`n" | Select -First 1

"$time | USER: $user | PROC: $proc | PARENT: $parent" | Out-File $Report -Append
"$time | $user | $cmdline" | Out-File $Timeline -Append

if($cmdline -match "-enc|base64"){
Add-Threat 5 "Encoded command by $user"
}

if($cmdline -match "Invoke-WebRequest|curl|wget"){
Add-Threat 3 "Download command used by $user"
}

}

# -----------------------------
Section "POWERSHELL HISTORY"

$psHist="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

if(Test-Path $psHist){

$history=Get-Content $psHist -Tail 30
$history | Out-File $Report -Append

foreach($cmd in $history){

if($cmd -match "Invoke-WebRequest|curl|wget"){
Add-Threat 3 "Download command in history"
}

if($cmd -match "FromBase64String"){
Add-Threat 4 "Obfuscated command in history"
}

}

}

# -----------------------------
Section "NETWORK CONNECTIONS"

$conns=Get-NetTCPConnection
$conns | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Out-File "$NetDir\network_connections.txt"

foreach($c in $conns){
if($c.RemotePort -eq 4444 -or $c.RemotePort -eq 1337){
Add-Threat 5 "Suspicious connection on port $($c.RemotePort)"
}
}

# -----------------------------
Section "SCHEDULED TASKS"

$tasks=Get-ScheduledTask
$tasks | Select TaskName,State | Out-File "$PersistenceDir\scheduled_tasks.txt"

$TaskWhitelist=@(
"Windows Defender Cache Maintenance",
"Windows Defender Cleanup",
"Windows Defender Scheduled Scan",
"Windows Defender Verification",
"Automatic-Device-Join",
"Recovery-Check",
"Monitoring"
)

foreach($t in $tasks){
if($TaskWhitelist -notcontains $t.TaskName){
$action=$t.Actions.Execute
if($action -match "powershell|cmd|wscript"){
Add-Threat 2 "Script-based task: $($t.TaskName)"
}
}
}

# -----------------------------
Section "AUTORUN ENTRIES"

$autoruns=@(
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach($path in $autoruns){
if(Test-Path $path){
$data=Get-ItemProperty $path
$data | Out-File "$PersistenceDir\autoruns.txt" -Append

foreach($prop in $data.PSObject.Properties){
$val=$prop.Value
if($val -match "powershell|cmd|wscript"){
Add-Threat 5 "Suspicious startup command: $val"
}
}
}
}

# -----------------------------
Section "SIGNATURE SCAN"

$scanTargets=@(
"$env:USERPROFILE\Downloads",
"$env:USERPROFILE\Desktop"
)

foreach($path in $scanTargets){
if(Test-Path $path){
Get-ChildItem $path -Filter *.exe -Recurse | Select -First 200 | ForEach-Object{
try{
$sig=Get-AuthenticodeSignature $_.FullName
if($sig.Status -eq "NotSigned"){
"UNSIGNED: $($_.FullName)" | Out-File $SigReport -Append
}
elseif($sig.Status -ne "Valid"){
Add-Threat 4 "Invalid signature: $($_.FullName)"
}
}catch{}
}
}
}

# -----------------------------
Section "WINDOWS SYSTEM INTEGRITY"

$winPaths=@(
"C:\Windows\System32",
"C:\Windows\SysWOW64"
)

foreach($path in $winPaths){
Get-ChildItem $path -Filter *.exe | Select -First 500 | ForEach-Object{
try{
$sig=Get-AuthenticodeSignature $_.FullName

if($sig.Status -eq "NotSigned"){
Add-Threat 3 "Unsigned system file: $($_.FullName)"
}
elseif($sig.Status -ne "Valid"){
Add-Threat 6 "Invalid system file signature: $($_.FullName)"
}
else{
$pub=$sig.SignerCertificate.Subject
if($pub -notmatch "Microsoft"){
Add-Threat 2 "Non-Microsoft system file: $($_.FullName)"
}
}

}catch{}
}
}

# -----------------------------
Section "SECURITY STATUS"

$def=Get-MpComputerStatus
if($def.AntivirusEnabled -eq $false){
Add-Threat 8 "Windows Defender disabled"
}

$fw=Get-NetFirewallProfile
foreach($p in $fw){
if($p.Enabled -eq $false){
Add-Threat 6 "Firewall disabled: $($p.Name)"
}
}

# -----------------------------
# FINAL SCORE (FIXED)
# -----------------------------

"----------------------------" | Out-File $ThreatFile
"THREAT ANALYSIS" | Out-File $ThreatFile -Append
"----------------------------" | Out-File $ThreatFile -Append

"Total Score: $RiskScore" | Out-File $ThreatFile -Append

foreach($r in $ThreatReasons){
$r | Out-File $ThreatFile -Append
}

"" | Out-File $ThreatFile -Append

if($RiskScore -eq 0){
"System appears clean." | Out-File $ThreatFile -Append
"Risk Level: LOW" | Out-File $ThreatFile -Append
}
elseif($RiskScore -lt 15){
"Risk Level: LOW" | Out-File $ThreatFile -Append
}
elseif($RiskScore -lt 35){
"Risk Level: MODERATE" | Out-File $ThreatFile -Append
}
else{
"Risk Level: HIGH" | Out-File $ThreatFile -Append
}
