$ErrorActionPreference="SilentlyContinue"

$Base=$PSScriptRoot

$LogDir="$Base\logs"
$BrowserDir="$Base\browser"
$NetDir="$Base\network"
$PersistenceDir="$Base\persistence"

New-Item -ItemType Directory -Force -Path $LogDir,$BrowserDir,$NetDir,$PersistenceDir | Out-Null

$Report="$LogDir\Audit_Report.txt"
$ThreatFile="$LogDir\Threat_Report.txt"

$RiskScore=0
$ThreatReasons=@()

"LEVEL 7 SECURITY AUDIT" | Out-File $Report
"Date: $(Get-Date)" | Out-File $Report -Append


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


# -----------------------------
Section "SYSTEM INFORMATION"

systeminfo | Out-File $Report -Append


# -----------------------------
Section "RUNNING PROCESSES"

$proc=Get-CimInstance Win32_Process

$proc |
Select Name,ProcessId,ExecutablePath |
Out-File "$LogDir\processes.txt"

if($proc.Count -gt 250){

Add-Info "Large number of running processes detected"

}


# -----------------------------
Section "NETWORK CONNECTIONS"

$connections=Get-NetTCPConnection

$connections |
Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State |
Out-File "$NetDir\network_connections.txt"

if($connections.Count -gt 30){

Add-Info "Many active network connections"

}

foreach($c in $connections){

if($c.RemotePort -eq 4444 -or $c.RemotePort -eq 1337){

Add-Threat 4 "Connection to suspicious remote port $($c.RemotePort)"

}

}


# -----------------------------
Section "SCHEDULED TASKS"

$tasks=Get-ScheduledTask

$tasks |
Select TaskName,State |
Out-File "$PersistenceDir\scheduled_tasks.txt"

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

if($action -match "powershell.exe|cmd.exe|wscript.exe"){

Add-Threat 2 "Script-based scheduled task: $($t.TaskName)"

}

}

}

if($tasks.Count -gt 100){

Add-Info "System contains many scheduled tasks (normal for Windows)"

}


# -----------------------------
Section "REGISTRY AUTORUN LOCATIONS"

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

if($val -match "powershell.exe" -or $val -match "pwsh.exe"){

Add-Threat 4 "PowerShell startup command detected: $val"

}

}

}

}


# -----------------------------
Section "WINDOWS DEFENDER STATUS"

$def=Get-MpComputerStatus

$def | Out-File "$LogDir\defender_status.txt"

if($def.AntivirusEnabled -eq $false){

Add-Threat 6 "Windows Defender disabled"

}else{

Add-Info "Windows Defender active"

}


# -----------------------------
Section "FIREWALL STATUS"

$fw=Get-NetFirewallProfile

$fw | Out-File "$LogDir\firewall_status.txt"

foreach($p in $fw){

if($p.Enabled -eq $false){

Add-Threat 5 "Firewall disabled on profile: $($p.Name)"

}

}


# -----------------------------
Section "BROWSER EXTENSIONS"

$ChromiumPaths=@(

"$env:LOCALAPPDATA\Google\Chrome\User Data",
"$env:LOCALAPPDATA\Microsoft\Edge\User Data"

)

foreach($basePath in $ChromiumPaths){

if(Test-Path $basePath){

Get-ChildItem $basePath -Directory |
Where {$_.Name -match "Default|Profile"} |
ForEach-Object{

$ext="$($_.FullName)\Extensions"

if(Test-Path $ext){

Get-ChildItem $ext -Directory |
Select FullName |
Out-File "$BrowserDir\chromium_extensions.txt" -Append

}

}

}

}


# -----------------------------
Section "SECURITY EVENT LOG"

$events=Get-WinEvent -LogName Security -MaxEvents 200

$events |
Out-File "$LogDir\Security_Events.txt"

$failed=($events | Where {$_.Id -eq 4625}).Count

if($failed -gt 5){

Add-Threat 2 "Multiple failed login attempts detected"

}elseif($failed -gt 0){

Add-Info "Some failed login attempts recorded"

}


# -----------------------------
Section "THREAT SCORE"

"----------------------------" | Out-File $ThreatFile
"THREAT ANALYSIS" | Out-File $ThreatFile -Append
"----------------------------" | Out-File $ThreatFile -Append

"Total Score: $RiskScore" | Out-File $ThreatFile -Append

foreach($r in $ThreatReasons){

$r | Out-File $ThreatFile -Append

}

"" | Out-File $ThreatFile -Append

if($RiskScore -eq 0){

"System appears clean. No threat indicators detected." | Out-File $ThreatFile -Append
"Risk Level: LOW" | Out-File $ThreatFile -Append

}elseif($RiskScore -lt 10){

"Risk Level: LOW" | Out-File $ThreatFile -Append

}elseif($RiskScore -lt 25){

"Risk Level: MODERATE" | Out-File $ThreatFile -Append

}else{

"Risk Level: HIGH" | Out-File $ThreatFile -Append

}
