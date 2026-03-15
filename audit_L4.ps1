$ErrorActionPreference="SilentlyContinue"

$Base="$PSScriptRoot"

$LogDir="$Base\logs"
$HashDir="$Base\hashes"
$BrowserDir="$Base\browser"
$NetDir="$Base\network"
$PersistenceDir="$Base\persistence"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $HashDir | Out-Null
New-Item -ItemType Directory -Force -Path $BrowserDir | Out-Null
New-Item -ItemType Directory -Force -Path $NetDir | Out-Null
New-Item -ItemType Directory -Force -Path $PersistenceDir | Out-Null

$Report="$LogDir\Audit_Report.txt"
$ThreatFile="$LogDir\Threat_Score.txt"

$RiskScore=0
$ThreatReasons=@()

function Section($name){
"" | Out-File $Report -Append
"==========================" | Out-File $Report -Append
$name | Out-File $Report -Append
"==========================" | Out-File $Report -Append
}

function Add-Threat($points,$reason){
$script:RiskScore += $points
$script:ThreatReasons += "$points : $reason"
}

"LEVEL 5 SECURITY AUDIT" | Out-File $Report
"Date: $(Get-Date)" | Out-File $Report -Append

# ----------------------------
Section "SYSTEM INFO"
systeminfo | Out-File $Report -Append

# ----------------------------
Section "LOCAL USERS"
Get-LocalUser | Out-File $Report -Append

# ----------------------------
Section "ADMINISTRATORS"

$admins=Get-LocalGroupMember Administrators
$admins | Out-File $Report -Append

if($admins.Count -gt 3){
Add-Threat 2 "Large number of administrator accounts"
}

# ----------------------------
Section "RUNNING PROCESSES"

$proc=Get-CimInstance Win32_Process |
Select Name,ProcessId,ExecutablePath

$proc | Out-File $Report -Append

$suspicious=@(
"powershell",
"cmd",
"wscript",
"cscript",
"mshta",
"rundll32",
"bitsadmin",
"certutil"
)

foreach($p in $proc){

foreach($s in $suspicious){

if($p.Name -like "*$s*"){
Add-Threat 1 "Script or living-off-the-land process running: $($p.Name)"
}

}

}

# ----------------------------
Section "NETWORK CONNECTIONS"

Get-NetTCPConnection |
Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
Out-File "$NetDir\network_connections.txt"

# ----------------------------
Section "OPEN PORTS"
netstat -ano | Out-File "$NetDir\open_ports.txt"

# ----------------------------
Section "DNS CACHE"
ipconfig /displaydns | Out-File "$NetDir\dns_cache.txt"

# ----------------------------
Section "SERVICES"

$services=Get-Service
$services | Out-File $Report -Append

# ----------------------------
Section "SCHEDULED TASKS"

$tasks=Get-ScheduledTask
$tasks | Out-File "$PersistenceDir\scheduled_tasks.txt"

if($tasks.Count -gt 120){
Add-Threat 1 "Large number of scheduled tasks"
}

# ----------------------------
Section "STARTUP FOLDERS"

Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" |
Out-File "$PersistenceDir\user_startup.txt"

Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" |
Out-File "$PersistenceDir\system_startup.txt"

# ----------------------------
Section "REGISTRY AUTORUN LOCATIONS"

$autoruns=@(
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

foreach($path in $autoruns){

if(Test-Path $path){

$data=Get-ItemProperty $path
$data | Out-File "$PersistenceDir\registry_autoruns.txt" -Append

foreach($prop in $data.PSObject.Properties){

if($prop.Value -match "powershell"){
Add-Threat 3 "PowerShell persistence found"
}

}

}

}

# ----------------------------
Section "UNSIGNED EXECUTABLES"

$scan=@(
"C:\Users",
"C:\Program Files",
"C:\Program Files (x86)"
)

foreach($path in $scan){

Get-ChildItem $path -Recurse -File |
Where {$_.Extension -eq ".exe"} |
ForEach-Object{

try{

$sig=Get-AuthenticodeSignature $_.FullName

if($sig.Status -ne "Valid"){
Add-Threat 1 "Unsigned executable: $($_.FullName)"
}

}catch{}

}

}

# ----------------------------
Section "SYSTEM HASHES"

Get-ChildItem C:\Windows\System32 -File |
ForEach-Object{

try{
Get-FileHash $_.FullName
}catch{}

} | Export-Csv "$HashDir\system_hashes.csv" -NoTypeInformation

# ----------------------------
Section "WINDOWS DEFENDER"

$def=Get-MpComputerStatus
$def | Out-File $Report -Append

if($def.AntivirusEnabled -eq $false){
Add-Threat 5 "Antivirus disabled"
}

# ----------------------------
Section "FIREWALL"

$fw=Get-NetFirewallProfile
$fw | Out-File $Report -Append

foreach($p in $fw){

if($p.Enabled -eq $false){
Add-Threat 4 "Firewall disabled on $($p.Name)"
}

}

# ----------------------------
Section "BROWSER EXTENSIONS"

$chrome="$env:LOCALAPPDATA\Google\Chrome\User Data"

if(Test-Path $chrome){

Get-ChildItem $chrome -Directory |
ForEach-Object{

$ext="$($_.FullName)\Extensions"

if(Test-Path $ext){
Get-ChildItem $ext -Directory
}

} | Select FullName |
Out-File "$BrowserDir\chrome_extensions.txt"

}

# ----------------------------
Section "EVENT LOGS"

Get-WinEvent -LogName Security -MaxEvents 400 |
Out-File "$LogDir\Security_Events.txt"

Get-WinEvent -LogName System -MaxEvents 400 |
Out-File "$LogDir\System_Events.txt"

# ----------------------------
Section "THREAT SCORE"

"Total Score: $RiskScore" | Out-File $ThreatFile

foreach($r in $ThreatReasons){
$r | Out-File $ThreatFile -Append
}

"" | Out-File $ThreatFile -Append

if($RiskScore -lt 5){
"Risk Level: LOW" | Out-File $ThreatFile -Append
}
elseif($RiskScore -lt 15){
"Risk Level: MODERATE" | Out-File $ThreatFile -Append
}
else{
"Risk Level: HIGH" | Out-File $ThreatFile -Append
}
