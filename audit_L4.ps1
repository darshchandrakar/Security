$ErrorActionPreference="SilentlyContinue"

$Base="$PSScriptRoot"
$LogDir="$Base\logs"
$HashDir="$Base\hashes"
$BrowserDir="$Base\browser"
$NetDir="$Base\network"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $HashDir | Out-Null
New-Item -ItemType Directory -Force -Path $BrowserDir | Out-Null
New-Item -ItemType Directory -Force -Path $NetDir | Out-Null

$Report="$LogDir\Audit_Full.txt"
$RiskScore=0

function Section($t){
"" | Out-File $Report -Append
"==============================" | Out-File $Report -Append
$t | Out-File $Report -Append
"==============================" | Out-File $Report -Append
}

"FULL SECURITY AUDIT REPORT" | Out-File $Report
"Date: $(Get-Date)" | Out-File $Report -Append

Section "SYSTEM INFORMATION"
systeminfo | Out-File $Report -Append

Section "BIOS / FIRMWARE"
Get-CimInstance Win32_BIOS | Out-File $Report -Append

Section "OPERATING SYSTEM"
Get-CimInstance Win32_OperatingSystem | Out-File $Report -Append

Section "LOCAL USERS"
Get-LocalUser | Out-File $Report -Append

Section "ADMINISTRATORS"
$admins=Get-LocalGroupMember Administrators
$admins | Out-File $Report -Append
if($admins.Count -gt 3){$RiskScore++}

Section "RUNNING PROCESSES"
Get-CimInstance Win32_Process |
Select Name,ProcessId,ParentProcessId,ExecutablePath |
Out-File $Report -Append

Section "PROCESS NETWORK CONNECTIONS"
Get-NetTCPConnection |
Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
Out-File "$NetDir\network_connections.txt"

Section "OPEN PORTS"
netstat -ano | Out-File "$NetDir\open_ports.txt"

Section "ARP TABLE"
arp -a | Out-File "$NetDir\arp_table.txt"

Section "DNS CACHE"
ipconfig /displaydns | Out-File "$NetDir\dns_cache.txt"

Section "SERVICES"
Get-Service | Out-File $Report -Append

Section "DRIVERS"
driverquery /v | Out-File $Report -Append

Section "BOOT CONFIGURATION"
bcdedit | Out-File $Report -Append

Section "SCHEDULED TASKS"
Get-ScheduledTask |
Select TaskName,State,TaskPath |
Out-File $Report -Append

Section "STARTUP FOLDERS"
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" |
Out-File $Report -Append
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" |
Out-File $Report -Append

Section "REGISTRY AUTORUN LOCATIONS"

$autoruns=@(
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach($p in $autoruns){
if(Test-Path $p){Get-ItemProperty $p | Out-File $Report -Append}
}

Section "INSTALLED SOFTWARE"

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select DisplayName,DisplayVersion |
Out-File $Report -Append

Section "WINDOWS DEFENDER STATUS"
Get-MpComputerStatus | Out-File $Report -Append

Section "FIREWALL STATUS"
Get-NetFirewallProfile | Out-File $Report -Append

Section "RECENT EXECUTABLE FILES"

Get-ChildItem C:\Users -Recurse -File |
Where {$_.Extension -match ".exe|.ps1|.bat|.vbs"} |
Select FullName,LastWriteTime |
Out-File $Report -Append

Section "UNSIGNED EXECUTABLES"

$scanPaths=@(
"C:\Users",
"C:\Program Files",
"C:\Program Files (x86)"
)

foreach($path in $scanPaths){

Get-ChildItem $path -Recurse -File |
Where {$_.Extension -eq ".exe"} |
ForEach-Object{

try{
$sig=Get-AuthenticodeSignature $_.FullName
if($sig.Status -ne "Valid"){
$_.FullName | Out-File $Report -Append
$RiskScore++
}
}catch{}

}

}

Section "SYSTEM FILE HASHES"

Get-ChildItem C:\Windows\System32 -File |
ForEach-Object{
try{Get-FileHash $_.FullName}catch{}
} | Export-Csv "$HashDir\system_hashes.csv" -NoTypeInformation

Section "BROWSER EXTENSIONS"

$chrome="$env:LOCALAPPDATA\Google\Chrome\User Data"
if(Test-Path $chrome){
Get-ChildItem $chrome -Directory |
ForEach-Object{
$ext="$($_.FullName)\Extensions"
if(Test-Path $ext){Get-ChildItem $ext -Directory}
} | Select FullName | Out-File "$BrowserDir\chrome_extensions.txt"
}

$edge="$env:LOCALAPPDATA\Microsoft\Edge\User Data"
if(Test-Path $edge){
Get-ChildItem $edge -Directory |
ForEach-Object{
$ext="$($_.FullName)\Extensions"
if(Test-Path $ext){Get-ChildItem $ext -Directory}
} | Select FullName | Out-File "$BrowserDir\edge_extensions.txt"
}

$firefox="$env:APPDATA\Mozilla\Firefox\Profiles"
if(Test-Path $firefox){
Get-ChildItem $firefox -Directory |
ForEach-Object{
$ext="$($_.FullName)\extensions"
if(Test-Path $ext){Get-ChildItem $ext}
} | Select FullName | Out-File "$BrowserDir\firefox_extensions.txt"
}

Section "EVENT LOGS"

Get-WinEvent -LogName Security -MaxEvents 300 |
Out-File "$LogDir\security_events.txt"

Get-WinEvent -LogName System -MaxEvents 300 |
Out-File "$LogDir\system_events.txt"

Section "RISK SCORE"

"Risk Score: $RiskScore" | Out-File $Report -Append

if($RiskScore -lt 3){
"Low risk indicators detected" | Out-File $Report -Append
}
elseif($RiskScore -lt 7){
"Moderate suspicious indicators detected" | Out-File $Report -Append
}
else{
"High risk indicators detected" | Out-File $Report -Append
}

Section "AUDIT COMPLETE"
