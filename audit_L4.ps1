$ErrorActionPreference = "SilentlyContinue"

$Base = "$PSScriptRoot"
$LogDir = "$Base\logs"
$HashDir = "$Base\hashes"
$BrowserDir = "$Base\browser"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $HashDir | Out-Null
New-Item -ItemType Directory -Force -Path $BrowserDir | Out-Null

$Report = "$LogDir\Audit_Level4.txt"
$RiskScore = 0

function Section($name){
"" | Out-File $Report -Append
"==============================" | Out-File $Report -Append
$name | Out-File $Report -Append
"==============================" | Out-File $Report -Append
}

"LEVEL 4 FORENSIC SECURITY AUDIT" | Out-File $Report
"Date: $(Get-Date)" | Out-File $Report -Append

# ------------------------
Section "SYSTEM INFORMATION"
systeminfo | Out-File $Report -Append

# ------------------------
Section "ADMINISTRATOR ACCOUNTS"

$admins = Get-LocalGroupMember Administrators
$admins | Out-File $Report -Append

if($admins.Count -gt 3){
    $RiskScore++
}

# ------------------------
Section "PROCESS TREE"

Get-CimInstance Win32_Process |
Select Name,ProcessId,ParentProcessId,ExecutablePath |
Out-File $Report -Append

# ------------------------
Section "LOADED DLL MODULES"

Get-Process | ForEach-Object {

    try{
        $_.Modules |
        Select ModuleName,FileName
    } catch {}

} | Out-File $Report -Append

# ------------------------
Section "NETWORK CONNECTIONS"

Get-NetTCPConnection |
Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
Out-File $Report -Append

# ------------------------
Section "DRIVERS"

driverquery /v | Out-File $Report -Append

# ------------------------
Section "BOOT CONFIGURATION"

bcdedit | Out-File $Report -Append

# ------------------------
Section "SERVICES"

Get-Service | Out-File $Report -Append

# ------------------------
Section "SCHEDULED TASKS"

Get-ScheduledTask |
Select TaskName,State,TaskPath |
Out-File $Report -Append

# ------------------------
Section "AUTORUN REGISTRY LOCATIONS"

$paths = @(
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach($p in $paths){

    if(Test-Path $p){
        Get-ItemProperty $p | Out-File $Report -Append
    }

}

# ------------------------
Section "RECENT EXECUTABLE FILES"

Get-ChildItem C:\Users -Recurse -File |
Where-Object { $_.Extension -match ".exe|.ps1|.bat|.vbs" } |
Select FullName,LastWriteTime |
Out-File $Report -Append

# ------------------------
Section "UNSIGNED EXECUTABLES"

$scanPaths = @(
"C:\Users",
"C:\Program Files",
"C:\Program Files (x86)",
"C:\Windows"
)

foreach($path in $scanPaths){

Get-ChildItem $path -Recurse -File |
Where-Object { $_.Extension -eq ".exe" } |
ForEach-Object {

    try{

        $sig = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction Stop

        if($sig.Status -ne "Valid"){
            $_.FullName | Out-File $Report -Append
            $RiskScore++
        }

    } catch {}

}

}

# ------------------------
Section "SYSTEM FILE HASHES"

Get-ChildItem C:\Windows\System32 -File |
ForEach-Object {

    try{
        Get-FileHash $_.FullName
    }
    catch{}

} | Export-Csv "$HashDir\system32_hashes.csv" -NoTypeInformation

"Hashes exported to hashes folder." | Out-File $Report -Append

# ------------------------
Section "BROWSER EXTENSIONS"

$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"

if(Test-Path $chrome){

Get-ChildItem $chrome |
Select Name |
Out-File "$BrowserDir\chrome_extensions.txt"

}

# ------------------------
Section "SECURITY EVENTS"

Get-WinEvent -LogName Security -MaxEvents 300 |
Out-File $Report -Append

# ------------------------
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

# ------------------------
Section "AUDIT COMPLETE"