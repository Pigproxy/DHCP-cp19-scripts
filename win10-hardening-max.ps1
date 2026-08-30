<#
   by Ethan Reeise
    Run:
      Set-ExecutionPolicy Bypass -Scope Process -Force
      .\win10-hardening-max.ps1
#>

$ErrorActionPreference = 'Continue'
$BackupRoot = Join-Path $env:SystemDrive ("CyberPatriot-Backup-{0:yyyyMMdd-HHmmss}" -f (Get-Date))
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null

function Step($Name) { Write-Host "`n=== $Name ===" -ForegroundColor Cyan }
function Ok($Text) { Write-Host "[OK] $Text" -ForegroundColor Green }
function Warn($Text) { Write-Host "[REVIEW] $Text" -ForegroundColor Yellow }
function Try-Do($Text, [scriptblock]$Action) {
    try { & $Action; Ok $Text }
    catch { Warn "$Text -- $($_.Exception.Message)" }
}
function Pause-Step($Message) {
    Write-Host "`n[CHECKPOINT] $Message" -ForegroundColor Yellow
    Read-Host "Press Enter to continue (Ctrl+C to stop)"
}

# ---- Competition-specific knobs: change these to match the scoring packet ----
$DisableRdp = $true
$DisableRemoteRegistry = $true
$DisableTelnet = $true
$DisableWinRM = $false       # Leave enabled if the image/scoring requires remote management.
$DisableLlmnr = $true
$DisableNetbios = $false     # Network-dependent; review before enabling.
$EnableBitLocker = $false    # Do NOT enable blindly on competition images.
$EnableHvci = $false         # Driver compatibility can make this unsafe to force blindly.
$MinPasswordLength = 10      # Replace with the exact scoring requirement if specified.
$MaxPasswordAge = 90
$MinPasswordAge = 1
$LockoutThreshold = 5
$LockoutDuration = 30
$LockoutWindow = 30

# ---- Must be Administrator ----
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

Step "FORENSICS CHECKPOINT"
Write-Host "Do NOT destroy evidence before answering the forensics questions." -ForegroundColor Yellow
Pause-Step "Confirm the forensics/scoring questions have been reviewed."

Step "BACKUP / BASELINE"
Try-Do "Exporting registry backup" {
    reg.exe export HKLM "$BackupRoot\HKLM.reg" /y | Out-Null
}
Try-Do "Exporting security policy" {
    secedit.exe /export /cfg "$BackupRoot\secpol-before.inf" /quiet
}
Try-Do "Saving firewall configuration" {
    netsh.exe advfirewall export "$BackupRoot\firewall-before.wfw" | Out-Null
}
Try-Do "Saving service configuration" {
    Get-Service | Select-Object Name,Status,StartType | Export-Csv "$BackupRoot\services-before.csv" -NoTypeInformation
}

Step "ACCOUNT AUDIT"
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired | Format-Table -AutoSize
Write-Host "`nAdministrators:" -ForegroundColor White
Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass | Format-Table -AutoSize
Write-Host "`nReview every account against the scoring packet. Do not remove required/scoring accounts." -ForegroundColor Yellow

# Guest is normally unnecessary and is a standard hardening action.
Try-Do "Disabling built-in Guest account" {
    Disable-LocalUser -Name "Guest" -ErrorAction Stop
}

Step "PASSWORD / LOCKOUT POLICY"
Try-Do "Applying account policy baseline" {
    net.exe accounts `
        /minpwlen:$MinPasswordLength `
        /maxpwage:$MaxPasswordAge `
        /minpwage:$MinPasswordAge `
        /lockoutthreshold:$LockoutThreshold `
        /lockoutduration:$LockoutDuration `
        /lockoutwindow:$LockoutWindow | Out-Null
}
Warn "If the scoring packet specifies different exact values, change the variables at the top before running."

Step "FIREWALL"
Try-Do "Enabling Windows Firewall for all profiles" {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow
}

Step "MICROSOFT DEFENDER"
Try-Do "Enabling Defender real-time protection" {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -DisableArchiveScanning $false
    Set-MpPreference -DisableEmailScanning $false
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples
}
Try-Do "Enabling potentially unwanted application protection" {
    Set-MpPreference -PUAProtection Enabled
}
Get-MpComputerStatus | Select-Object AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled | Format-List

Step "WINDOWS UPDATE"
Try-Do "Setting Windows Update to Automatic" {
    Set-Service -Name wuauserv -StartupType Automatic
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
}
Try-Do "Setting BITS to Automatic (Delayed Start)" {
    Set-Service -Name BITS -StartupType Automatic
    Start-Service -Name BITS -ErrorAction SilentlyContinue
}

Step "SMB / LEGACY PROTOCOLS"
Try-Do "Disabling SMBv1" {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
}
Try-Do "Disabling SMBv1 server configuration" {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue | Out-Null
}

Step "REMOTE ACCESS"
if ($DisableRdp) {
    Try-Do "Disabling Remote Desktop" {
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    }
}
if ($DisableRemoteRegistry) {
    Try-Do "Disabling Remote Registry" {
        Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue
        Set-Service RemoteRegistry -StartupType Disabled
    }
}
if ($DisableTelnet) {
    Try-Do "Disabling Telnet service" {
        if (Get-Service TlntSvr -ErrorAction SilentlyContinue) {
            Stop-Service TlntSvr -Force -ErrorAction SilentlyContinue
            Set-Service TlntSvr -StartupType Disabled
        }
    }
}
if ($DisableWinRM) {
    Try-Do "Disabling WinRM" {
        Disable-PSRemoting -Force -ErrorAction SilentlyContinue
        Stop-Service WinRM -Force -ErrorAction SilentlyContinue
        Set-Service WinRM -StartupType Disabled
    }
}

Step "UAC / CREDENTIAL HARDENING"
Try-Do "Enabling UAC and secure elevation prompt" {
    $uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-ItemProperty $uac EnableLUA 1
    Set-ItemProperty $uac ConsentPromptBehaviorAdmin 2
    Set-ItemProperty $uac PromptOnSecureDesktop 1
    Set-ItemProperty $uac EnableInstallerDetection 1
}
Try-Do "Disabling anonymous SID/name enumeration" {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-ItemProperty $lsa RestrictAnonymous 1
    Set-ItemProperty $lsa RestrictAnonymousSAM 1
}
Try-Do "Disabling LAN Manager hash storage" {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-ItemProperty $lsa NoLMHash 1
}
Try-Do "Disabling LLMNR" {
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0
}

Step "AUDITING"
Try-Do "Enabling advanced audit categories" {
    auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol.exe /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
    auditpol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
    auditpol.exe /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
    auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
    auditpol.exe /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
    auditpol.exe /set /subcategory:"System Integrity" /success:enable /failure:enable | Out-Null
}
Try-Do "Enabling command-line auditing for process creation" {
    New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1
}

Step "SECURITY OPTIONS"
Try-Do "Disabling autorun/autoplay for non-fixed media" {
    $explorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    New-Item $explorer -Force | Out-Null
    Set-ItemProperty $explorer NoDriveTypeAutoRun 255
}
Try-Do "Enabling Windows Defender SmartScreen" {
    $system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
    Set-ItemProperty $system SmartScreenEnabled RequireAdmin -ErrorAction SilentlyContinue
}
Try-Do "Disabling insecure guest logons for SMB client" {
    $lanman = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
    New-Item $lanman -Force | Out-Null
    Set-ItemProperty $lanman AllowInsecureGuestAuth 0
}

Step "SERVICES REVIEW"
$services = @('RemoteRegistry','TlntSvr')
Get-Service | Where-Object { $_.Status -eq 'Running' } |
    Sort-Object Name | Select-Object Name,DisplayName,StartType | Format-Table -AutoSize
Warn "Review running services against the image requirements. Do not blindly disable services needed by scoring, networking, or applications."

Step "SCHEDULED TASKS / STARTUP"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } |
    Select-Object TaskName,TaskPath,State,Author | Format-Table -AutoSize
Get-CimInstance Win32_StartupCommand |
    Select-Object Name,Command,Location,User | Format-Table -AutoSize

Step "SHARES / OPEN NETWORKING"
try {
    Get-SmbShare | Select-Object Name,Path,Description,ShareType | Format-Table -AutoSize
} catch { Warn "SMB share enumeration unavailable." }
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,OwningProcess |
    Format-Table -AutoSize
Warn "Investigate unexpected listeners and shares; don't remove them without confirming the scoring packet."

Step "PROHIBITED / SUSPICIOUS FILE REVIEW"
$extensions = @('*.mp3','*.mp4','*.avi','*.mkv','*.torrent','*.iso')
Get-ChildItem C:\Users -Recurse -Include $extensions -File -ErrorAction SilentlyContinue |
    Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize
Warn "Review before deleting. Files may be forensic evidence or legitimate scoring artifacts."

Step "BITLOCKER / OPTIONAL HARDENING"
try { Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod | Format-Table -AutoSize }
catch { Warn "BitLocker cmdlet unavailable." }
if ($EnableBitLocker) {
    Warn "BitLocker was requested by configuration, but automatic encryption is intentionally not performed by this template."
}
if ($EnableHvci) {
    Warn "HVCI is intentionally reported rather than force-enabled because driver compatibility can break the image."
}
try {
    $hvci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction Stop
    $hvci | Select-Object Enabled,WasEnabledBy | Format-List
} catch { Warn "HVCI status could not be read." }

Step "FINAL VERIFICATION"
Write-Host "`nFirewall:"; Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table
Write-Host "`nAccounts:"; Get-LocalUser | Select-Object Name,Enabled | Format-Table
Write-Host "`nPolicy:"; net accounts
Write-Host "`nBackup: $BackupRoot" -ForegroundColor Green

Write-Host "`n=== HARDENING PASS COMPLETE ===" -ForegroundColor Cyan
Warn "Now compare every change with the CyberPatriot scoring report and rules packet. Exact image-specific requirements take priority over this generic baseline."
