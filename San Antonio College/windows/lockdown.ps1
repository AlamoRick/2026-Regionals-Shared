# =============================================================================
# lockdown.ps1 -- Windows/AD Hardening Script
# San Antonio College -- SWCCDC 2026
# Based on University of Tulsa's win-lockdown.ps1 pattern
#
# Works on Windows 10/11 + Server. Detects what's installed and hardens it.
# Each section pauses so you can skip if needed.
#
# Usage: powershell -ExecutionPolicy Bypass -File lockdown.ps1
# =============================================================================

$ErrorActionPreference = "SilentlyContinue"
$OS = (Get-CimInstance Win32_OperatingSystem).Caption
$IsServer = $OS -match "Server"

Write-Host ""
Write-Host "============================================" -ForegroundColor Magenta
Write-Host "  Windows Lockdown -- San Antonio College" -ForegroundColor White
Write-Host "  OS: $OS" -ForegroundColor Cyan
Write-Host "  Host: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Magenta

function Pause-Section($Title) {
    Write-Host ""
    Write-Host "==============================" -ForegroundColor Yellow
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "==============================" -ForegroundColor Yellow
    $resp = Read-Host "  Run this section? (y/n)"
    return ($resp -match "^[yY]")
}

# =============================================================================
# INVENTORY -- Run first, always
# =============================================================================
Write-Host ""
Write-Host "=== INVENTORY ===" -ForegroundColor Green

Write-Host "IP Addresses:" -ForegroundColor Cyan
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1" } |
    Format-Table IPAddress, InterfaceAlias -AutoSize

Write-Host "Listening Ports:" -ForegroundColor Cyan
Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        "  Port {0,-6} PID {1,-6} ({2})" -f $_.LocalPort, $_.OwningProcess, $proc.Name
    } | Select-Object -First 25

Write-Host "Local Users:" -ForegroundColor Cyan
Get-LocalUser | ForEach-Object {
    $status = if ($_.Enabled) { "ENABLED" } else { "disabled" }
    "  {0,-20} {1}" -f $_.Name, $status
}

Write-Host "Local Admins:" -ForegroundColor Cyan
Get-LocalGroupMember -Group "Administrators" | ForEach-Object { "  $($_.Name)" }

if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory
    Write-Host "Domain Admins:" -ForegroundColor Cyan
    Get-ADGroupMember "Domain Admins" | ForEach-Object { "  $($_.Name)" }
}

Write-Host ""
if (Get-WindowsFeature -ErrorAction SilentlyContinue) {
    Write-Host "Installed Roles:" -ForegroundColor Cyan
    Get-WindowsFeature | Where-Object Installed | ForEach-Object { "  $($_.Name)" }
}

Read-Host "Press Enter to begin hardening..."

# =============================================================================
# PASSWORDS
# =============================================================================
if (Pause-Section "CHANGE PASSWORDS") {
    $NewPass = Read-Host "Enter new password for admin accounts" -AsSecureString
    $Plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPass))

    net user Administrator $Plain 2>&1 | Out-Null
    Write-Host "  [+] Local Administrator" -ForegroundColor Green

    Get-LocalUser | Where-Object Enabled | ForEach-Object {
        if ($_.Name -ne "Administrator") {
            net user $_.Name $Plain 2>&1 | Out-Null
            Write-Host "  [+] $($_.Name)" -ForegroundColor Green
        }
    }

    if (Get-Module -Name ActiveDirectory) {
        try {
            Set-ADAccountPassword -Identity "Administrator" -NewPassword $NewPass -Reset
            Write-Host "  [+] Domain Administrator" -ForegroundColor Green
        } catch { Write-Host "  [-] Domain Admin password change failed" -ForegroundColor Red }
    }

    "Password: $Plain" | Out-File "C:\passwords_$env:COMPUTERNAME.txt"
    Write-Host "  [!] Saved to C:\passwords_$env:COMPUTERNAME.txt -- DELETE AFTER PORTAL UPDATE" -ForegroundColor Yellow
}

# =============================================================================
# BASELINE HARDENING (always recommended)
# =============================================================================
if (Pause-Section "BASELINE HARDENING") {
    # Firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed True
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" 2>&1 | Out-Null
    Write-Host "  [+] Firewall: ON, default BLOCK inbound" -ForegroundColor Green

    # Disable Guest
    net user Guest /active:no 2>&1 | Out-Null
    Write-Host "  [+] Guest account disabled" -ForegroundColor Green

    # SMBv1
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 2>&1 | Out-Null
    Write-Host "  [+] SMBv1 disabled" -ForegroundColor Green

    # SMB signing
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force 2>&1 | Out-Null
    Write-Host "  [+] SMB signing required" -ForegroundColor Green

    # Password policy
    net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 2>&1 | Out-Null
    Write-Host "  [+] Password policy set (min 12 chars, lockout after 5)" -ForegroundColor Green

    # Auditing
    auditpol /set /category:* /success:enable /failure:enable 2>&1 | Out-Null
    wevtutil sl Security /ms:1073741824 2>&1 | Out-Null
    Write-Host "  [+] Full auditing enabled, log size 1GB" -ForegroundColor Green

    # RDP NLA
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
    Write-Host "  [+] RDP NLA enabled" -ForegroundColor Green

    # Block dangerous ports
    netsh advfirewall firewall add rule name="Block-Dangerous" protocol=TCP dir=in localport=137,138,139,5800,5900 action=block 2>&1 | Out-Null
    Write-Host "  [+] Blocked inbound NetBIOS/VNC ports" -ForegroundColor Green

    # Disable unnecessary services
    foreach ($svc in @("RemoteRegistry","SSDPSRV","upnphost","WerSvc","Fax","TlntSvr")) {
        $s = Get-Service $svc -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq "Running") {
            Stop-Service $svc -Force; Set-Service $svc -StartupType Disabled
            Write-Host "  [!] Disabled: $svc" -ForegroundColor Yellow
        }
    }

    # Credential hardening
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
    Write-Host "  [+] LM hashes disabled, NTLMv2 only, LLMNR disabled" -ForegroundColor Green
}

# =============================================================================
# SERVICE-SPECIFIC HARDENING
# =============================================================================
Write-Host ""
Write-Host "==============================" -ForegroundColor Yellow
Write-Host "  Select services to harden:" -ForegroundColor White
Write-Host "  [1] Active Directory" -ForegroundColor Cyan
Write-Host "  [2] DNS Server" -ForegroundColor Cyan
Write-Host "  [3] DHCP Server" -ForegroundColor Cyan
Write-Host "  [4] IIS Web Server" -ForegroundColor Cyan
Write-Host "  [5] FTP (IIS)" -ForegroundColor Cyan
Write-Host "  [6] File Server (SMB)" -ForegroundColor Cyan
Write-Host "  [7] Exchange" -ForegroundColor Cyan
Write-Host "  [0] Skip / None" -ForegroundColor Cyan
$selection = Read-Host 'Enter numbers separated by commas, e.g. 1,2,4'
$choices = $selection -split "," | ForEach-Object { $_.Trim() }

foreach ($c in $choices) {
    switch ($c) {
        "1" {
            Write-Host "`n  === Active Directory ===" -ForegroundColor Green
            if (Get-Module -Name ActiveDirectory) {
                Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
                    -MinPasswordLength 12 -ComplexityEnabled $true `
                    -LockoutThreshold 5 -LockoutDuration "00:30:00" `
                    -PasswordHistoryCount 5 -ReversibleEncryptionEnabled $false
                Write-Host "  [+] AD password policy hardened" -ForegroundColor Green

                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
                    -Name "LDAPServerIntegrity" -Value 2 -PropertyType DWord -Force | Out-Null
                Write-Host "  [+] LDAP signing required" -ForegroundColor Green
            }
        }
        "2" {
            Write-Host "`n  === DNS ===" -ForegroundColor Green
            Set-DnsServerResponseRateLimiting -Mode Enable 2>&1 | Out-Null
            Write-Host "  [+] DNS response rate limiting enabled" -ForegroundColor Green
        }
        "3" {
            Write-Host "`n  === DHCP ===" -ForegroundColor Green
            Set-DhcpServerAuditLog -Enable $true 2>&1 | Out-Null
            Write-Host "  [+] DHCP audit logging enabled" -ForegroundColor Green
        }
        "4" {
            Write-Host "`n  === IIS Web ===" -ForegroundColor Green
            Import-Module WebAdministration 2>&1 | Out-Null
            Remove-WindowsFeature Web-DAV-Publishing 2>&1 | Out-Null
            Write-Host "  [+] WebDAV removed" -ForegroundColor Green
        }
        "5" {
            Write-Host "`n  === FTP ===" -ForegroundColor Green
            Import-Module WebAdministration 2>&1 | Out-Null
            Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/ftpServer/security/authentication/anonymousAuthentication" -Name enabled -Value false
            Write-Host "  [+] Anonymous FTP disabled" -ForegroundColor Green
        }
        "6" {
            Write-Host "`n  === File Server ===" -ForegroundColor Green
            Set-SmbServerConfiguration -EncryptData $true -RejectUnencryptedAccess $true -Force
            Write-Host "  [+] SMB encryption enforced" -ForegroundColor Green
        }
        "7" {
            Write-Host "`n  === Exchange ===" -ForegroundColor Green
            Write-Host "  [!] Exchange hardening is mostly manual:" -ForegroundColor Yellow
            Write-Host "  - Disable OWA if not scored" -ForegroundColor Yellow
            Write-Host "  - Check for mail forwarding rules" -ForegroundColor Yellow
            Write-Host "  - Update transport rules" -ForegroundColor Yellow
        }
    }
}

# =============================================================================
# SCHEDULED TASKS AUDIT
# =============================================================================
if (Pause-Section "AUDIT SCHEDULED TASKS") {
    $tasks = Get-ScheduledTask | Where-Object {
        $_.Author -notmatch "Microsoft" -and $_.State -ne "Disabled" -and $_.TaskPath -notmatch "\\Microsoft\\"
    }
    if ($tasks) {
        foreach ($t in $tasks) {
            $action = ($t | Select-Object -ExpandProperty Actions).Execute
            Write-Host "  [!] $($t.TaskName) -- Author: $($t.Author) -- Action: $action" -ForegroundColor Yellow
        }
        Write-Host "  Review these. Disable suspicious ones with:" -ForegroundColor Cyan
        Write-Host '  Disable-ScheduledTask -TaskName "NAME"' -ForegroundColor Cyan
    } else {
        Write-Host "  [+] No suspicious scheduled tasks" -ForegroundColor Green
    }
}

# =============================================================================
# DONE
# =============================================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Magenta
Write-Host "  Lockdown Complete!" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Still to do:" -ForegroundColor Yellow
Write-Host "  - Verify ALL scored services work" -ForegroundColor Yellow
Write-Host "  - Check firewall allows scored service ports" -ForegroundColor Yellow
Write-Host "  - Review Event Viewer for suspicious activity" -ForegroundColor Yellow
Write-Host "  - Delete password file after portal update" -ForegroundColor Yellow
