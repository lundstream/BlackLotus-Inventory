<#
.SYNOPSIS
    Collects Microsoft Secure Boot certificate status and reports to inventory server.

.DESCRIPTION
    Read-only inventory script that gathers Secure Boot UEFI CA 2023 migration status
    from the local machine and sends it to a central inventory API.

    This script makes NO changes to the system. It only reads registry keys and
    Secure Boot UEFI variables to determine the current state, then POSTs the
    data to the configured API endpoint.

    Designed to run as a scheduled task on Windows clients and servers.

    Reference: https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d

.PARAMETER ApiUrl
    The URL of the inventory API endpoint (e.g., https://inventory.example.com/api/report).

.PARAMETER ApiKey
    The API key for authentication with the inventory server.

.EXAMPLE
    .\Collect-SecureBootInventory.ps1 -ApiUrl "https://inventory.example.com/api/report" -ApiKey "your-api-key"

.EXAMPLE
    # Run via scheduled task (as SYSTEM):
    powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Collect-SecureBootInventory.ps1" -ApiUrl "https://inventory.example.com/api/report" -ApiKey "your-api-key"

.NOTES
    Author:     Black Lotus Inventory
    Version:    1.0.0
    Requires:   Windows with Secure Boot support, PowerShell 5.1+
    Permissions: Must run as Administrator/SYSTEM to read UEFI variables
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

# --- Helper: safely read a registry property ---
function Get-RegValue {
    [CmdletBinding()]
    Param (
        [string]$Path,
        [string]$Name
    )
    try {
        if (Test-Path $Path) {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            return $val
        }
    }
    catch { }
    return $null
}

# --- Helper: safely check UEFI variable for certificate string ---
function Test-UefiCert {
    [CmdletBinding()]
    Param (
        [string]$Store,
        [string]$Pattern
    )
    try {
        $uefi = Get-SecureBootUEFI $Store -ErrorAction Stop
        if ($uefi -and $uefi.bytes) {
            return [System.Text.Encoding]::ASCII.GetString($uefi.bytes) -match $Pattern
        }
    }
    catch {
        Write-Verbose "Could not read UEFI $Store store: $($_.Exception.Message)"
    }
    return $null
}

# --- Collect machine info ---
$biosObj = Get-WmiObject Win32_BIOS
$computerInfo = @{
    "Hostname"       = $env:COMPUTERNAME
    "Domain"         = (Get-WmiObject Win32_ComputerSystem).Domain
    "OSVersion"      = [System.Environment]::OSVersion.VersionString
    "OSBuild"        = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    "OSName"         = (Get-WmiObject Win32_OperatingSystem).Caption
    "Manufacturer"   = (Get-WmiObject Win32_ComputerSystem).Manufacturer
    "Model"          = (Get-WmiObject Win32_ComputerSystem).Model
    "BIOSVersion"    = $biosObj.SMBIOSBIOSVersion
    "BIOSDate"       = $null
    "IsVirtualMachine" = $false
    "VMwareHWVersion" = $null
    "BitLockerStatus" = $null
}

# BIOS release date
try {
    if ($biosObj.ReleaseDate) {
        $computerInfo.BIOSDate = [Management.ManagementDateTimeConverter]::ToDateTime($biosObj.ReleaseDate).ToString("yyyy-MM-dd")
    }
} catch { }

# Detect virtual machine
$vmManufacturers = @("Microsoft Corporation", "VMware, Inc.", "QEMU", "Xen", "innotek GmbH", "Parallels Software International Inc.")
if ($computerInfo.Manufacturer -in $vmManufacturers) {
    $computerInfo.IsVirtualMachine = $true

    # VMware hardware version
    if ($computerInfo.Manufacturer -eq "VMware, Inc.") {
        try {
            $vmModel = (Get-WmiObject Win32_ComputerSystem).Model
            if ($vmModel -match 'VMware\d+,(\d+)') {
                $computerInfo.VMwareHWVersion = "vmx-" + $Matches[1]
            }
            elseif ($vmModel -match 'VMware') {
                # Try registry for VM hardware version
                $hwVer = Get-RegValue -Path "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools" -Name "ProductVersion"
                if ($hwVer) { $computerInfo.VMwareHWVersion = $hwVer }
            }
        } catch { }
    }
}

# BitLocker status on system drive
try {
    $blStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $computerInfo.BitLockerStatus = $blStatus.ProtectionStatus.ToString()
} catch {
    # Fallback: try manage-bde
    try {
        $bdeOutput = manage-bde -status $env:SystemDrive 2>&1
        if ($bdeOutput -match 'Protection Status:\s+(.+)') {
            $computerInfo.BitLockerStatus = $Matches[1].Trim()
        } else {
            $computerInfo.BitLockerStatus = "Unknown"
        }
    } catch {
        $computerInfo.BitLockerStatus = "NotAvailable"
    }
}

# --- Collect Secure Boot registry state ---
$registryState = @{
    "AvailableUpdates"        = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates"
    "UEFISecureBootEnabled"   = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled"
    "UEFICA2023Status"        = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023Status"
    "UEFICA2023Error"         = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023Error"
    "WindowsUEFICA2023Capable" = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "WindowsUEFICA2023Capable"
    "OEMManufacturerName"     = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name "OEMManufacturerName"
    "OEMModelNumber"          = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name "OEMModelNumber"
}

# --- Collect UEFI certificate status ---
$certStatus = @{
    "DBInstallStatus"        = Test-UefiCert -Store "db" -Pattern 'Windows UEFI CA 2023'
    "DBDefaultInstallStatus" = Test-UefiCert -Store "dbdefault" -Pattern 'Windows UEFI CA 2023'
    "MSROMInstallStatus"     = Test-UefiCert -Store "db" -Pattern 'Microsoft UEFI CA 2023'
    "OptROMInstallStatus"    = Test-UefiCert -Store "db" -Pattern 'Microsoft Option ROM UEFI CA 2023'
    "KEKInstallStatus"       = Test-UefiCert -Store "kek" -Pattern 'Microsoft Corporation KEK 2K CA 2023'
    "ThirdPartyInstallStatus" = Test-UefiCert -Store "db" -Pattern 'Microsoft Corporation UEFI CA 2011'
    "DBXRevocationStatus"    = Test-UefiCert -Store "dbx" -Pattern 'Microsoft Windows Production PCA 2011'
}

# --- Determine overall migration phase ---
function Get-MigrationPhase {
    # Phase 0: Secure Boot not enabled
    if ($registryState.UEFISecureBootEnabled -ne 1) {
        return "SecureBootDisabled"
    }

    # Phase 4: Fully complete — certs installed, old revoked, KEK updated
    if ($certStatus.DBInstallStatus -and
        $certStatus.DBXRevocationStatus -and
        $certStatus.KEKInstallStatus) {
        return "Complete"
    }

    # Phase 3: Revocation done, KEK pending
    if ($certStatus.DBInstallStatus -and
        $certStatus.DBXRevocationStatus -and
        -not $certStatus.KEKInstallStatus) {
        return "Phase3_KEKPending"
    }

    # Phase 2: Certs installed, revocation pending
    if ($certStatus.DBInstallStatus -and
        -not $certStatus.DBXRevocationStatus) {
        return "Phase2_RevocationPending"
    }

    # Phase 1: In progress
    if ($registryState.UEFICA2023Status -eq "InProgress") {
        return "Phase1_InProgress"
    }

    # Phase 0: Not started
    if ($registryState.UEFICA2023Status -eq "NotStarted" -or
        -not $certStatus.DBInstallStatus) {
        return "Phase0_NotStarted"
    }

    return "Unknown"
}

$migrationPhase = Get-MigrationPhase

# --- Build the report payload ---
$report = @{
    "hostname"        = $computerInfo.Hostname
    "domain"          = $computerInfo.Domain
    "osVersion"       = $computerInfo.OSVersion
    "osBuild"         = $computerInfo.OSBuild
    "osName"          = $computerInfo.OSName
    "manufacturer"    = $computerInfo.Manufacturer
    "model"           = $computerInfo.Model
    "biosVersion"     = $computerInfo.BIOSVersion
    "biosDate"        = $computerInfo.BIOSDate
    "isVirtualMachine" = $computerInfo.IsVirtualMachine
    "vmwareHWVersion" = $computerInfo.VMwareHWVersion
    "bitlockerStatus" = $computerInfo.BitLockerStatus
    "secureBootEnabled" = ($registryState.UEFISecureBootEnabled -eq 1)
    "migrationPhase"  = $migrationPhase
    "registry"        = $registryState
    "certificates"    = $certStatus
    "collectedAt"     = (Get-Date -Format "o")
}

$json = $report | ConvertTo-Json -Depth 4 -Compress

# --- Send to API ---
Write-Verbose "Sending inventory report to $ApiUrl"
Write-Verbose "Hostname: $($computerInfo.Hostname)"
Write-Verbose "Migration Phase: $migrationPhase"

try {
    $headers = @{
        "Content-Type"  = "application/json"
        "X-Api-Key"     = $ApiKey
    }

    $response = Invoke-RestMethod -Uri $ApiUrl -Method Post -Body $json -Headers $headers -TimeoutSec 30 -ErrorAction Stop

    Write-Verbose "Report submitted successfully."
    if ($response.status) {
        Write-Verbose "Server response: $($response.status)"
    }
    exit 0
}
catch {
    Write-Warning "Failed to send inventory report: $($_.Exception.Message)"
    exit 1
}
