<#
.SYNOPSIS
    NullTracer Phase 3 — Test-Sign & Install Script
    =================================================
    Enables test-signing, creates a self-signed code-signing certificate,
    signs NullTracerDrv.sys, and installs the driver as a kernel service.

.DESCRIPTION
    This script performs the complete driver installation flow for a
    development/test environment:

      1. Enables test-signing boot option (bcdedit /set testsigning on).
      2. Creates a self-signed certificate in the local machine store.
      3. Signs NullTracerDrv.sys with signtool.exe.
      4. Copies the driver to System32\drivers\.
      5. Creates the kernel service with sc.exe.
      6. Starts the driver with sc.exe start.

    IMPORTANT: A REBOOT is required after step 1 if test-signing was
    previously disabled. The script will prompt you.

.PARAMETER DriverPath
    Full path to the compiled NullTracerDrv.sys.
    Default: .\NullTracerDrv\x64\Release\NullTracerDrv.sys

.PARAMETER CertName
    Subject name for the self-signed certificate.
    Default: "NullTracer Test Signing Cert"

.PARAMETER ServiceName
    Name of the kernel service (sc.exe).
    Default: "NullTracer"

.EXAMPLE
    # Sign and install with defaults (after build.ps1 succeeds):
    .\driver\setup_testsign.ps1

    # Specify a different driver binary:
    .\driver\setup_testsign.ps1 -DriverPath "C:\MyBuild\NullTracerDrv.sys"

.NOTES
    Requirements:
      - Must be run as Administrator.
      - Windows SDK (signtool.exe) or WDK must be installed.
      - A REBOOT is needed if this is the first time enabling test-signing.
      - To uninstall: run   sc stop NullTracer; sc delete NullTracer
      - To disable test-signing: bcdedit /set testsigning off  (+ reboot)
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$DriverPath  = $null,
    [string]$CertName    = "NullTracer Test Signing Cert",
    [string]$ServiceName = "NullTracer"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $DriverPath) {
    $DriverPath = Join-Path $ScriptDir "NullTracerDrv\x64\Release\NullTracerDrv.sys"
}

# ============================================================================
# Helpers
# ============================================================================

function Write-Header([string]$msg) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-Step([string]$msg)  { Write-Host "  [*] $msg" -ForegroundColor Yellow }
function Write-OK([string]$msg)    { Write-Host "  [+] $msg" -ForegroundColor Green  }
function Write-Warn([string]$msg)  { Write-Host "  [!] $msg" -ForegroundColor Magenta }
function Write-Fail([string]$msg)  { Write-Host "  [X] $msg" -ForegroundColor Red    }

function Find-SignTool {
    # Search common WDK / Windows SDK locations
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    )
    foreach ($root in $roots) {
        if (Test-Path $root) {
            $hit = Get-ChildItem $root -Recurse -Filter "signtool.exe" |
                   Where-Object { $_.FullName -like "*x64*" } |
                   Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    # Fallback: PATH
    $inPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }
    return $null
}

# ============================================================================
# Banner
# ============================================================================
Write-Header "NullTracer - Test-Sign and Install"
Write-Host "  Driver path : $DriverPath"
Write-Host "  Cert name   : $CertName"
Write-Host "  Service name: $ServiceName"

# ============================================================================
# Step 1: Validate driver binary exists
# ============================================================================
Write-Header "Step 1: Validating driver binary"

if (-not (Test-Path $DriverPath)) {
    Write-Fail "Driver not found: $DriverPath"
    Write-Fail "Run .\driver\build.ps1 first."
    exit 1
}
Write-OK "Driver found: $DriverPath"

# ============================================================================
# Step 2: Enable test-signing boot option
# ============================================================================
Write-Header "Step 2: Enabling test-signing boot mode"

$bcdOutput = bcdedit /enum | Select-String "testsigning"
if ($bcdOutput -match "Yes") {
    Write-OK "Test-signing is already enabled."
} else {
    Write-Step "Enabling test-signing (requires reboot to take effect)..."
    bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "bcdedit failed. Ensure Secure Boot is disabled in BIOS/UEFI."
        exit 1
    }
    Write-OK "Test-signing enabled."
    Write-Warn "NOTE: A REBOOT is required before the driver can be loaded."
    Write-Warn "      After rebooting, re-run this script to continue installation."
    $reboot = Read-Host "  Reboot now? [Y/N]"
    if ($reboot -eq "Y" -or $reboot -eq "y") {
        Restart-Computer -Force
    } else {
        Write-Warn "Continuing without reboot — driver load may fail until next reboot."
    }
}

# ============================================================================
# Step 3: Create / locate self-signed code-signing certificate
# ============================================================================
Write-Header "Step 3: Code-signing certificate"

$certStore = "Cert:\LocalMachine\My"
$existing  = Get-ChildItem $certStore | Where-Object { $_.Subject -like "*$CertName*" }

if ($existing) {
    $cert = $existing | Select-Object -First 1
    Write-OK "Existing cert found: $($cert.Thumbprint)"
} else {
    Write-Step "Creating new self-signed code-signing certificate..."
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$CertName" `
        -Type CodeSigningCert `
        -CertStoreLocation $certStore `
        -KeyUsage DigitalSignature `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(5)

    Write-OK "Created certificate: $($cert.Thumbprint)"

    # Export to Trusted Root CA and Trusted Publishers so test-sign works
    Write-Step "Adding certificate to Trusted Root CA store..."
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $rootStore.Add($cert)
    $rootStore.Close()

    Write-Step "Adding certificate to Trusted Publishers store..."
    $pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $pubStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $pubStore.Add($cert)
    $pubStore.Close()

    Write-OK "Certificate added to trust stores."
}

# ============================================================================
# Step 4: Sign the driver with signtool
# ============================================================================
Write-Header "Step 4: Signing NullTracerDrv.sys"

$signTool = Find-SignTool
if (-not $signTool) {
    Write-Fail "signtool.exe not found. Ensure the Windows SDK or WDK is installed."
    exit 1
}
Write-Step "signtool: $signTool"

& $signTool sign `
    /sha1  $cert.Thumbprint `
    /fd    SHA256 `
    /t     "http://timestamp.digicert.com" `
    /v     $DriverPath

if ($LASTEXITCODE -ne 0) {
    Write-Warn "Timestamp server unreachable — signing without timestamp..."
    & $signTool sign `
        /sha1  $cert.Thumbprint `
        /fd    SHA256 `
        /v     $DriverPath

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "signtool failed."
        exit 1
    }
}
Write-OK "Driver signed successfully."

# ============================================================================
# Step 5: Copy driver to System32\drivers\
# ============================================================================
Write-Header "Step 5: Installing driver binary"

$destPath = "$env:SystemRoot\System32\drivers\NullTracerDrv.sys"
Write-Step "Copying to $destPath ..."
Copy-Item $DriverPath $destPath -Force
Write-OK "Driver copied."

# ============================================================================
# Step 6: Create kernel service
# ============================================================================
Write-Header "Step 6: Creating kernel service"

$svcExists = sc.exe query $ServiceName 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Warn "Service '$ServiceName' already exists — stopping and deleting..."
    sc.exe stop  $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 1
    sc.exe delete $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 1
}

Write-Step "Creating service '$ServiceName'..."
sc.exe create $ServiceName `
    type=   kernel `
    start=  demand `
    error=  normal `
    binPath= $destPath `
    DisplayName= "NullTracer Kernel Threat Detection Driver"

if ($LASTEXITCODE -ne 0) {
    Write-Fail "sc.exe create failed."
    exit 1
}
Write-OK "Service created."

# ============================================================================
# Step 7: Start the driver
# ============================================================================
Write-Header "Step 7: Starting driver"

Write-Step "Starting service '$ServiceName'..."
sc.exe start $ServiceName

if ($LASTEXITCODE -ne 0) {
    Write-Fail "sc.exe start failed. Check Event Viewer > System for kernel errors."
    Write-Fail "Common causes:"
    Write-Fail "  - Test-signing not yet active (reboot required)"
    Write-Fail "  - Certificate not in Trusted Publishers store"
    Write-Fail "  - Driver binary not correctly signed"
    exit 1
}

Write-OK "Driver started successfully!"
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host "  NullTracer is now running in kernel mode." -ForegroundColor Green
Write-Host "  Device available at: \\.\NullTracer" -ForegroundColor Green
Write-Host ""
Write-Host "  Start the relay agent:" -ForegroundColor Cyan
Write-Host "    pip install -r requirements.txt" -ForegroundColor Cyan
Write-Host "    python -m agent.nulltracer_agent" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Green

# ============================================================================
# Uninstall reminder
# ============================================================================
Write-Host ""
Write-Host "  To uninstall later:" -ForegroundColor Gray
Write-Host "    sc stop NullTracer" -ForegroundColor Gray
Write-Host "    sc delete NullTracer" -ForegroundColor Gray
Write-Host "    del $env:SystemRoot\System32\drivers\NullTracerDrv.sys" -ForegroundColor Gray
