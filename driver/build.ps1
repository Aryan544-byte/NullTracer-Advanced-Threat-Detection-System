<#
.SYNOPSIS
    NullTracer Phase 3 - Driver Build Script
    ==========================================
    Automatically installs the Windows Driver Kit (WDK) and Visual Studio
    Build Tools if not present, then compiles NullTracerDrv.sys.

.DESCRIPTION
    This script:
      1. Checks for winget availability.
      2. Installs Visual Studio 2022 Build Tools (C++ workload) if absent.
      3. Installs the Windows Driver Kit (WDK) 10 if absent.
      4. Locates the WDK MSBuild toolchain.
      5. Invokes MSBuild to build NullTracerDrv.vcxproj (x64 Release).
      6. Reports the output path of NullTracerDrv.sys.

.NOTES
    Requires:
      - Internet access (for winget downloads, ~5 GB total).
      - PowerShell running as Administrator (required by WDK installer).
      - Windows 10 or 11.

    Run as:
        Set-ExecutionPolicy Bypass -Scope Process -Force
        .\driver\build.ps1

    After a successful build, run:
        .\driver\setup_testsign.ps1
    to sign and install the driver on a test VM.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [ValidateSet("x64", "x86")]
    [string]$Platform = "x64",

    [switch]$SkipInstall   # Skip winget installs (use if tools already installed)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$DriverDir  = Join-Path $ScriptDir "NullTracerDrv"
$ProjectFile = Join-Path $DriverDir "NullTracerDrv.vcxproj"
$OutDir     = Join-Path $DriverDir "$Platform\$Configuration"

# ============================================================================
# Helper functions
# ============================================================================

function Write-Header([string]$msg) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-Step([string]$msg) {
    Write-Host "  [*] $msg" -ForegroundColor Yellow
}

function Write-OK([string]$msg) {
    Write-Host "  [+] $msg" -ForegroundColor Green
}

function Write-Fail([string]$msg) {
    Write-Host "  [!] $msg" -ForegroundColor Red
}

function Test-WingetAvailable {
    try {
        $null = winget --version 2>$null
        return $true
    } catch {
        return $false
    }
}

function Find-MSBuild {
    # Try vswhere first (most reliable)
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null
        if ($vsPath) {
            return $vsPath | Select-Object -First 1
        }
    }
    # Fallback: known VS 2022 path
    $fallback = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (Test-Path $fallback) { return $fallback }

    $fallback2 = "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (Test-Path $fallback2) { return $fallback2 }

    return $null
}

function Test-WDKInstalled {
    $wdkReg = "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
    if (Test-Path $wdkReg) {
        $roots = Get-ItemProperty $wdkReg -ErrorAction SilentlyContinue
        return ($null -ne $roots.KitsRoot10)
    }
    return $false
}

# ============================================================================
# Step 0: Banner
# ============================================================================
Write-Header "NullTracer Phase 3 - Driver Build"
Write-Host "  Configuration : $Configuration"
Write-Host "  Platform      : $Platform"
Write-Host "  Project       : $ProjectFile"
Write-Host "  Output dir    : $OutDir"

# ============================================================================
# Step 1: Verify winget
# ============================================================================
Write-Header "Step 1: Checking winget"

if (-not (Test-WingetAvailable)) {
    Write-Fail "winget not found. Please install 'App Installer' from the Microsoft Store."
    Write-Fail "Alternatively, install VS Build Tools and WDK manually:"
    Write-Fail "  VS Build Tools: https://aka.ms/vs/17/release/vs_BuildTools.exe"
    Write-Fail "  WDK:            https://go.microsoft.com/fwlink/?linkid=2196230"
    exit 1
}

$wingetVer = winget --version
Write-OK "winget found: $wingetVer"

# ============================================================================
# Step 2: Install Visual Studio Build Tools (C++ + WDK workloads)
# ============================================================================
Write-Header "Step 2: Visual Studio Build Tools"

if ($SkipInstall) {
    Write-Step "Skipping install (--SkipInstall specified)"
} else {
    $msbuild = Find-MSBuild
    if ($msbuild) {
        Write-OK "MSBuild already found: $msbuild"
    } else {
        Write-Step "Installing Visual Studio 2022 Build Tools..."
        Write-Step "This may take 5-10 minutes and ~3 GB of disk space."

        # Install VS Build Tools with:
        #   - C++ core desktop tools
        #   - Windows 11 SDK (10.0.22621.0)
        #   - MSVC v143 compiler
        winget install --id Microsoft.VisualStudio.2022.BuildTools `
            --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended" `
            --accept-package-agreements --accept-source-agreements

        $msbuild = Find-MSBuild
        if (-not $msbuild) {
            Write-Fail "MSBuild not found after VS Build Tools install."
            Write-Fail "Please install manually and re-run this script with -SkipInstall."
            exit 1
        }
        Write-OK "MSBuild installed: $msbuild"
    }
}

# ============================================================================
# Step 3: Install Windows Driver Kit (WDK) 10
# ============================================================================
Write-Header "Step 3: Windows Driver Kit (WDK)"

if ($SkipInstall) {
    Write-Step "Skipping install (--SkipInstall specified)"
} elseif (Test-WDKInstalled) {
    Write-OK "WDK already installed."
} else {
    Write-Step "Installing Windows Driver Kit (WDK)..."
    Write-Step "This may take 5-15 minutes and ~2 GB of disk space."

    # WDK 10 (latest stable)
    $wdkInstallerUrl = "https://go.microsoft.com/fwlink/?linkid=2196230"
    $wdkInstaller    = "$env:TEMP\wdksetup.exe"

    Write-Step "Downloading WDK installer from Microsoft..."
    Invoke-WebRequest -Uri $wdkInstallerUrl -OutFile $wdkInstaller -UseBasicParsing

    Write-Step "Running WDK installer (silent)..."
    Start-Process -FilePath $wdkInstaller -ArgumentList "/quiet /norestart" -Wait

    if (-not (Test-WDKInstalled)) {
        Write-Fail "WDK not detected after installation. Check $wdkInstaller manually."
        exit 1
    }
    Write-OK "WDK installed successfully."
}

# ============================================================================
# Step 4: Locate MSBuild (re-check if we skipped install)
# ============================================================================
$msbuild = Find-MSBuild
if (-not $msbuild) {
    Write-Fail "MSBuild not found. Install Visual Studio Build Tools first."
    exit 1
}
Write-OK "Using MSBuild: $msbuild"

# ============================================================================
# Step 5: Build the driver
# ============================================================================
Write-Header "Step 5: Building NullTracerDrv.sys"

if (-not (Test-Path $ProjectFile)) {
    Write-Fail "Project file not found: $ProjectFile"
    exit 1
}

Write-Step "Invoking MSBuild..."

$msbuildArgs = @(
    $ProjectFile,
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/m",           # parallel build
    "/v:minimal"    # minimal verbosity
)

& $msbuild @msbuildArgs

if ($LASTEXITCODE -ne 0) {
    Write-Fail "MSBuild failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# ============================================================================
# Step 6: Verify output
# ============================================================================
Write-Header "Step 6: Verification"

$SysFile = Join-Path $OutDir "NullTracerDrv.sys"

if (Test-Path $SysFile) {
    $size = (Get-Item $SysFile).Length
    Write-OK "Build successful!"
    Write-OK "  Driver: $SysFile"
    Write-OK "  Size  : $size bytes"
    Write-Host ""
    Write-Host "  Next step: Sign and install the driver." -ForegroundColor Cyan
    Write-Host "  Run: .\driver\setup_testsign.ps1 -DriverPath '$SysFile'" -ForegroundColor Cyan
} else {
    Write-Fail "NullTracerDrv.sys not found at expected path: $SysFile"
    exit 1
}
