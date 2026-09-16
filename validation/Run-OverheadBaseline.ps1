<#
.SYNOPSIS
NullTracer Live VM Validation - Overhead & FP Baseline

.DESCRIPTION
Runs for a specified duration to collect baseline CPU and Memory metrics using Windows
Performance Counters, and counts the number of false positive alerts generated.
Run this script twice: once with the driver loaded (and agent running), and once with it unloaded.

.PARAMETER DurationMinutes
How long to run the baseline test (default 60 minutes).
#>

param (
    [int]$DurationMinutes = 60,
    [string]$AgentLog = "agent.log"
)

$DurationSeconds = $DurationMinutes * 60
$Samples = $DurationSeconds / 5 # Sample every 5 seconds

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " NullTracer FP & Overhead Baseline" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Duration : $DurationMinutes minutes"
Write-Host "Samples  : $Samples (every 5s)"
Write-Host "==========================================`n"

# Check if agent log exists to count FPs (if loaded)
$InitialAlertCount = 0
if (Test-Path $AgentLog) {
    $InitialAlertCount = (Select-String -Path $AgentLog -Pattern "\[ALERT\]").Line.Count
    Write-Host "[*] Tracking False Positives from $AgentLog"
} else {
    Write-Host "[!] $AgentLog not found. Assuming unloaded run (FP check skipped)." -ForegroundColor Yellow
}

Write-Host "[*] Collecting Performance Counters... Please use the system normally (idle/benign)."
# Get CPU % and Available Memory (MB)
$Counters = @(
    "\Processor(_Total)\% Processor Time",
    "\Memory\Available MBytes"
)

# Run Get-Counter continuously
$PerfData = Get-Counter -Counter $Counters -SampleInterval 5 -MaxSamples $Samples

# Process Data
$CpuSamples = @()
$MemSamples = @()

foreach ($sample in $PerfData) {
    $CpuSamples += $sample.CounterSamples[0].CookedValue
    $MemSamples += $sample.CounterSamples[1].CookedValue
}

$AvgCpu = ($CpuSamples | Measure-Object -Average).Average
$AvgMem = ($MemSamples | Measure-Object -Average).Average

# Check final FP count
$FinalAlertCount = 0
$FpCount = 0
if (Test-Path $AgentLog) {
    $FinalAlertCount = (Select-String -Path $AgentLog -Pattern "\[ALERT\]").Line.Count
    $FpCount = $FinalAlertCount - $InitialAlertCount
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Baseline Results Summary" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Avg CPU Usage       : $([math]::Round($AvgCpu, 2)) %" -ForegroundColor Green
Write-Host "Avg Available Mem   : $([math]::Round($AvgMem, 2)) MB" -ForegroundColor Green
Write-Host "False Positives     : $FpCount (over $DurationMinutes mins)" -ForegroundColor Green

if ($FpCount -gt 0) {
    $FpPerHour = ($FpCount / $DurationMinutes) * 60
    Write-Host "FP Rate (per hour)  : $FpPerHour" -ForegroundColor Red
}
Write-Host "==========================================" -ForegroundColor Cyan
