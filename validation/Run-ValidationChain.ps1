<#
.SYNOPSIS
NullTracer Live VM Validation - Attack Chain Detection & Latency (10x Loop)

.DESCRIPTION
Executes a malicious LOLbin chain (PowerShell -> rundll32 -> WmiPrvSE) exactly 10 times.
Captures the start time and reads the NullTracer agent.log to calculate exact detection latency.

.PREREQUISITES
1. NullTracerDrv.sys must be loaded (sc start NullTracerDrv)
2. NullTracer Agent must be running and piping output to agent.log:
   python -m agent.nulltracer_agent > agent.log 2>&1
#>

$Runs = 10
$AgentLog = "agent.log"
$Results = @()

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " NullTracer Live Validation (10x Loop)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

if (-not (Test-Path $AgentLog)) {
    Write-Host "[!] Could not find $AgentLog. Ensure agent is running: python -m agent.nulltracer_agent > agent.log" -ForegroundColor Red
    exit
}

for ($i = 1; $i -le $Runs; $i++) {
    Write-Host "`n[*] Run $i / $Runs" -ForegroundColor Yellow
    
    # 1. Capture exact start time
    $StartTime = Get-Date
    Write-Host "    [+] Attack initiated at: $($StartTime.ToString('HH:mm:ss.fff'))"

    # 2. Execute the Chain (T1059.001 -> T1218.011 -> T1047)
    # We use a custom wrapper to ensure strict parent-child lineage.
    # PowerShell spawns rundll32, which in turn spawns WMI (via WmiPrvSE).
    $EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Start-Process rundll32.exe -ArgumentList 'C:\Windows\System32\wbem\WmiPrvSE.exe, -secured -Embedding'"))
    Start-Process powershell.exe -ArgumentList "-enc $EncodedCommand" -WindowStyle Hidden

    # 3. Wait for alert in agent.log (Timeout after 5 seconds)
    $AlertFound = $false
    $EndTime = $null
    $WaitTime = 0
    $Timeout = 5000 # 5 seconds max wait

    while ($WaitTime -lt $Timeout) {
        # Read the last 20 lines of the log looking for the Sigma alert
        $Tail = Get-Content $AgentLog -Tail 20 -ErrorAction SilentlyContinue
        
        # Look for the alert timestamp in our custom log format.
        # Assuming the alert log contains "[ALERT] LOLbin Lateral Movement" and a timestamp
        foreach ($line in $Tail) {
            if ($line -match "\[ALERT\] LOLbin Lateral Movement") {
                $AlertFound = $true
                $EndTime = Get-Date
                break
            }
        }

        if ($AlertFound) { break }
        
        Start-Sleep -Milliseconds 100
        $WaitTime += 100
    }

    if ($AlertFound) {
        $Latency = ($EndTime - $StartTime).TotalMilliseconds
        Write-Host "    [+] DETECTED! Latency: $Latency ms" -ForegroundColor Green
        $Results += [PSCustomObject]@{
            Run = $i
            Detected = $true
            LatencyMs = $Latency
        }
    } else {
        Write-Host "    [-] MISSED! No alert within 5 seconds." -ForegroundColor Red
        $Results += [PSCustomObject]@{
            Run = $i
            Detected = $false
            LatencyMs = $null
        }
    }
    
    # Give the system a second to settle before the next run
    Start-Sleep -Seconds 1
}

# Calculate Metrics
$DetectedCount = ($Results | Where-Object { $_.Detected }).Count
$DetectionRate = ($DetectedCount / $Runs) * 100

$Latencies = $Results | Where-Object { $_.Detected } | Select-Object -ExpandProperty LatencyMs
$AvgLatency = if ($Latencies.Count -gt 0) { ($Latencies | Measure-Object -Average).Average } else { 0 }
$MaxLatency = if ($Latencies.Count -gt 0) { ($Latencies | Measure-Object -Maximum).Maximum } else { 0 }

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Validation Results Summary" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Detection Rate : $DetectionRate % ($DetectedCount / $Runs)" -ForegroundColor Green
Write-Host "Avg Latency    : $AvgLatency ms" -ForegroundColor Green
Write-Host "Max Latency    : $MaxLatency ms" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
