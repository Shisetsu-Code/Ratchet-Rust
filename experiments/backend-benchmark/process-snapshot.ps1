param([int]$RootProcess)
$ErrorActionPreference = 'Stop'
$processes = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name)
$selected = [System.Collections.Generic.HashSet[int]]::new()
[void]$selected.Add($RootProcess)
do {
    $changed = $false
    foreach ($item in $processes) {
        if ($selected.Contains([int]$item.ParentProcessId) -and $selected.Add([int]$item.ProcessId)) { $changed = $true }
    }
} while ($changed)
$rows = foreach ($item in $processes) {
    if ($selected.Contains([int]$item.ProcessId) -and $item.Name -match '^workerd') {
        $process = Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
        if ($process) { @{ id=$process.Id; name=$process.ProcessName; cpu_ms=$process.TotalProcessorTime.TotalMilliseconds; rss_bytes=$process.WorkingSet64; peak_rss_bytes=$process.PeakWorkingSet64 } }
    }
}
ConvertTo-Json -InputObject @($rows) -Compress
