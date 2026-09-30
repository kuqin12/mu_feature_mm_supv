$log = 'D:\Repos\mu_tiano_platforms_2\Build\BUILDLOG_QemuQ35Pkg_Run.txt'
$out = 'D:\Repos\mu_tiano_platforms_2\Build\test_aux_config.toml'

$lines = Get-Content $log
$s = ($lines | Select-String -SimpleMatch 'Validation Error! Dumping Info' | Select-Object -Last 1).LineNumber - 1

$mseg   = $lines[$s+1] -replace '^INFO -\s+',''
$msegSz = $lines[$s+2] -replace '^INFO -\s+',''
$base   = $lines[$s+3] -replace '^INFO -\s+',''

$body = New-Object System.Collections.Generic.List[string]
$j = $s + 5
while ($j -lt $lines.Count -and $lines[$j] -match '^INFO -\s+[0-9A-Fa-f]{8}:') {
    $body.Add(($lines[$j] -replace '^INFO - ','00:00:00.000 : ')); $j++
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine($mseg); [void]$sb.AppendLine($msegSz); [void]$sb.AppendLine($base)
[void]$sb.AppendLine("MmSupervisor = '''")
[void]$sb.AppendLine(($body -join "`r`n"))
[void]$sb.AppendLine("'''")
[System.IO.File]::WriteAllText($out, $sb.ToString())

"dump = 0x{0:X} bytes" -f ($body.Count * 16)
