param()

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
# -----------------------
# Path Preparation (Auto Create)
# -----------------------
$BaseDir = Join-Path (Get-Location) "IR"
$ArtifactsDir = Join-Path $BaseDir "Artifacts"
$timeTag = (Get-Date).ToString("yyyyMMdd_HHmmss")
$OutDir  = Join-Path $BaseDir ("IncidentResponse_Output_{0}" -f $timeTag)
$IOCFile = Join-Path $BaseDir "iocs.txt"

foreach($p in @($BaseDir,$ArtifactsDir,$OutDir)){ if(!(Test-Path $p)){ New-Item -ItemType Directory -Path $p | Out-Null } }
if(!(Test-Path $IOCFile)){ New-Item -ItemType File -Path $IOCFile | Out-Null }

$logPath = Join-Path $OutDir "analysis.log"
function Write-Section([string]$name){ "`n=== $name ===`n" | Out-File -FilePath $logPath -Append -Encoding UTF8 }

Write-Host "[+] Artifacts Directory: $ArtifactsDir"
Write-Host "[+] Output Directory: $OutDir"

# =======================
# 1) Artifact Collection
# =======================
Write-Host "[+] Collecting artifacts..."

# System / Patches
try { Get-ComputerInfo | Out-File (Join-Path $ArtifactsDir "system_info.txt") } catch {}
try { Get-HotFix | Out-File (Join-Path $ArtifactsDir "installed_hotfix.txt") } catch {}

# Processes / Services
try { 
  Get-Process | Select-Object Id,ProcessName,Path,StartTime |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $ArtifactsDir "process_list.csv")
} catch {}
try { Get-Service | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $ArtifactsDir "service_list.csv") } catch {}

# Network
try { netstat -ano | Out-File (Join-Path $ArtifactsDir "netstat.txt") -Encoding UTF8 } catch {}
try { Get-NetTCPConnection | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $ArtifactsDir "net_tcp.csv") } catch {}
try { Get-NetUDPEndpoint  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $ArtifactsDir "net_udp.csv") } catch {}

# Users / Logs
try { Get-LocalUser | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $ArtifactsDir "local_users.csv") } catch {}
try { Get-EventLog -LogName Security -Newest 300 | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $ArtifactsDir "security_log_recent.csv") } catch {}

# Startup registry
$RunKeys = @(
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
"=== Registry Run ===" | Out-File (Join-Path $ArtifactsDir "registry_run.txt") -Encoding UTF8
foreach($key in $RunKeys){
  if(Test-Path $key){ Get-ItemProperty $key | Out-File (Join-Path $ArtifactsDir "registry_run.txt") -Append -Encoding UTF8 }
}

# Scheduled tasks
try { schtasks /query /fo csv /v | Out-File (Join-Path $ArtifactsDir "scheduled_tasks_raw.csv") -Encoding UTF8 } catch {}

Write-Host "[+] Artifact collection complete!"

# =======================
# 2) Automated Analysis
# =======================
Write-Host "[+] Starting analysis..."
Write-Section "Process & Image Checks"

# Process signature / path heuristics
$procList = $null
$procCsvPath = Join-Path $ArtifactsDir "process_list.csv"
if (Test-Path $procCsvPath) { try { $procList = Import-Csv $procCsvPath -ErrorAction Stop } catch {} }
if(-not $procList){ try { $procList = Get-Process | Select-Object Id,ProcessName,Path,StartTime } catch { $procList=@() } }

$resultProc = @()
foreach($p in $procList){
  $path = $p.Path
  if([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)){
    $resultProc += New-Object psobject -Property @{ Process=$p.ProcessName; PID=$p.Id; Path=$path; Signed="N/A"; Company=""; Finding="NoPath" }
    continue
  }
  $signed="Unsigned"; $company=""
  try{
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    if($sig.Status -eq "Valid"){ $signed="Signed" }
    $ver = Get-Item $path | Select-Object -ExpandProperty VersionInfo -ErrorAction Stop
    if($ver){ $company = $ver.CompanyName }
  } catch {}
  $finding=@()
  if($signed -eq "Unsigned"){ $finding+="UNSIGNED_BIN" }
  if($path -match "\\Users\\[^\\]+\\AppData\\|\\ProgramData\\|\\Temp\\|Recycle\.Bin"){ $finding+="SUSPICIOUS_PATH" }
  if([string]::IsNullOrWhiteSpace($company)){ $finding+="NO_COMPANY_META" }
  $resultProc += New-Object psobject -Property @{
    Process=$p.ProcessName; PID=$p.Id; Path=$path; Signed=$signed; Company=$company; Finding=($finding -join ";")
  }
}
$resultProc | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir "process_findings.csv") -Encoding UTF8

# Network anomalies
Write-Section "Network Anomalies"
$netRaw = Get-Content (Join-Path $ArtifactsDir "netstat.txt") -ErrorAction SilentlyContinue
if(-not $netRaw){ $netRaw = netstat -ano }
$parsed=@()
foreach($line in $netRaw){
  if($line -match "^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\d+|\*)\s+(\S+)?\s*(\d+)$"){
    $parsed += New-Object psobject -Property @{
      Proto=$matches[1]; LAddr=$matches[2]; LPort=[int]$matches[3]; RAddr=$matches[4]; RPort=$matches[5]; State=$matches[6]; PID=[int]$matches[7]
    }
  }
}
$stdPorts=@(80,443,53,25,110,143,3389,22)
$netFind=@()
foreach($n in $parsed){
  $p = $resultProc | Where-Object { $_.PID -eq $n.PID } | Select-Object -First 1
  $flags=@()
  if($n.Proto -eq "TCP" -and $n.State -eq "LISTENING" -and ($stdPorts -notcontains $n.LPort)){ $flags+="LISTEN_NONSTD" }
  if($p -and $p.Signed -eq "Unsigned"){ $flags+="UNSIGNED_OWNER" }
  if($p -and $p.Path -match "\\Users\\|\\AppData\\|\\Temp\\"){ $flags+="USERSPACE_LISTEN" }
  if($flags.Count -gt 0){
    $netFind += New-Object psobject -Property @{
      Proto=$n.Proto; L=("$($n.LAddr):$($n.LPort)"); R=("$($n.RAddr):$($n.RPort)");
      State=$n.State; PID=$n.PID; Proc=$p.Process; Path=$p.Path; Flags=($flags -join ";")
    }
  }
}
$netFind | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir "net_findings.csv") -Encoding UTF8

# Persistence
Write-Section "Persistence"
$persist=@()

# Run key
foreach($rk in $RunKeys){
  if(Test-Path $rk){
    $props=(Get-ItemProperty $rk).psobject.Properties | Where-Object { $_.Name -notmatch "^PS(Path|ParentPath|ChildName|Drive|Provider)$" }
    foreach($pr in $props){
      $val=[string]$pr.Value; $flag=@()
      if($val -match "\\AppData\\|\\Temp\\|\.cmd$|\.vbs$|powershell\.exe"){ $flag+="SUSPICIOUS_PATH_OR_SCRIPT" }
      $persist += New-Object psobject -Property @{ Type="RegistryRun"; Key=$rk; Name=$pr.Name; Data=$val; Flags=($flag -join ";") }
    }
  }
}

# Scheduled tasks
try{
  $rawPath = Join-Path $ArtifactsDir "scheduled_tasks_raw.csv"
  $tasks = Import-Csv $rawPath
  foreach($t in $tasks){
    $cmd=$null
    if($t.PSObject.Properties.Name -contains "Task To Run"){ $cmd=$t."Task To Run" }
    elseif($t.PSObject.Properties.Name -contains "작업 실행 내용"){ $cmd=$t."작업 실행 내용" } # Keep Korean fallback
    else{
      $maybe = $t.PSObject.Properties | Where-Object { $_.Name -match "Run|실행|Command|명령" } | Select-Object -First 1
      if($maybe){ $cmd=$maybe.Value }
    }
    if([string]::IsNullOrWhiteSpace($cmd)){ continue }
    if($cmd -match "\\AppData\\|\\Temp\\|powershell\.exe|-enc |-EncodedCommand"){
      $persist += New-Object psobject -Property @{ Type="ScheduledTask"; Name=$t.TaskName; Command=$cmd; Flags="SUSPICIOUS_TASK" }
    }
  }
} catch {}

# Services
try{
  $svcs=Get-CimInstance Win32_Service
  foreach($s in $svcs){
    $flags=@()
    if($s.PathName -match "\\AppData\\|\\Temp\\"){ $flags+="USERSPACE_SERVICE" }
    if($s.StartMode -eq "Auto" -and $s.State -ne "Running"){ $flags+="AUTO_NOT_RUNNING" }
    if($flags.Count -gt 0){
      $persist += New-Object psobject -Property @{ Type="Service"; Name=$s.Name; Path=$s.PathName; Flags=($flags -join ";") }
    }
  }
} catch {}
$persist | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir "persistence_findings.csv") -Encoding UTF8

# Hashes & IOC
Write-Section "Hashes & IOC"
$hashes=@()
$exePaths = ($resultProc | Where-Object { $_.Path -and (Test-Path $_.Path) } | Select-Object -ExpandProperty Path -Unique)
foreach($fp in $exePaths){
  try{ $h=Get-FileHash -Algorithm SHA256 -Path $fp; $hashes += New-Object psobject -Property @{ Path=$fp; SHA256=$h.Hash } } catch {}
}
$hashCsv=Join-Path $OutDir "file_hashes.csv"
$hashes | Export-Csv -NoTypeInformation -Path $hashCsv -Encoding UTF8

$IOC_Hits=@()
if(Test-Path $IOCFile){
  $ioc = Get-Content $IOCFile | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Sort-Object -Unique
  foreach($h in $hashes){ if($ioc -contains $h.SHA256){ $IOC_Hits += $h } }
}
$iocCsv=Join-Path $OutDir "ioc_hits.csv"
$IOC_Hits | Export-Csv -NoTypeInformation -Path $iocCsv -Encoding UTF8

# Sysmon Heuristics
Write-Section "Sysmon Heuristics"
$evOut = @()
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'

$hasSysmon = $false
try {
  $logInfo = Get-WinEvent -ListLog $sysmonLog -ErrorAction Stop
  if ($logInfo -and $logInfo.LogName) { $hasSysmon = $true }
} catch { $hasSysmon = $false }

if ($hasSysmon) {
  try {
    $since = (Get-Date).AddDays(-7)
    $ev = Get-WinEvent -FilterHashtable @{ LogName = $sysmonLog; StartTime = $since } -ErrorAction Stop
    foreach ($e in $ev) {
      $xml = [xml]$e.ToXml()
      $id  = [int]$xml.Event.System.EventID.'#text'
      $cmd = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
      $dst = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationIp' }).'#text'

      $flags = @()
      if ($id -eq 1 -and $cmd -match "powershell\.exe.*-enc|-encodedcommand|rundll32|regsvr32\s+/s") { $flags += "SUSPICIOUS_CMD" }
      if ($id -eq 3 -and $dst -and $dst -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1)') { $flags += "EXT_NET_CONN" }

      if ($flags.Count -gt 0) {
        $evOut += [pscustomobject]@{ Time = $e.TimeCreated; EventID = $id; Hint = ($flags -join ";"); Detail = $cmd }
      }
    }
  } catch {
    "Sysmon exists but events could not be read: $($_.Exception.Message)" | Out-File (Join-Path $OutDir 'analysis.log') -Append -Encoding UTF8
  }
} else {
  "Sysmon log not found on this host. Skipping Sysmon heuristics." | Out-File (Join-Path $OutDir 'analysis.log') -Append -Encoding UTF8
}

$evCsv = Join-Path $OutDir "event_findings.csv"
$evOut | Export-Csv -NoTypeInformation -Path $evCsv -Encoding UTF8

# Summary
Write-Section "Summary"
$unsignedCount   = ($resultProc | Where-Object {$_.Signed -eq "Unsigned"} | Measure-Object).Count
$suspListenCount = ($netFind | Measure-Object).Count
$persistCount    = ($persist | Measure-Object).Count

$IOC_Count = 0; if(Test-Path $iocCsv){ try{ $IOC_Count = (Import-Csv $iocCsv | Measure-Object).Count } catch {} }
$sysmonCount = 0; if(Test-Path $evCsv){ try{ $sysmonCount = (Import-Csv $evCsv | Measure-Object).Count } catch {} }

$summaryObj = New-Object psobject -Property @{
  UnsignedProcesses   = $unsignedCount
  SuspiciousListeners = $suspListenCount
  PersistenceFindings = $persistCount
  IOC_Hits            = $IOC_Count
  SysmonAlerts        = $sysmonCount
}
$summaryObj | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir "summary.csv") -Encoding UTF8

Write-Host "[+] Done! Results saved in: $OutDir"

