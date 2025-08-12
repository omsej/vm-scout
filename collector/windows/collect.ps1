param(
  [string]$ApiUrl = "http://localhost:8000/ingest/inventory"
)

# OS info
$ci = Get-ComputerInfo | Select-Object OsName, OsVersion, WindowsBuildLabEx
$os = @{
  name    = $ci.OsName
  version = $ci.OsVersion
  build   = $ci.WindowsBuildLabEx
}

# Installed software from registry
$regPaths = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$software = foreach ($p in $regPaths) {
  Get-ItemProperty $p -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayVersion } |
    ForEach-Object {
      [pscustomobject]@{
        name      = $_.DisplayName
        version   = $_.DisplayVersion
        publisher = $_.Publisher
      }
    } | Sort-Object name -Unique
}


# Listening services + process mapping
$listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
$pidToName = @{}
Get-Process | ForEach-Object { $pidToName[$_.Id] = $_.ProcessName }

$services = foreach ($c in $listen) {
  [pscustomobject]@{
    protocol      = $c.State -eq 'Listen' ? 'TCP' : 'TCP'
    local_address = $c.LocalAddress
    local_port    = [int]$c.LocalPort
    process       = $pidToName[[int]$c.OwningProcess]
    banner        = $null  # placeholder; add banner grabbing later if needed
  } | Sort-Object local_port -Unique
}

$payload = [pscustomobject]@{
  hostname     = $env:COMPUTERNAME
  collected_at = (Get-Date).ToString("o")
  os           = $os
  software     = $software
  services     = $services
}

# Send
try {
  $json = $payload | ConvertTo-Json -Depth 6
  $resp = Invoke-RestMethod -Method POST -Uri $ApiUrl -ContentType "application/json" -Body $json
  Write-Host ("Ingest OK: " + ($resp | ConvertTo-Json -Compress))
} catch {
  Write-Error $_
  throw
}
