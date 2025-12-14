param(
  [int]$DirectoryPort = 5000,
  [string]$DirectoryHost = "0.0.0.0",
  [int]$RelayCount = 3,
  [int]$RelayBasePort = 8001,
  [string]$AdvertiseIp = "127.0.0.1",
  [string]$DllDir = "./dlls",
  [string]$LogDir = "./logs"
)

$ErrorActionPreference = "Stop"

# Resolve paths
$Root = Resolve-Path "."
$DllDirFull = Resolve-Path $DllDir
$LogDirFull = Join-Path $Root $LogDir

New-Item -ItemType Directory -Force -Path $LogDirFull | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $LogDirFull "pids") | Out-Null

$DirectoryUrl = "http://$AdvertiseIp`:$DirectoryPort"

Write-Host "Root:        $Root"
Write-Host "Directory:   $DirectoryUrl"
Write-Host "Relays:      $RelayCount (ports $RelayBasePort..$($RelayBasePort + $RelayCount - 1))"
Write-Host "AdvertiseIp: $AdvertiseIp"
Write-Host "DllDir:      $DllDirFull"
Write-Host "Logs:        $LogDirFull"

# Common environment for child processes
$env:MATRYOSHKA_DLL_PATH = Join-Path $DllDirFull "Matryoshka.dll"
if (!(Test-Path $env:MATRYOSHKA_DLL_PATH)) {
  $env:MATRYOSHKA_DLL_PATH = Join-Path $DllDirFull "matryoshka.dll"
}
if (!(Test-Path $env:MATRYOSHKA_DLL_PATH)) {
  throw "Matryoshka.dll not found in $DllDirFull"
}

# Ensure dependent DLLs (libcrypto, cpr, etc.) are discoverable
$env:PATH = "$DllDirFull;$env:PATH"

# Start Directory Server
$dirLog = Join-Path $LogDirFull "directory-server.log"
$dirPidFile = Join-Path $LogDirFull "pids\directory-server.pid"

Write-Host "Starting directory server (port=$DirectoryPort)..."
$dirProc = Start-Process -FilePath "node" -ArgumentList "directory_server.js" `
  -WorkingDirectory (Join-Path $Root "directory-server") `
  -PassThru -RedirectStandardOutput $dirLog -RedirectStandardError $dirLog

$dirProc.Id | Out-File -Encoding ascii -FilePath $dirPidFile

# Set PORT for directory server process (Start-Process can't set per-process env easily in PS5.1)
# If you need a non-5000 port, set $env:PORT before running this script.
# Example:
#   $env:PORT=5000; .\scripts\start.ps1

# Start Relays
for ($i = 0; $i -lt $RelayCount; $i++) {
  $relayId = "relay_$($i+1)"
  $relayPort = $RelayBasePort + $i

  $relayLog = Join-Path $LogDirFull "$relayId.log"
  $relayPidFile = Join-Path $LogDirFull "pids\$relayId.pid"

  Write-Host "Starting relay $relayId on port $relayPort ..."

  $relayArgs = @(
    "relay_node.py",
    "--id", $relayId,
    "--port", "$relayPort",
    "--directory", "http://$AdvertiseIp`:$DirectoryPort",
    "--ip", $AdvertiseIp
  )

  $p = Start-Process -FilePath "python" -ArgumentList $relayArgs `
    -WorkingDirectory (Join-Path $Root "relay") `
    -PassThru -RedirectStandardOutput $relayLog -RedirectStandardError $relayLog

  $p.Id | Out-File -Encoding ascii -FilePath $relayPidFile
}

Write-Host "Done. Tail logs in $LogDirFull" 
Write-Host "Stop with: .\scripts\stop.ps1" 
