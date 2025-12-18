param(
  [string]$AdvertiseIp = "127.0.0.1",
  [int]$DirectoryPort = 5000,
  [int]$RelayCount = 20,
  [int]$RelayBasePort = 8000,
  [string]$LogDir = "./logs/20-relays",
  [string]$DllDir = "./dlls"
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path "."
$LogDirFull = Join-Path $Root $LogDir
$pidsDir = Join-Path $LogDirFull "pids"

New-Item -ItemType Directory -Force -Path $LogDirFull | Out-Null
New-Item -ItemType Directory -Force -Path $pidsDir | Out-Null

# Export env for directory server
$env:PORT = [string]$DirectoryPort

# Expose DLLs (if used by relays)
$env:MATRYOSHKA_DLL_PATH = Join-Path (Resolve-Path $DllDir) "Matryoshka.dll"
if (!(Test-Path $env:MATRYOSHKA_DLL_PATH)) {
  $env:MATRYOSHKA_DLL_PATH = Join-Path (Resolve-Path $DllDir) "matryoshka.dll"
}

$env:PATH = "$(Resolve-Path $DllDir);$env:PATH"

# Sanity checks
if (!(Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Host "node not found in PATH. Install Node.js or add it to PATH." -ForegroundColor Yellow
}
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Host "python not found in PATH. Add Python to PATH." -ForegroundColor Yellow
}

$directoryLog = Join-Path $LogDirFull "directory-server.log"
$directoryPidFile = Join-Path $pidsDir "directory-server.pid"

Write-Host "Starting Directory Server on 0.0.0.0:$DirectoryPort (logs: $directoryLog)"
$dirProc = Start-Process -FilePath "node" -ArgumentList "directory_server.js" `
  -WorkingDirectory (Join-Path $Root "directory-server") `
  -PassThru -RedirectStandardOutput $directoryLog -RedirectStandardError $directoryLog

$dirProc.Id | Out-File -Encoding ascii -FilePath $directoryPidFile

Start-Sleep -Seconds 1

Write-Host "Starting $RelayCount relays on ports $RelayBasePort..$($RelayBasePort + $RelayCount - 1)..."
for ($i = 0; $i -lt $RelayCount; $i++) {
  $relayId = "relay_$($i+1)"
  $relayPort = $RelayBasePort + $i

  $relayLog = Join-Path $LogDirFull "$relayId.log"
  $relayPidFile = Join-Path $pidsDir "$relayId.pid"

  Write-Host "Starting $relayId on 0.0.0.0:$relayPort (registering with http://$AdvertiseIp`:$DirectoryPort)"

  $relayArgs = @(
    "relay_node.py",
    "--id", $relayId,
    "--port", "${relayPort}",
    "--directory", "http://$AdvertiseIp`:$DirectoryPort",
    "--ip", $AdvertiseIp
  )

  $p = Start-Process -FilePath "python" -ArgumentList $relayArgs `
    -WorkingDirectory (Join-Path $Root "relay") `
    -PassThru -RedirectStandardOutput $relayLog -RedirectStandardError $relayLog

  $p.Id | Out-File -Encoding ascii -FilePath $relayPidFile
  Start-Sleep -Milliseconds 150
}

Write-Host "Done. Logs: $LogDirFull" -ForegroundColor Green
Write-Host "Stop all with: .\scripts\stop.ps1" -ForegroundColor Cyan
