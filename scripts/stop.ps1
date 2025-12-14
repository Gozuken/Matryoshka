param(
  [string]$LogDir = "./logs"
)

$ErrorActionPreference = "Continue"

$Root = Resolve-Path "."
$LogDirFull = Join-Path $Root $LogDir
$pidsDir = Join-Path $LogDirFull "pids"

if (!(Test-Path $pidsDir)) {
  Write-Host "No pid dir found: $pidsDir"
  exit 0
}

Get-ChildItem -Path $pidsDir -Filter "*.pid" | ForEach-Object {
  $pidFile = $_.FullName
  $pid = (Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)

  if ($pid -and ($pid -match '^\d+$')) {
    Write-Host "Stopping PID $pid ($($_.Name))"
    try {
      Stop-Process -Id ([int]$pid) -Force
    } catch {
      Write-Host "  Could not stop PID $pid: $($_.Exception.Message)"
    }
  }

  try { Remove-Item $pidFile -Force } catch {}
}

Write-Host "Done."
