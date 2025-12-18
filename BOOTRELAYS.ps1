$baseId = 1
$basePort = 8001
$ip = "194.146.36.166"
$dir = "http://194.146.36.166:5000"

# Start relays (detached) and save logs
New-Item -ItemType Directory -Force -Path ".\logs" | Out-Null
for ($i = 0; $i -lt 20; $i++) {
  $id = "relay_" + ($baseId + $i)
  $port = $basePort + $i
  $args = @(".\relay\relay_node.py", "--id", $id, "--port", $port, "--ip", $ip, "--directory", $dir)
  Start-Process -FilePath python `
    -ArgumentList $args `
    -WorkingDirectory "." `
    -RedirectStandardOutput ".\logs\$id.out.log" `
    -RedirectStandardError  ".\logs\$id.err.log" `
}