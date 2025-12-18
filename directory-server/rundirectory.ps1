
# Start directory server (set env for current session)
$envPORT = 5000
Start-Process -FilePath node -ArgumentList directory_server.js
