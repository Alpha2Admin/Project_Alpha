# --- CONFIGURATION ---
$UbuntuServerIP = "192.168.100.10"
$ProxyAddr = "http=$($UbuntuServerIP):8080;https=$($UbuntuServerIP):8080"
$CertPath = "C:\Certs\mitmproxy-ca-cert.pem"
$ExtDir = "C:\VSCode\extensions"

$Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'Code.exe'"

Write-Host "🛡️ AI-CASB Global Enforcement Active. Watching for VS Code..." -ForegroundColor Cyan

# Ensure the watcher is clean
Get-EventSubscriber -SourceIdentifier "VSCodeWatcher" -ErrorAction SilentlyContinue | Unregister-Event

# Create the Event Watcher
$Watcher = Register-CimIndicationEvent -Query $Query -SourceIdentifier "VSCodeWatcher"

try {
    while ($true) {
        $Event = Wait-Event -SourceIdentifier "VSCodeWatcher"
        $ProcessID = $Event.SourceEventArgs.NewEvent.ProcessID
        $FullCmd = (Get-CimInstance Win32_Process -Filter "ProcessID = $ProcessID").CommandLine

        # Check if the process was launched WITHOUT our enforcement flags
        if ($FullCmd -notmatch "--extensions-dir" -or $FullCmd -notmatch "--proxy-server") {
            Write-Host "[!] Unauthorized VS Code launch detected (PID: $ProcessID). Re-wrapping with CASB..." -ForegroundColor Yellow
            
            # Kill the un-proxied process
            Stop-Process -Id $ProcessID -Force
            
            # Launch the secure version
            $Env:NODE_EXTRA_CA_CERTS = $CertPath
            Start-Process "C:\VSCode\Code.exe" -ArgumentList "--ignore-certificate-errors", "--proxy-server=$ProxyAddr", "--extensions-dir=$ExtDir"
        }
        
        Remove-Event -SourceIdentifier "VSCodeWatcher"
    }
}
finally {
    Unregister-Event -SourceIdentifier "VSCodeWatcher"
}
