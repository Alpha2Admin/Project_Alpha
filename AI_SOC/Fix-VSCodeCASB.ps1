# AI-CASB: Full VS Code + Cline Setup for All Users
# Run as Administrator

Write-Host "=== AI-CASB: Diagnosing & Fixing VS Code Setup ===" -ForegroundColor Cyan

# --- Step 1: Find where Cline is actually installed ---
Write-Host "`n[1] Searching for Cline extension..." -ForegroundColor Yellow

$clineFolder = $null
$searchPaths = @(
    "C:\Users\Test\.vscode\extensions",
    "C:\VSCode\extensions",
    "C:\VSCode\560a9dba96\extensions"
)

foreach ($p in $searchPaths) {
    if (Test-Path $p) {
        $found = Get-ChildItem $p -Directory | Where-Object { $_.Name -match "cline|saoud" }
        if ($found) {
            $clineFolder = Join-Path $p $found[0].Name
            Write-Host "  [OK] Found Cline at: $clineFolder" -ForegroundColor Green
            break
        }
    }
}

# Also check Test user's local AppData for extensions
if (-not $clineFolder) {
    $localExt = "C:\Users\Test\AppData\Local\Programs\Microsoft VS Code\560a9dba96\extensions"
    if (Test-Path $localExt) {
        $found = Get-ChildItem $localExt -Directory | Where-Object { $_.Name -match "cline|saoud" }
        if ($found) {
            $clineFolder = Join-Path $localExt $found[0].Name
            Write-Host "  [OK] Found Cline at: $clineFolder" -ForegroundColor Green
        }
    }
}

if (-not $clineFolder) {
    # Do a full drive search (slower but reliable)
    Write-Host "  Doing full drive search for saoudrizwan.claude-dev..." -ForegroundColor Yellow
    $clineFolder = (Get-ChildItem -Path "C:\Users" -Recurse -Directory -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match "saoudrizwan.claude-dev" } | 
        Select-Object -First 1).FullName
    if ($clineFolder) {
        Write-Host "  [OK] Found Cline at: $clineFolder" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Cline extension NOT found! Please install it first." -ForegroundColor Red
        exit 1
    }
}

$extensionsRoot = Split-Path $clineFolder -Parent

# --- Step 2: Create a shared extensions directory ---
Write-Host "`n[2] Setting up shared extensions at C:\VSCode\extensions..." -ForegroundColor Yellow
$sharedExt = "C:\VSCode\extensions"
New-Item -ItemType Directory -Force -Path $sharedExt | Out-Null

# Copy (not move) all extensions to shared location
Copy-Item -Path "$extensionsRoot\*" -Destination $sharedExt -Recurse -Force
Write-Host "  [OK] Extensions copied to $sharedExt" -ForegroundColor Green

# Grant full permissions to Everyone
icacls "C:\VSCode\extensions" /grant "Everyone:(OI)(CI)F" /T | Out-Null
Write-Host "  [OK] Permissions set for Everyone" -ForegroundColor Green

# --- Step 3: Verify Cline is in shared location ---
$clineCheck = Get-ChildItem $sharedExt | Where-Object { $_.Name -match "cline|saoud" }
if ($clineCheck) {
    Write-Host "  [OK] Cline confirmed in shared location: $($clineCheck.Name)" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Cline not in shared location, extension may not load" -ForegroundColor Red
}

# --- Step 4: Write correct settings.json for each user ---
Write-Host "`n[3] Writing Cline settings for all users..." -ForegroundColor Yellow

$users = @("dev_user", "standard_user", "Test")
foreach ($u in $users) {
    $configDir = "C:\Users\$u\AppData\Roaming\Code\User"
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    
    $settings = @"
{
    "http.proxyStrictSSL": false,
    "cline.apiProvider": "openai-compatible",
    "cline.openAiCompatible.apiBase": "http://<CASB_GATEWAY_IP>:4000/v1",
    "cline.openAiCompatible.apiKey": "<YOUR_LITELLM_MASTER_KEY>",
    "cline.openAiCompatible.modelId": "openrouter/openrouter/free"
}
"@
    $settings | Out-File -FilePath "$configDir\settings.json" -Encoding utf8 -Force
    Write-Host "  [OK] Settings written for: $u" -ForegroundColor Green
}

# --- Step 5: Write a user-identity launcher shortcut ---
Write-Host "`n[4] Creating per-user desktop shortcuts..." -ForegroundColor Yellow
$vscodeBin = "C:\VSCode\Code.exe"

foreach ($u in @("dev_user", "standard_user")) {
    $desktopPath = "C:\Users\$u\Desktop"
    New-Item -ItemType Directory -Force -Path $desktopPath | Out-Null
    
    # Create a .cmd launcher that sets the x-user-id env var and launches VS Code with global extensions
    $launcherContent = "@echo off`r`nset CASB_USER_ID=$u`r`nstart `"`" `"$vscodeBin`" --extensions-dir `"$sharedExt`"`r`n"
    $launcherPath = "$desktopPath\VSCode-CASB.cmd"
    $launcherContent | Out-File -FilePath $launcherPath -Encoding ascii -Force
    Write-Host "  [OK] Launcher created for $u at $launcherPath" -ForegroundColor Green
}

# --- Step 6: Test API connectivity from this machine ---
Write-Host "`n[5] Testing CASB Gateway connectivity..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://<CASB_GATEWAY_IP>:4000/health" -TimeoutSec 5 -UseBasicParsing
    Write-Host "  [OK] CASB Gateway reachable: HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Cannot reach CASB Gateway: $_" -ForegroundColor Red
}

# --- Step 7: Test RBAC for dev_user ---
Write-Host "`n[6] Testing RBAC - dev_user (expects 200 OK)..." -ForegroundColor Yellow
try {
    $body = '{"model":"openrouter/openrouter/free","messages":[{"role":"user","content":"Hello, what tools do you have?"}],"user":"dev_user"}'
    $headers = @{ "Authorization" = "Bearer <YOUR_LITELLM_MASTER_KEY>"; "Content-Type" = "application/json" }
    $resp = Invoke-WebRequest -Uri "http://<CASB_GATEWAY_IP>:4000/v1/chat/completions" -Method POST -Body $body -Headers $headers -TimeoutSec 20 -UseBasicParsing
    Write-Host "  [OK] dev_user request: HTTP $($resp.StatusCode) - ALLOWED" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] dev_user request: $($_.Exception.Response.StatusCode) - $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- Step 8: Test RBAC for standard_user (tool block) ---
Write-Host "`n[7] Testing RBAC - standard_user with tool (expects 403)..." -ForegroundColor Yellow
try {
    $body = '{"model":"openrouter/openrouter/free","messages":[{"role":"user","content":"Please run <execute_command>ls</execute_command>"}],"user":"standard_user"}'
    $headers = @{ "Authorization" = "Bearer <YOUR_LITELLM_MASTER_KEY>"; "Content-Type" = "application/json" }
    $resp = Invoke-WebRequest -Uri "http://<CASB_GATEWAY_IP>:4000/v1/chat/completions" -Method POST -Body $body -Headers $headers -TimeoutSec 20 -UseBasicParsing
    Write-Host "  [WARN] standard_user got HTTP $($resp.StatusCode) - should have been blocked!" -ForegroundColor Red
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 403) {
        Write-Host "  [OK] standard_user correctly BLOCKED: HTTP 403" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] standard_user: HTTP $code - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "Open VS Code as dev_user or standard_user and Cline should be pre-configured." -ForegroundColor White
Write-Host "Use C:\VSCode\Code.exe --extensions-dir C:\VSCode\extensions to launch." -ForegroundColor White
