<#
.SYNOPSIS
    Installs VS Code + Cline extension for ALL users on a Windows machine.
    Copies extensions into every existing user profile and the Default profile.
    Must be run as Administrator.
#>
param(
    [switch]$SkipInstall  # Skip VS Code installer download if already installed
)

$ExtensionsToInstall = @(
    "saoudrizwan.claude-dev",      # Cline AI assistant
    "ms-python.python",            # Python support
    "ms-azuretools.vscode-docker"  # Docker support
)

# CASB Gateway settings applied to every user
$CasbSettings = @{
    "http.proxyStrictSSL"                    = $false
    "cline.apiProvider"                      = "openai"
    "cline.openaiBaseUrl"                    = "http://<CASB_GATEWAY_IP>:4000/v1"
    "cline.openaiApiKey"                     = "<YOUR_LITELLM_MASTER_KEY>"
    "cline.openaiModelId"                    = "openrouter/auto"
    "extensions.autoUpdate"                  = $false
    "telemetry.telemetryLevel"               = "off"
    "security.workspace.trust.enabled"       = $false
}

$LogFile = "C:\vscode_global_setup.log"
function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts - $msg" | Tee-Object -FilePath $LogFile -Append | Write-Host
}

Write-Log "=== AI-CASB Global VS Code + Cline Setup ==="

# ── 1. Locate VS Code binary ────────────────────────────────────────────────
$codePaths = @(
    "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd",
    "$env:ProgramFiles\Microsoft VS Code\Code.exe",
    "${env:ProgramFiles(x86)}\Microsoft VS Code\bin\code.cmd",
    "$env:LocalAppData\Programs\Microsoft VS Code\bin\code.cmd"
)
$codePath = $null
foreach ($p in $codePaths) { if (Test-Path $p) { $codePath = $p; break } }

if (-not $codePath) {
    Write-Log "[!] VS Code not found. Downloading and installing silently..."
    $installer = "$env:TEMP\vscode_setup.exe"
    try {
        Invoke-WebRequest -Uri "https://update.code.visualstudio.com/latest/win32-x64/stable" `
            -OutFile $installer -UseBasicParsing -TimeoutSec 120
        Start-Process -FilePath $installer -ArgumentList `
            "/VERYSILENT /MERGETASKS=!runcode,addcontextmenufiles,addcontextmenufolders,associatewithfiles,addtopath /ALLUSERS" `
            -Wait -NoNewWindow
        Write-Log "[+] VS Code installed."
        # Refresh path
        $codePath = "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd"
    } catch {
        Write-Log "[!] FAILED to download/install VS Code: $_"
        exit 1
    }
}
Write-Log "[+] VS Code found at: $codePath"

# ── 2. Install extensions into a SHARED system-wide directory ────────────────
$SharedExtDir = "C:\ProgramData\VSCode\extensions"
if (-not (Test-Path $SharedExtDir)) {
    New-Item -ItemType Directory -Path $SharedExtDir -Force | Out-Null
    Write-Log "[+] Created shared extensions dir: $SharedExtDir"
}
icacls "$SharedExtDir" /grant "Everyone:(OI)(CI)F" /T /Q | Out-Null

foreach ($ext in $ExtensionsToInstall) {
    Write-Log "[*] Installing extension: $ext → $SharedExtDir"
    & $codePath --extensions-dir $SharedExtDir --install-extension $ext --force 2>&1 |
        ForEach-Object { Write-Log "    $_" }
}

# ── 3. Set Machine-level env var so VS Code CLI picks up shared dir ──────────
[Environment]::SetEnvironmentVariable("VSCODE_EXTENSIONS", $SharedExtDir, "Machine")
Write-Log "[+] Machine env var VSCODE_EXTENSIONS = $SharedExtDir"

# ── 4. Deploy settings.json + extensions to EVERY existing user ──────────────
$SettingsJson = $CasbSettings | ConvertTo-Json -Depth 3

# Collect all real + default user profiles
$profiles = @(Get-ChildItem "C:\Users" -Directory) + @(Get-Item "C:\Users\Default")

foreach ($prof in $profiles) {
    $userName = $prof.Name

    # Write CASB settings.json
    $codeUserPath = Join-Path $prof.FullName "AppData\Roaming\Code\User"
    if (-not (Test-Path $codeUserPath)) {
        New-Item -ItemType Directory -Path $codeUserPath -Force | Out-Null
    }
    $settingsFile = Join-Path $codeUserPath "settings.json"
    $SettingsJson | Out-File -FilePath $settingsFile -Encoding utf8 -Force
    Write-Log "[+] Settings applied → $settingsFile"

    # Symlink or copy extensions into per-user extensions dir
    $userExtDir = Join-Path $prof.FullName ".vscode\extensions"
    if (-not (Test-Path $userExtDir)) {
        New-Item -ItemType Directory -Path $userExtDir -Force | Out-Null
    }

    # Copy each installed extension folder into per-user dir
    Get-ChildItem -Path $SharedExtDir -Directory | ForEach-Object {
        $dest = Join-Path $userExtDir $_.Name
        if (-not (Test-Path $dest)) {
            Copy-Item -Path $_.FullName -Destination $dest -Recurse -Force
            Write-Log "    Copied $($_.Name) → $userExtDir"
        } else {
            Write-Log "    Exists: $($_.Name) in $userExtDir (skipped)"
        }
    }
}

# ── 5. Configure VS Code Machine-Wide default extensions path in registry ────
# This ensures any NEW user also gets the shared extensions automatically
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{EA457B21-F73E-494C-ACAB-524FDE069978}_is1"
    if (-not (Test-Path $regPath)) { $regPath = $null }

    # Write a VS Code argv.json to point at shared extensions (works for system install)
    $vscodeDataPath = "$env:ProgramFiles\Microsoft VS Code\resources\app"
    $argvFile = "$vscodeDataPath\argv.json"
    if (Test-Path $vscodeDataPath) {
        $argv = @{ "extensions-dir" = $SharedExtDir }
        $argv | ConvertTo-Json | Out-File -FilePath $argvFile -Encoding utf8 -Force
        Write-Log "[+] VS Code argv.json written: $argvFile"
    }
} catch {
    Write-Log "[~] Could not write argv.json (non-critical): $_"
}

Write-Log "=== Setup Complete ==="
Write-Host "`n[OK] All users now have Cline configured with OpenRouter." -ForegroundColor Green
Write-Host "    Extensions dir: $SharedExtDir"
Write-Host "    Log: $LogFile"
