$userDir = "$env:APPDATA\Code\User"
if (-not (Test-Path $userDir)) { New-Item -ItemType Directory -Force -Path $userDir }

# Configuration for AI-CASB
$settings = @{
    "http.proxyStrictSSL" = $false
    "cline.apiProvider" = "openai-compatible"
    "cline.openAiCompatible.apiBase" = "http://<CASB_GATEWAY_IP>:4000/v1"
    "cline.openAiCompatible.apiKey" = "<YOUR_LITELLM_MASTER_KEY>"
    "cline.openAiCompatible.modelId" = "openrouter/openrouter/free"
}

# Inject the current Windows username as the AI User ID
# This allows the CASB to distinguish between standard_user and dev_user on the same VM
$settings["cline.openAiCompatible.userId"] = $env:USERNAME

$settings | ConvertTo-Json | Out-File -FilePath "$userDir\settings.json" -Encoding utf8
Write-Host "CASB Identity Enforced: $( $env:USERNAME )" -ForegroundColor Green
