# SentinelPass Installation Script for Windows

param(
    [Parameter(Mandatory=$false)]
    # Defaults to the stable ID derived from the manifest key (matches
    # install.sh); override only when repackaging with a new key.
    [string]$ExtensionId = "nophfgfiiohedlodfeepjoioljbhggdd",

    [Parameter(Mandatory=$false)]
    [string]$BinaryDir = ""
)

$ErrorActionPreference = "Stop"

# Configuration
$InstallDir = Join-Path $env:LOCALAPPDATA "SentinelPass"
$NativeHostFileName = "com.passwordmanager.host.json"
$FirefoxHostFileName = "com.passwordmanager.host.firefox.json"
$ChromeRegistryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.passwordmanager.host"
$FirefoxRegistryPath = "HKCU:\Software\Mozilla\NativeMessagingHosts\com.passwordmanager.host"

Write-Host "Installing SentinelPass..." -ForegroundColor Green

# Create installation directory
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force
    Write-Host "Created installation directory: $InstallDir" -ForegroundColor Cyan
}

# Copy binaries
if ([string]::IsNullOrWhiteSpace($BinaryDir)) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $BinaryDir = Join-Path $ProjectRoot "target\release"
}

if (!(Test-Path $BinaryDir)) {
    Write-Error "Binary directory not found. Please run 'cargo build --release' first."
    exit 1
}

Copy-Item (Join-Path $BinaryDir "sentinelpass-host.exe") -Destination $InstallDir -Force
Copy-Item (Join-Path $BinaryDir "sentinelpass-daemon.exe") -Destination $InstallDir -Force
Copy-Item (Join-Path $BinaryDir "sentinelpass-ui.exe") -Destination $InstallDir -Force
if (Test-Path (Join-Path $BinaryDir "sentinelpass.exe")) {
    Copy-Item (Join-Path $BinaryDir "sentinelpass.exe") -Destination $InstallDir -Force
}

Write-Host "Copied binaries to $InstallDir" -ForegroundColor Cyan

# Generate native messaging host manifest with correct path
$ManifestDest = Join-Path $InstallDir $NativeHostFileName
$FirefoxManifestDest = Join-Path $InstallDir $FirefoxHostFileName
$BinaryPath = Join-Path $InstallDir "sentinelpass-host.exe"

$ManifestContent = @{
    name = "com.passwordmanager.host"
    description = "SentinelPass Native Messaging Host"
    path = $BinaryPath
    type = "stdio"
    allowed_origins = @(
        if ($ExtensionId -match '^[a-z]{32}$') {
            "chrome-extension://$ExtensionId/"
        } else {
            "chrome-extension://YOUR_EXTENSION_ID_HERE/"
        }
    )
}

$ManifestContent | ConvertTo-Json -Depth 10 | Out-File -FilePath $ManifestDest -Encoding UTF8

$FirefoxManifestContent = @{
    name = "com.passwordmanager.host"
    description = "SentinelPass Native Messaging Host"
    path = $BinaryPath
    type = "stdio"
    allowed_extensions = @(
        "sentinelpass@localhost"
    )
}

$FirefoxManifestContent | ConvertTo-Json -Depth 10 | Out-File -FilePath $FirefoxManifestDest -Encoding UTF8

Write-Host "Created manifest: $ManifestDest" -ForegroundColor Cyan
Write-Host "Created Firefox manifest: $FirefoxManifestDest" -ForegroundColor Cyan

if ($ExtensionId -match '^[a-z]{32}$') {
    Write-Host "Registered allowed origin: chrome-extension://$ExtensionId/" -ForegroundColor Green
} else {
    Write-Host "`nIMPORTANT: You need to update the extension ID in the manifest." -ForegroundColor Yellow
    Write-Host "1. Load the unpacked extension in Chrome from: browser-extension\chrome" -ForegroundColor Yellow
    Write-Host "2. Get the extension ID from chrome://extensions/" -ForegroundColor Yellow
    Write-Host "3. Run: .\register-chrome.ps1 -ExtensionId <ID> -InstallDir '$InstallDir'" -ForegroundColor Yellow
    Write-Host "   or edit 'allowed_origins' in: $ManifestDest" -ForegroundColor Yellow
}

# Create registry keys for native messaging hosts
if (!(Test-Path $ChromeRegistryPath)) {
    New-Item -Path $ChromeRegistryPath -Force
    Write-Host "Created registry key: $ChromeRegistryPath" -ForegroundColor Cyan
}
Set-ItemProperty -Path $ChromeRegistryPath -Name "(default)" -Value $ManifestDest
Write-Host "Registered Chrome native messaging host" -ForegroundColor Cyan

if (!(Test-Path $FirefoxRegistryPath)) {
    New-Item -Path $FirefoxRegistryPath -Force
    Write-Host "Created registry key: $FirefoxRegistryPath" -ForegroundColor Cyan
}
Set-ItemProperty -Path $FirefoxRegistryPath -Name "(default)" -Value $FirefoxManifestDest
Write-Host "Registered Firefox native messaging host" -ForegroundColor Cyan

# Add to PATH for convenience
$PathEnv = [Environment]::GetEnvironmentVariable("Path", "User")
if ($PathEnv -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", $PathEnv + ";$InstallDir", "User")
    Write-Host "Added $InstallDir to user PATH" -ForegroundColor Cyan
    Write-Warning "You may need to restart your terminal for PATH changes to take effect"
}

Write-Host "`nInstallation completed successfully!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Load the browser extension from browser-extension\chrome" -ForegroundColor White
Write-Host "2. Run 'sentinelpass init' to create a new vault" -ForegroundColor White
Write-Host "3. Start the UI: sentinelpass-ui" -ForegroundColor White
Write-Host "4. Use the browser extension to autofill passwords" -ForegroundColor White
