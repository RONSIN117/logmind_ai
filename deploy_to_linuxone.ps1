param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$HostIp,

    [Parameter(Mandatory=$false)]
    [string]$RemoteUser = "linux1",

    [Parameter(Mandatory=$false)]
    [string]$KeyFile = "rounak10.pem"
)

$ErrorActionPreference = "Stop"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  LogMind: Deploying to Real IBM LinuxONE Instance ($HostIp)      " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# 1. Verify PEM Key
if (-not (Test-Path $KeyFile)) {
    Write-Error "Key file '$KeyFile' not found in current directory."
    exit 1
}

# Ensure correct Windows permissions on key
icacls $KeyFile /inheritance:r /grant:r "$($env:USERNAME):(R)" | Out-Null

# 2. Test SSH Connection
Write-Host "[*] Testing SSH connectivity to $RemoteUser@$HostIp..." -ForegroundColor Yellow
$testConnection = ssh -i $KeyFile -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$RemoteUser@$HostIp" "uname -m" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Could not connect as user '$RemoteUser'. Output: $testConnection"
    Write-Host "Tip: Try with '-RemoteUser root' or '-RemoteUser ubuntu' if your LinuxONE image uses a different user." -ForegroundColor Yellow
    exit 1
}

$remoteArch = $testConnection.Trim()
Write-Host "[✓] Connected successfully! Remote Architecture: $remoteArch" -ForegroundColor Green
if ($remoteArch -match "s390x|s390") {
    Write-Host "[✓] Confirmed Native IBM Z / LinuxONE mainframe hardware!" -ForegroundColor Green
} else {
    Write-Host "[!] Note: Remote host is $remoteArch (not s390x)." -ForegroundColor Yellow
}

# 3. Create remote target directory
Write-Host "[*] Preparing remote directory ~/logmind..." -ForegroundColor Yellow
ssh -i $KeyFile -o StrictHostKeyChecking=no "$RemoteUser@$HostIp" "mkdir -p ~/logmind"

# 4. Transfer Codebase via SCP
Write-Host "[*] Uploading LogMind files to LinuxONE..." -ForegroundColor Yellow
scp -i $KeyFile -o StrictHostKeyChecking=no -r backend frontend data deployment requirements.txt run_linuxone.sh deploy_container.sh "$RemoteUser@${HostIp}:~/logmind/"

# 5. Fix permissions on Linux scripts
ssh -i $KeyFile -o StrictHostKeyChecking=no "$RemoteUser@$HostIp" "chmod +x ~/logmind/run_linuxone.sh ~/logmind/deploy_container.sh"

Write-Host "==================================================================" -ForegroundColor Green
Write-Host " [✓] Upload Complete! Starting LogMind on LinuxONE..." -ForegroundColor Green
Write-Host " Port 8000 is tunneled to your laptop browser." -ForegroundColor Green
Write-Host " Open: http://localhost:8000 once started." -ForegroundColor Green
Write-Host " Press Ctrl+C in this terminal when you want to stop." -ForegroundColor Gray
Write-Host "==================================================================" -ForegroundColor Green

# 6. Start server with local port forwarding 8000:localhost:8000 (with keepalive)
ssh -i $KeyFile -o StrictHostKeyChecking=no -o ServerAliveInterval=15 -o ServerAliveCountMax=9999 -t -L 8000:localhost:8000 "$RemoteUser@$HostIp" "cd ~/logmind && ./run_linuxone.sh"
