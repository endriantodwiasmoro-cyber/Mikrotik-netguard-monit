<#
.SYNOPSIS
    Setup Cloudflare Tunnel untuk NetGuard Monit dengan DuckDNS
.DESCRIPTION
    Otomatisasi: install cloudflared, login, create tunnel, route DNS, get token, update .env
.PREREQUISITE
    1. Sudah daftar DuckDNS & buat subdomain (contoh: netguard-xxx.duckdns.org)
    2. Sudah add site ke Cloudflare & ganti nameserver di DuckDNS
    3. Jalankan script ini sebagai Administrator
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$DuckDnsSubdomain,   # contoh: netguard-abc123 (tanpa .duckdns.org)

    [Parameter(Mandatory=$true)]
    [string]$HostnamePrefix      # contoh: monitor (full: monitor.netguard-abc123.duckdns.org)
)

$ErrorActionPreference = "Stop"
$fullDomain = "$DuckDnsSubdomain.duckdns.org"
$fullHostname = "$HostnamePrefix.$fullDomain"
$envPath = "R:\NetGuardMonit\.env"

Write-Host "=== NetGuard Monit - Cloudflare Tunnel Setup ===" -ForegroundColor Cyan
Write-Host "Domain: $fullDomain" -ForegroundColor Yellow
Write-Host "Hostname: $fullHostname" -ForegroundColor Yellow
Write-Host ""

# 1. Install cloudflared
Write-Host "[1/6] Install cloudflared..." -ForegroundColor Green
if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
    Write-Host "   Installing via winget..." -ForegroundColor Gray
    winget install --id Cloudflare.cloudflared --silent --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} else {
    Write-Host "   Already installed" -ForegroundColor Gray
}

# 2. Login Cloudflare
Write-Host "[2/6] Login Cloudflare (akan buka browser)..." -ForegroundColor Green
try {
    cloudflared tunnel login
} catch {
    Write-Error "Login gagal. Pastikan browser terbuka dan Anda authorize domain $fullDomain"
    exit 1
}

# 3. Create tunnel
Write-Host "[3/6] Create tunnel 'netguard'..." -ForegroundColor Green
$tunnelOutput = cloudflared tunnel create netguard 2>&1
Write-Host $tunnelOutput

# Extract tunnel ID
$tunnelIdRegex = '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'
if ($tunnelOutput -match $tunnelIdRegex) {
    $tunnelId = $Matches[1]
    Write-Host "   Tunnel ID: $tunnelId" -ForegroundColor Cyan
} else {
    # Mungkin tunnel sudah ada, coba list
    Write-Host "   Tunnel mungkin sudah ada, mencari..." -ForegroundColor Yellow
    $listOutput = cloudflared tunnel list
    if ($listOutput -match "netguard\s+($tunnelIdRegex)") {
        $tunnelId = $Matches[1]
        Write-Host "   Found existing tunnel ID: $tunnelId" -ForegroundColor Cyan
    } else {
        Write-Error "Tidak bisa mendapatkan Tunnel ID"
        exit 1
    }
}

# 4. Route DNS
Write-Host "[4/6] Route DNS: $fullHostname -> tunnel..." -ForegroundColor Green
cloudflared tunnel route dns netguard $fullHostname

# 5. Get token
Write-Host "[5/6] Get tunnel token..." -ForegroundColor Green
$token = cloudflared tunnel token $tunnelId
$token = $token.Trim()
Write-Host "   Token: $($token.Substring(0,20))..." -ForegroundColor Cyan

# 6. Update .env
Write-Host "[6/6] Update .env..." -ForegroundColor Green
if (-not (Test-Path $envPath)) {
    Write-Error "File .env tidak ditemukan di $envPath"
    exit 1
}

$envContent = Get-Content $envPath -Raw

# Update APP_TRUSTED_HOSTS
$envContent = $envContent -replace '^APP_TRUSTED_HOSTS=.*', "APP_TRUSTED_HOSTS=`"$fullHostname,localhost`""

# Update CLOUDFLARE_TUNNEL_TOKEN
if ($envContent -match '^CLOUDFLARE_TUNNEL_TOKEN=') {
    $envContent = $envContent -replace '^CLOUDFLARE_TUNNEL_TOKEN=.*', "CLOUDFLARE_TUNNEL_TOKEN=`"$token`""
} else {
    $envContent += "`nCLOUDFLARE_TUNNEL_TOKEN=`"$token`""
}

Set-Content $envPath $envContent -Encoding UTF8
Write-Host "   .env updated" -ForegroundColor Gray

Write-Host ""
Write-Host "=== SELESAI ===" -ForegroundColor Cyan
Write-Host "Hostname dashboard: https://$fullHostname" -ForegroundColor Yellow
Write-Host ""
Write-Host "Jalankan:" -ForegroundColor Green
Write-Host "  cd R:\NetGuardMonit" -ForegroundColor Gray
Write-Host "  docker compose up -d --build" -ForegroundColor Gray
Write-Host ""
Write-Host "⚠️  INGAT: Regenerate TELEGRAM_BOT_TOKEN di @BotFather sebelum jalan!" -ForegroundColor Red