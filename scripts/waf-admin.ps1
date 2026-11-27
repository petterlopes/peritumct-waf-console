# Local operator tunnel. Forwards the workstation to the console loopback.
# Does not publish :18990, does not write Traefik config, and does not spawn
# anything except tsh in the foreground.
param(
    [Parameter(Position = 0)]
    [ValidateSet("tunnel")]
    [string]$Command = "tunnel"
)

$ErrorActionPreference = "Stop"
$LocalPort = 18990
$Url = "http://127.0.0.1:${LocalPort}/waf/"
$Forward = "${LocalPort}:127.0.0.1:${LocalPort}"

if ($Command -ne "tunnel") {
    Write-Error "Usage: .\scripts\waf-admin.ps1 tunnel"
}

$tsh = Get-Command tsh -ErrorAction SilentlyContinue
if (-not $tsh) {
    Write-Error "tsh was not found on PATH. Install Teleport, log in, then rerun."
}

Write-Host "Teleport forward ${Forward} as root@localhost."
Write-Host "Leave this window open. Open ${Url}"
Write-Host "https://expertsforensic.com/waf/ stays Forbidden off the admin overlay."
Write-Host "Ctrl+C closes the tunnel."

& tsh ssh -N -L $Forward root@localhost
exit $LASTEXITCODE
