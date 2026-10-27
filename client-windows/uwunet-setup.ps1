#Requires -RunAsAdministrator
<#
    UwUNet - Windows client setup.

    Points this PC's (already PATCHED) Rec Room 20250718.01 client at the UwUNet
    server and trusts the server's TLS certificate authority, so the client talks
    to UwUNet instead of the dead rec.net.

    Run in an ELEVATED PowerShell:  Right-click Start > "Terminal (Admin)" /
    "Windows PowerShell (Admin)", then run this script.

        powershell -ExecutionPolicy Bypass -File uwunet-setup.ps1

    To UNDO everything later:   uwunet-setup.ps1 -Undo
#>
param([switch]$Undo)

$ErrorActionPreference = 'Stop'
$VPS       = '51.38.36.86'
$hostsFile = "$env:windir\System32\drivers\etc\hosts"
$marker    = '# UwUNet'

# The 22 rec.net subdomains the client contacts. Photon (*.photonengine.com etc.)
# is deliberately NOT redirected - the client reaches real Photon Cloud for voice
# and networking, exactly as on the Linux host.
$subs = @('accounts','ai','api','auth','cards','cdn','chat','clubs','commerce',
          'datacollection','discovery','econ','img','link','lists','match',
          'moderation','notify','ns','platformnotifications','playersettings','rooms')

# UwUNet CA - public certificate only (no private key). Trusting this lets the
# client accept the server's rec.net TLS cert.
$caPem = @'
-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIUefYCFhsJOFcsHlpkn9fES8NMaaMwDQYJKoZIhvcNAQEL
BQAwMjESMBAGA1UEAwwJVXdVTmV0IENBMQ8wDQYDVQQKDAZVd1VOZXQxCzAJBgNV
BAYTAlVTMB4XDTI2MTAyNTIyMzgyMVoXDTM2MTAyMjIyMzgyMVowMjESMBAGA1UE
AwwJVXdVTmV0IENBMQ8wDQYDVQQKDAZVd1VOZXQxCzAJBgNVBAYTAlVTMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp/tuzvAWM7z9h5xxvRm5DYSeAMRN
OckQs0lzYIooDBfzfbE5GbljuKrttGw/JuBbvvGnPQAhF/SeVRBtgzZo6V7oaJ+l
hDBE80igBVzTWBnbOUAGB9lcVWVVkC5pIMfiqwomt7qqF+bbFNsId3hmGFEAFXzy
JSg+jUS+UaLCl8IlTzBbF//87lVhrkzBCHdZ6n5yQFW/Ryb+CFaG6m6sx27+/57v
WYLcX61pG97lZPKWpRWBJWaooF7iM5EbRXC3hUlLFnd7xBWlNLHI72DDwxW3f0/R
PU0wldbR3FP0fJZykQh7eksX2hkdoTrmqa99ulZtefyJ4cCOyjq9eWo40QIDAQAB
o1MwUTAdBgNVHQ4EFgQURFOjB41AcQ9DU7foTbejTvJMPCAwHwYDVR0jBBgwFoAU
RFOjB41AcQ9DU7foTbejTvJMPCAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEARCx9OSIMQ/l/ou/yHAzjbXKOEcuqIVRM5GiQqcH6QjNL61bXpC4O
zHnOHMYvunrr6+pL1SRiP6qJHM8Z+b/2hovcABWgbCJTVd8lC0ciRJeLTDcwyUS3
pfeYMlZSo8b+x8OMrn9KSkuXt7/q+Xeej8Lms3ym3OP7DQBG3nyQ40VGL5bZotT8
1d3ZUaKFMc9xr1St/tS9zz0BFkjpn0w2/vPnflT/cee64f1PZ12Ip0U5jM68Abem
Jvq1dro10x09qIB17SLCZfCOm/wIt93udlb8kq8UcJLqcjAvkL2Dg3VMC5WvHfaJ
rlvJhoylr8PjpS4DEZ1iiEjaxs2umFsV5w==
-----END CERTIFICATE-----
'@

function Strip-UwUNetHosts {
    # Keep every line that is not ours (our marker, or an <ip> *.rec.net line).
    if (-not (Test-Path $hostsFile)) { return @() }
    Get-Content $hostsFile | Where-Object {
        ($_ -notmatch [regex]::Escape($marker)) -and ($_ -notmatch '\.rec\.net\s*$')
    }
}

if ($Undo) {
    Write-Host '== UwUNet Windows setup: UNDO ==' -ForegroundColor Cyan
    Set-Content -Path $hostsFile -Value (Strip-UwUNetHosts) -Encoding ascii
    ipconfig /flushdns | Out-Null
    Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object { $_.Subject -eq 'CN=UwUNet CA, O=UwUNet, C=US' } |
        ForEach-Object { Remove-Item $_.PSPath -Force }
    Write-Host '[ok] rec.net host entries removed, DNS flushed, UwUNet CA untrusted.' -ForegroundColor Green
    return
}

Write-Host '== UwUNet Windows setup ==' -ForegroundColor Cyan

# 1) Trust the UwUNet CA.
$caPath = Join-Path $env:TEMP 'uwunet-ca.crt'
Set-Content -Path $caPath -Value $caPem -Encoding ascii
Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Write-Host '[ok] UwUNet CA trusted (LocalMachine\Root).'

# 2) Redirect the rec.net domains to the UwUNet server (backup first).
Copy-Item $hostsFile "$hostsFile.uwunet-bak" -Force -ErrorAction SilentlyContinue
$lines = Strip-UwUNetHosts
$lines += $marker
foreach ($s in $subs) { $lines += ('{0} {1}.rec.net' -f $VPS, $s) }
Set-Content -Path $hostsFile -Value $lines -Encoding ascii
Write-Host ("[ok] hosts updated: {0} rec.net domains -> {1}" -f $subs.Count, $VPS)

# 3) Flush DNS so the new mapping takes effect immediately.
ipconfig /flushdns | Out-Null
Write-Host '[ok] DNS cache flushed.'

Write-Host ''
Write-Host 'Setup complete.' -ForegroundColor Green
Write-Host 'Checklist before launching your PATCHED client:'
Write-Host '  - 2025patch.ini  ApiHost=   (empty)   PhotonHost=   (empty)'
Write-Host '  - Launch Recroom_Release.exe the same way you normally do.'
Write-Host 'Log in with YOUR Steam - the server creates your UwUNet account automatically.'
