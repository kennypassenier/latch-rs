# D4 release signing (Windows 11). Run AFTER the release workflow has
# published the binaries + SHA256SUMS for a tag. Your secret key never
# touches GitHub.
#
# Usage:  scripts\sign-release.ps1 v2.0.0  [$HOME\.minisign\minisign.key]
param(
  [Parameter(Mandatory=$true)][string]$Tag,
  [string]$Key = "$HOME\.minisign\minisign.key"
)
$ErrorActionPreference = "Stop"
$repo = "kennypassenier/latch-rs"
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid()))
try {
  gh release download $Tag -R $repo -p SHA256SUMS -D $tmp
  minisign -S -m (Join-Path $tmp SHA256SUMS) -s $Key -x (Join-Path $tmp SHA256SUMS.minisig)
  gh release upload $Tag (Join-Path $tmp SHA256SUMS.minisig) -R $repo --clobber
  Write-Host "OK signed and uploaded SHA256SUMS.minisig for $Tag"
} finally { Remove-Item -Recurse -Force $tmp }
