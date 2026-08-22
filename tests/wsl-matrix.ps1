$ErrorActionPreference = 'Stop'
$distros = @('Ubuntu')
foreach ($d in $distros) {
  $found = (wsl.exe -l -q) -contains $d
  if (-not $found) {
    Write-Host "Skipping $d (not installed)"
    continue
  }
  Write-Host "=== $d ==="
  $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
  wsl.exe -d $d --cd $root env APE_LOADER=/usr/bin/ape bash ./tests/linux.sh
  if ($LASTEXITCODE) { throw "$d failed" }
}
