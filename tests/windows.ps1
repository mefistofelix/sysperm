$ErrorActionPreference = 'Stop'
$bin = if ($env:BIN) { $env:BIN } else { '.\sysperm.exe' }
$user = 'sysperm_ci_user'
$group = 'sysperm_ci_group'
$root = Join-Path $env:TEMP ('sysperm-ci-' + $PID)

function Cleanup {
  & $bin user $user --absent 2>$null | Out-Null
  & $bin group $group --absent 2>$null | Out-Null
  Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
}

try {
  & $bin user $user -g $group -p 'sysperm-ci-password'
  if ($LASTEXITCODE) { throw 'user create failed' }
  & $bin user $user -p 'sysperm-ci-password-2'
  if ($LASTEXITCODE) { throw 'password reset failed' }
  net user $user | Out-Null
  $members = net localgroup $group
  if (-not ($members -match $user)) { throw 'membership missing' }

  New-Item -ItemType Directory -Path $root | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $root 'sub') | Out-Null
  Set-Content -Path (Join-Path $root 'sub\file.txt') -Value test
  & $bin perm $root "user:$user=rx"
  if ($LASTEXITCODE) { throw 'ACL grant failed' }
  $acl = Get-Acl $root
  if (-not ($acl.Access.IdentityReference.Value -match $user)) { throw 'ACL missing' }

  & $bin user $user --absent
  if ($LASTEXITCODE) { throw 'user delete failed' }
  if ((net user $user 2>$null) -and $LASTEXITCODE -eq 0) { throw 'user still exists' }
  & $bin group $group --absent
  if ($LASTEXITCODE) { throw 'group delete failed' }
}
finally { Cleanup }
