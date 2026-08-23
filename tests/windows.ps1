$ErrorActionPreference = 'Stop'
$bin = if ($env:BIN) { $env:BIN } else { '.\sysperm.exe' }
$user = 'sysperm_ci_user'
$group = 'sysperm_ci_group'
$root = Join-Path $env:TEMP ('sysperm-ci-' + $PID)
$whoFile = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-who.txt')
$emptyWhoFile = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-empty-who.txt')
$emptyStatusFile = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-empty-status.txt')
$stdoutFile = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-stdout.txt')
$stdinFile = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-stdin.txt')
$stdinOutFile = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-stdinout.txt')
$exitFile = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-exit.txt')
$doneFile = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-done.txt')
$runner = Join-Path $env:PUBLIC ('sysperm-ci-' + $PID + '-run.cmd')
$task = 'sysperm-ci-' + $PID

function Cleanup {
  & $bin user $user --absent 2>$null | Out-Null
  & $bin group $group --absent 2>$null | Out-Null
  Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
  schtasks.exe /Delete /TN $task /F 2>$null | Out-Null
  Remove-Item -Force $whoFile,$emptyWhoFile,$emptyStatusFile,$stdoutFile,$stdinFile,$stdinOutFile,$exitFile,$doneFile,$runner -ErrorAction SilentlyContinue
}

try {
  & $bin user $user -g $group -p 'Sysperm-CI9!Pass'
  if ($LASTEXITCODE) { throw 'user create failed' }
  & $bin user $user -p 'Sysperm-CI8!Next'
  if ($LASTEXITCODE) { throw 'password reset failed' }
  # Omitting -p on an existing user must leave the password unchanged.
  & $bin user $user
  if ($LASTEXITCODE) { throw 'password-preserving upsert failed' }
  net user $user | Out-Null
  $members = net localgroup $group
  if (-not ($members -match $user)) { throw 'membership missing' }

  # Hosted Windows administrators do not carry SeAssignPrimaryTokenPrivilege.
  # Run the impersonation checks as LocalSystem so CreateProcessAsUserW is
  # tested under the privilege model sysperm documents for this operation.
  Set-Content -Path $stdinFile -Value 'stdin-value' -NoNewline
  $lines = @(
    '@echo off',
    ('"' + $bin + '" exec ' + $user + ' -p "Sysperm-CI8!Next" -- whoami.exe > "' + $whoFile + '"'),
    ('"' + $bin + '" exec ' + $user + ' -p "Sysperm-CI8!Next" -- cmd.exe /d /c "echo stdout-value" > "' + $stdoutFile + '"'),
    ('"' + $bin + '" exec ' + $user + ' -p "Sysperm-CI8!Next" -- cmd.exe /v:on /d /c "set /p X=& echo !X!" < "' + $stdinFile + '" > "' + $stdinOutFile + '"'),
    ('"' + $bin + '" exec ' + $user + ' -p "Sysperm-CI8!Next" -- cmd.exe /d /c "exit /b 23"'),
    ('echo %ERRORLEVEL% > "' + $exitFile + '"'),
    ('"' + $bin + '" user ' + $user + ' -p ""'),
    ('echo reset=%ERRORLEVEL% > "' + $emptyStatusFile + '"'),
    ('"' + $bin + '" user ' + $user),
    ('echo upsert=%ERRORLEVEL% >> "' + $emptyStatusFile + '"'),
    ('"' + $bin + '" -v exec ' + $user + ' -- whoami.exe > "' + $emptyWhoFile + '" 2>> "' + $emptyStatusFile + '"'),
    ('echo exec=%ERRORLEVEL% >> "' + $emptyStatusFile + '"'),
    ('echo done > "' + $doneFile + '"')
  )
  Set-Content -Path $runner -Value $lines -Encoding Ascii
  $start = (Get-Date).AddMinutes(2).ToString('HH:mm')
  schtasks.exe /Create /TN $task /TR ('"' + $runner + '"') /SC ONCE /ST $start /RU SYSTEM /RL HIGHEST /F | Out-Null
  if ($LASTEXITCODE) { throw 'scheduled impersonation test creation failed' }
  schtasks.exe /Run /TN $task | Out-Null
  if ($LASTEXITCODE) { throw 'scheduled impersonation test launch failed' }
  for ($i = 0; $i -lt 60 -and -not (Test-Path $doneFile); $i++) { Start-Sleep -Milliseconds 500 }
  if (-not (Test-Path $doneFile)) { throw 'scheduled impersonation test timed out' }
  $who = (Get-Content $whoFile -Raw).Trim()
  if (-not $who.ToLowerInvariant().EndsWith(('\' + $user).ToLowerInvariant())) { throw "impersonated exec identity failed: $who" }
  if ((Get-Content $stdoutFile -Raw).Trim() -ne 'stdout-value') { throw 'impersonated stdout inheritance failed' }
  if ((Get-Content $stdinOutFile -Raw).Trim() -ne 'stdin-value') { throw 'impersonated stdin inheritance failed' }
  $exitValue = (Get-Content $exitFile -Raw).Trim()
  if ($exitValue -ne '23') { throw "impersonated exec exit code failed: $exitValue" }
  $emptyStatus = (Get-Content $emptyStatusFile -Raw)
  $emptyWho = if (Test-Path $emptyWhoFile) { (Get-Content $emptyWhoFile -Raw).Trim() } else { '' }
  if (-not $emptyWho -or -not $emptyWho.ToLowerInvariant().EndsWith(('\' + $user).ToLowerInvariant())) { throw "empty-password exec failed: who=[$emptyWho] status=[$emptyStatus]" }

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
