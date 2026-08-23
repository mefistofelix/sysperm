# sysperm

`sysperm` is a single fat Cosmopolitan/APE executable for managing local users, groups, memberships and filesystem permissions with one common CLI on Linux, macOS and Windows.

The intent is declarative and idempotent: commands describe the state that should exist rather than forcing the caller to distinguish creation from modification.

## Users and groups

```sh
sysperm user app
sysperm user app -g web,logs
sysperm user app -g web,logs -pg logs
sysperm user app -p 'temporary-password'
sysperm user app --home /srv/app --shell /bin/false
sysperm user app --absent

sysperm group deploy
sysperm group deploy --gid 1500
sysperm group deploy --absent
```

`user NAME` ensures that the account exists. If it already exists, only attributes explicitly present on the command line are changed; unspecified attributes are left untouched.

A newly-created Unix user gets a same-name primary group by default when no groups are supplied. `-g` / `--groups` accepts a comma-separated list; every named group is ensured automatically and the first group becomes primary. `-pg` / `--primary-group` overrides the primary group and also ensures a named group exists. On an existing user, passing `-g` likewise makes its first group primary unless `-pg` is supplied. Windows has no equivalent Unix primary-group attribute, so the groups are memberships there.

Group references use one convention everywhere: a platform-native ID is recognized automatically, otherwise the value is a name. On Linux and macOS an all-decimal value is treated as a GID; on Windows an `S-1-...` value is recognized as a SID. The backend then selects the native command form actually supported by the chosen system utility. Linux `useradd`/`usermod` accept names or numeric GIDs directly. macOS primary groups can be set by numeric GID, while `dseditgroup` membership requires a group name. Windows account and membership management deliberately depends only on `net.exe`; because `net localgroup` has no SID membership form, SID group membership is not supported. No PowerShell fallback is used.

`-p` / `-P` / `--password` accepts an optional clear-text password. `-p VALUE` uses that value; `-p` with no value means an explicitly empty password. For a newly-created user, omitting `-p` uses the stable machine password returned by `sysperm pwd`. Existing users still keep their password unchanged when `-p` is omitted. The machine password is derived from a random per-machine secret stored in an administrator-only location (`/var/lib/sysperm` on Linux, `/var/db/sysperm` on macOS, `%ProgramData%\\sysperm` on Windows), so all automatically-managed users on one machine share the same generated password. Because an explicit non-empty password is supplied as a command-line argument, callers should account for shell history and process-argument visibility.

For new users, the default shell is `/bin/sh` on Linux and `/bin/zsh` on macOS. Existing users keep their current shell unless `--shell` is explicitly supplied. Windows has no shell attribute in this abstraction.

`group NAME` has the equivalent ensure-present behavior, while `--absent` means ensure absent.

The caller is responsible for running `sysperm` with whatever privileges the requested system operation requires.

## Execute as another local user

```sh
sysperm pwd
sysperm exec app -- program arg1 "arg with spaces"
sysperm exec app -p 'password' -- program arg1
sysperm exec app -p -- program arg1
```

On Linux and macOS, `sysperm` resolves a local account, initializes its supplementary groups, switches GID/UID, and replaces itself with the requested program. The child therefore inherits the caller's stdin, stdout and stderr normally, including ordinary shell redirection, and its exit status becomes the `sysperm` exit status.

When `-p` is omitted, `exec` uses the same stable machine password printed by `sysperm pwd`. Supplying `-p` without a following password explicitly selects the empty string. On Windows, `sysperm` uses native Windows APIs (`LogonUserW`, `DuplicateTokenEx`, and `CreateProcessAsUserW`) and waits for the child, propagating its exit code. Standard input/output/error handles are inherited, so ordinary redirection around `sysperm` is also inherited by the launched process. Windows alternate-user process creation requires the caller token to hold the privileges required by `CreateProcessAsUserW`, notably `SeIncreaseQuotaPrivilege` and, for a different unrestricted primary token, `SeAssignPrimaryTokenPrivilege`. Merely being a member of Administrators does not guarantee that the latter privilege is present in the current token; service/System contexts commonly have it. `sysperm` reports `ERROR_PRIVILEGE_NOT_HELD` explicitly instead of silently falling back to PowerShell, `runas`, or another mechanism.

The execution feature intentionally targets local users only; it does not promise generic NSS/LDAP/Active Directory identity resolution.

## Filesystem permissions

Permission operations are recursive by default:

```sh
sysperm perm /srv/app u=rwX g=rX o=
sysperm perm /srv/app g+rwX
sysperm perm /srv/app group:deploy=rwx
sysperm perm /srv/app user:alice=rx
```

Unix mode expressions retain chmod-style `u`, `g`, `o`, `+`, `-`, `=` and `rwxX` syntax. Named ACL entries use `user:NAME` / `group:NAME` (or `u:NAME` / `g:NAME`) followed by the same operation idea.

Examples:

```sh
sysperm perm ./tree user:alice=rwx
sysperm perm ./tree group:developers+rwX
sysperm perm ./tree user:alice-
```

Use `--no-recursive` for only the specified path.

On Linux, recursive permission management also enables directory setgid (`g+s`) by default. This causes newly-created children to inherit the containing directory's group. Disable it with `--no-setgid`.

Named ACLs map to the native platform mechanism:

- Linux: `setfacl` (and eventually `getfacl` where read-modify-write semantics are required).
- macOS: native ACL support through `chmod`.
- Windows: `icacls`.

Ownership is available directly as `sysperm chown OWNER[:GROUP] PATH`, recursive by default and disableable with `--no-recursive`. Unix maps this to native `chown`; Windows maps the single owner identity form to `icacls /setowner` and rejects the Unix-only `OWNER:GROUP` form.

## Native account backends

`sysperm` intentionally uses the operating system's own account-management utilities rather than directly editing account databases:

- Linux: `getent`, `useradd`, `usermod`, `userdel`, `groupadd`, `groupmod`, `groupdel`.
- macOS: `sysadminctl`, `dscl`, `dseditgroup`.
- Windows: `net`.

This avoids trying to write through NSS on Linux and keeps the implementation aligned with each operating system's supported administration path.

## Build

The build follows the same WSL-safe Cosmopolitan approach used by the `ape-run` project. The official compiler toolchain is downloaded into the ignored `build/` directory; the full Cosmopolitan source tree is not rebuilt.

On Windows, run:

```cmd
wsl.exe --cd "%CD%" bash ./build.sh
```

or simply:

```cmd
build.cmd
```

From Linux/WSL:

```sh
./build.sh
```

To exercise the built APE against every locally installed WSL distro supported by the test harness:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\wsl-matrix.ps1
```

The local matrix currently targets Ubuntu and Debian when installed. Under WSL it deliberately invokes the APE through `/usr/bin/ape` so WSL's Windows PE interop cannot make the test accidentally exercise the Windows backend.

`build.sh` downloads the official current Cosmopolitan compiler archive from:

```text
https://cosmo.zip/pub/cosmocc/cosmocc.zip
```

It invokes `cosmocc` directly on `src/main.c`; the driver builds the x86_64 and aarch64 slices and fat-links them into:

```text
sysperm.exe
```

The `.exe` suffix is intentional and is retained on all supported operating systems.

### WSL note

WSL Windows-executable interop can intercept Cosmopolitan APE helper programs. The build script uses the same workaround as `ape-run`: while building under WSL it disables the relevant WSL interop registration and installs the matching native APE loader from the downloaded Cosmopolitan toolchain when needed.

## Status

The project is currently being brought up. User/group desired-state handling and the initial cross-platform ACL/mode abstraction are implemented; unsupported or lossy ACL translations should fail explicitly rather than silently changing meaning.
