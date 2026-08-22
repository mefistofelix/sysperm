# sysperm

`sysperm` is a single fat Cosmopolitan/APE executable for managing local users, groups, memberships and filesystem permissions with one common CLI on Linux, macOS and Windows.

The intent is declarative and idempotent: commands describe the state that should exist rather than forcing the caller to distinguish creation from modification.

## Users and groups

```sh
sysperm user app
sysperm user app --group web --group logs
sysperm user app --home /srv/app --shell /bin/false
sysperm user app --absent

sysperm group deploy
sysperm group deploy --gid 1500
sysperm group deploy --absent
```

`user NAME` ensures that the account exists. If it already exists, only attributes explicitly present on the command line are changed; unspecified attributes are left untouched.

A newly-created user gets a same-name group by default. `--no-private-group` disables that behavior. Every group named with `--group` is ensured automatically before membership is added.

`group NAME` has the equivalent ensure-present behavior, while `--absent` means ensure absent.

The caller is responsible for running `sysperm` with whatever privileges the requested system operation requires.

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

Standard Unix ownership/mode operations use the native `chmod`/`chown` facilities where appropriate.

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
