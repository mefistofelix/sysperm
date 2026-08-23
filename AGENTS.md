# AGENTS.md

## Project

`sysperm` is a small C project built as a fat Cosmopolitan Actually Portable Executable (APE). The same `sysperm.exe` must run on supported Linux, macOS and Windows hosts.

## Scope

The executable provides idempotent system administration primitives for:

- local users;
- local groups;
- user/group membership;
- filesystem ownership and Unix mode permissions;
- named filesystem ACLs.

The public CLI should expose one common semantic model even when implementation details differ between operating systems.

## Platform strategy

Prefer the operating system's standard administration utilities for account and ACL mutation rather than editing account databases directly.

- Linux: `getent`, `useradd`, `usermod`, `userdel`, `groupadd`, `groupmod`, `groupdel`, `chmod`, `chown`, and `setfacl`/`getfacl` when ACLs are needed.
- macOS: `dscl`, `dseditgroup`, `chmod`, `chown` and native ACL support in `chmod`.
- Windows: `net`, `icacls`, and other inbox utilities only when needed.

Never invoke account-management commands through a shell string. Pass executable name and arguments separately so names and paths cannot become shell syntax.

## Idempotency

Commands describe desired state.

- `user NAME` means ensure the user exists.
- `user NAME --absent` means ensure it does not exist.
- `group NAME` means ensure the group exists.
- `group NAME --absent` means ensure it does not exist.
- Existing user/group attributes not explicitly supplied by the caller must remain unchanged, including an existing user's password when no password option is present.
- New users without an explicit password use one stable machine password derived from a sysperm-owned random machine secret. `pwd` prints that generated password. `-p`/`-P`/`--password` with no value explicitly means the empty password.
- A missing group referenced by an ensured user must be created automatically before membership is added.
- A newly created user gets a same-name primary/private group by default unless explicitly disabled.

## Permissions

Permission operations are recursive by default.

Support ordinary chmod-style `u`, `g`, `o`, `+`, `-`, and `=` expressions on Unix. Support named users and groups through the extended ACL expression layer and map those semantics to the platform-native ACL utility. `chown` is recursive by default; Unix accepts `OWNER[:GROUP]`, while Windows supports the owner identity through `icacls /setowner`.

On Linux, directory setgid (`g+s`) is enabled by default during recursive permission management so newly created children inherit the directory group. This is distinct from execute/traversal permission. Do not describe setgid itself as traversal.

Do not silently weaken requested ACL semantics. If one platform cannot faithfully represent an operation, return a clear error rather than pretending success.

## Cosmopolitan build

`build.sh` deliberately follows the proven `ape-run` WSL-safe build pattern. Keep it self-contained and keep all downloaded/generated Cosmopolitan material below `build/`.

On Windows, run the build through WSL. The script contains the canonical invocation comment at its top. Do not replace this with a native Windows cosmocc invocation unless it has been demonstrated to work with the same fat x86_64+aarch64 output.

The build downloads the official current `cosmocc.zip` from `cosmo.zip` and invokes the `cosmocc` fat compiler directly. `cosmocc` builds both x86_64 and aarch64 slices and combines them with `apelink` into `sysperm.exe`; do not rebuild the full Cosmopolitan source tree for this project.

The final executable keeps the `.exe` suffix on every operating system.

## Repository hygiene

Do not edit or vendor files inside `ape-run` or other projects. They may be inspected as references only. Generated toolchains, upstream source trees, temporary files, object files and build outputs belong under ignored paths.

Prefer small, explicit C code. Avoid dependencies that are not required for the actual system operation. Keep error messages actionable and propagate non-zero exit statuses from native utilities.
