#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/nt/accounting.h"
#include "libc/nt/dll.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/synchronization.h"
#include "libc/x/x.h"

extern char **environ;

#define MAX_ARGS 64
#define MAX_GROUPS 32

typedef enum { OS_LINUX, OS_MACOS, OS_WINDOWS, OS_OTHER } Os;

static bool verbose;

typedef struct {
  const char *name;
  bool absent;
  const char *home;
  const char *shell;
  const char *uid;
  const char *gid;
  const char *primary_group;
  const char *password;
  const char *groups[MAX_GROUPS];
  int group_count;
  bool private_group;
} UserSpec;

typedef struct {
  const char *name;
  bool absent;
  const char *gid;
} GroupSpec;

typedef struct {
  bool recursive;
  bool setgid_dirs;
  const char *path;
  const char **exprs;
  int expr_count;
} PermSpec;

static Os host_os(void) {
  if (IsWindows()) return OS_WINDOWS;
  if (IsXnu()) return OS_MACOS;
  if (IsLinux()) return OS_LINUX;
  return OS_OTHER;
}

static const char *os_name(Os os) {
  switch (os) {
    case OS_LINUX: return "linux";
    case OS_MACOS: return "macos";
    case OS_WINDOWS: return "windows";
    default: return "unsupported";
  }
}

static void print_command(char *const argv[]) {
  fprintf(stderr, "+");
  for (int i = 0; argv[i]; ++i) fprintf(stderr, " %s", argv[i]);
  fputc('\n', stderr);
}

static int spawn_wait(char *const argv[], bool quiet) {
  pid_t pid;
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  int nullfd = -1;
  if (verbose) print_command(argv);
  if (quiet && !verbose) {
    nullfd = open("/dev/null", O_WRONLY);
    if (nullfd >= 0) {
      posix_spawn_file_actions_adddup2(&fa, nullfd, STDOUT_FILENO);
      posix_spawn_file_actions_adddup2(&fa, nullfd, STDERR_FILENO);
    }
  }
  int rc = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  if (nullfd >= 0) close(nullfd);
  if (rc) {
    if (!quiet) fprintf(stderr, "sysperm: cannot run %s: %s\n", argv[0], strerror(rc));
    return 127;
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return 127;
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code && !quiet && verbose) {
      fprintf(stderr, "sysperm: command exited with status %d\n", code);
    }
    return code;
  }
  return 128;
}

static int spawn_wait_input(char *const argv[], const char *input, bool quiet) {
  int fds[2];
  if (pipe(fds)) return 127;
  size_t len = strlen(input);
  ssize_t written = write(fds[1], input, len);
  close(fds[1]);
  if (written < 0 || (size_t)written != len) { close(fds[0]); return 127; }

  pid_t pid;
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, fds[0], STDIN_FILENO);
  int nullfd = -1;
  if (verbose) print_command(argv);
  if (quiet && !verbose) {
    nullfd = open("/dev/null", O_WRONLY);
    if (nullfd >= 0) {
      posix_spawn_file_actions_adddup2(&fa, nullfd, STDOUT_FILENO);
      posix_spawn_file_actions_adddup2(&fa, nullfd, STDERR_FILENO);
    }
  }
  int rc = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  close(fds[0]);
  if (nullfd >= 0) close(nullfd);
  if (rc) return 127;
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return 127;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

static int spawn_capture(char *const argv[], char *out, size_t out_size) {
  if (verbose) print_command(argv);
  int fds[2];
  if (pipe(fds)) return 127;
  pid_t pid;
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
  int rc = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  close(fds[1]);
  if (rc) { close(fds[0]); return 127; }
  size_t used = 0;
  while (used + 1 < out_size) {
    ssize_t n = read(fds[0], out + used, out_size - used - 1);
    if (n <= 0) break;
    used += (size_t)n;
  }
  close(fds[0]);
  out[used] = 0;
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return 127;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

static int tool_error(Os os, const char *operation, int rc) {
  if (!rc) return 0;
  if (rc == 127) fprintf(stderr, "sysperm: %s failed: required system tool could not be run\n", operation);
  else if (os == OS_WINDOWS && rc == 5) fprintf(stderr, "sysperm: %s failed: access denied; administrator privileges are required\n", operation);
  else if (os == OS_WINDOWS && rc == 2) fprintf(stderr, "sysperm: %s failed: the requested account, group, or resource was not found\n", operation);
  else if (os == OS_LINUX && rc == 4) fprintf(stderr, "sysperm: %s failed: requested ID is already in use\n", operation);
  else if (os == OS_LINUX && rc == 6) fprintf(stderr, "sysperm: %s failed: requested account or group does not exist\n", operation);
  else if (os == OS_LINUX && rc == 8) fprintf(stderr, "sysperm: %s failed: account or group is currently in use\n", operation);
  else if (os == OS_LINUX && rc == 9) fprintf(stderr, "sysperm: %s failed: requested account or group already exists\n", operation);
  else if (os == OS_LINUX && rc == 10) fprintf(stderr, "sysperm: %s failed: system account/group database could not be updated\n", operation);
  else if (os == OS_LINUX && rc == 12) fprintf(stderr, "sysperm: %s failed: home directory could not be created or removed\n", operation);
  else fprintf(stderr, "sysperm: %s failed (system tool exit status %d)\n", operation, rc);
  return rc;
}

static int tool_result(Os os, const char *operation, int rc) {
  return rc ? tool_error(os, operation, rc) : 0;
}

static int runv(bool quiet, const char *a0, ...) {
  char *argv[MAX_ARGS];
  int n = 0;
  va_list ap;
  va_start(ap, a0);
  const char *s = a0;
  while (s && n < MAX_ARGS - 1) {
    argv[n++] = (char *)s;
    s = va_arg(ap, const char *);
  }
  va_end(ap);
  argv[n] = NULL;
  return spawn_wait(argv, quiet);
}

static bool user_exists(Os os, const char *name) {
  if (os == OS_LINUX) return runv(true, "getent", "passwd", name, NULL) == 0;
  if (os == OS_MACOS) {
    char node[512]; snprintf(node, sizeof(node), "/Users/%s", name);
    return runv(true, "dscl", ".", "-read", node, NULL) == 0;
  }
  if (os == OS_WINDOWS) return runv(true, "net.exe", "user", name, NULL) == 0;
  return false;
}

static bool is_numeric_id(const char *s) {
  if (!s || !*s) return false;
  for (; *s; ++s) if (*s < '0' || *s > '9') return false;
  return true;
}

static bool is_windows_sid(const char *s) {
  if (!s || strncmp(s, "S-1-", 4)) return false;
  s += 4;
  bool digit = false;
  for (; *s; ++s) {
    if (*s >= '0' && *s <= '9') digit = true;
    else if (*s == '-' && digit) digit = false;
    else return false;
  }
  return digit;
}

static bool is_platform_id(Os os, const char *s) {
  return os == OS_WINDOWS ? is_windows_sid(s) : is_numeric_id(s);
}

static bool group_exists(Os os, const char *name) {
  if (os == OS_LINUX) return runv(true, "getent", "group", name, NULL) == 0;
  if (os == OS_MACOS) {
    char node[512]; snprintf(node, sizeof(node), "/Groups/%s", name);
    return runv(true, "dscl", ".", "-read", node, NULL) == 0;
  }
  if (os == OS_WINDOWS) return runv(true, "net.exe", "localgroup", name, NULL) == 0;
  return false;
}

static int ensure_group(Os os, const GroupSpec *g) {
  bool exists = group_exists(os, g->name);
  if (g->absent) {
    if (!exists) return 0;
    if (os == OS_LINUX) return tool_result(os, "group deletion", runv(false, "groupdel", g->name, NULL));
    if (os == OS_MACOS) return tool_result(os, "group deletion", runv(false, "dseditgroup", "-o", "delete", g->name, NULL));
    if (os == OS_WINDOWS) return tool_result(os, "group deletion", runv(false, "net.exe", "localgroup", g->name, "/delete", NULL));
    return 2;
  }

  if (!exists) {
    if (os == OS_LINUX) {
      if (g->gid) return tool_result(os, "group creation", runv(false, "groupadd", "-g", g->gid, g->name, NULL));
      return tool_result(os, "group creation", runv(false, "groupadd", g->name, NULL));
    }
    if (os == OS_MACOS) {
      if (g->gid) return tool_result(os, "group creation", runv(false, "dseditgroup", "-o", "create", "-i", g->gid, g->name, NULL));
      return tool_result(os, "group creation", runv(false, "dseditgroup", "-o", "create", g->name, NULL));
    }
    if (os == OS_WINDOWS) return tool_result(os, "group creation", runv(false, "net.exe", "localgroup", g->name, "/add", NULL));
    return 2;
  }

  if (g->gid) {
    if (os == OS_LINUX) return tool_result(os, "group modification", runv(false, "groupmod", "-g", g->gid, g->name, NULL));
    if (os == OS_MACOS) {
      char node[512]; snprintf(node, sizeof(node), "/Groups/%s", g->name);
      return tool_result(os, "group modification", runv(false, "dscl", ".", "-create", node, "PrimaryGroupID", g->gid, NULL));
    }
  }
  return 0;
}

static int mac_group_gid(const char *group, char gid[32]) {
  char node[512];
  snprintf(node, sizeof(node), "/Groups/%s", group);
  char *av[] = {"dscl", ".", "-read", node, "PrimaryGroupID", NULL};
  char out[256];
  int rc = spawn_capture(av, out, sizeof(out));
  if (rc) return rc;
  char *p = strrchr(out, ' ');
  if (!p) return 2;
  while (*p == ' ') ++p;
  size_t n = strcspn(p, "\r\n");
  if (!n || n >= 32) return 2;
  memcpy(gid, p, n);
  gid[n] = 0;
  return 0;
}

static int set_password(Os os, const char *user, const char *password) {
  if (strchr(password, '\n') || strchr(password, '\r')) {
    fprintf(stderr, "sysperm: password cannot contain a newline\n");
    return 2;
  }
  if (os == OS_LINUX) {
    if (!*password) return tool_result(os, "password clearing", runv(false, "passwd", "-d", user, NULL));
    char line[4096];
    int n = snprintf(line, sizeof(line), "%s:%s\n", user, password);
    if (n < 0 || (size_t)n >= sizeof(line)) return 2;
    char *av[] = {"chpasswd", NULL};
    return tool_result(os, "password change", spawn_wait_input(av, line, false));
  }
  if (os == OS_MACOS) {
    char node[512];
    snprintf(node, sizeof(node), "/Users/%s", user);
    return tool_result(os, "password change", runv(false, "dscl", ".", "-passwd", node, password, NULL));
  }
  if (os == OS_WINDOWS) {
    if (!*password) {
      int rc = runv(false, "net.exe", "user", user, "/passwordreq:no", NULL);
      if (rc) return tool_error(os, "password policy update", rc);
    }
    return tool_error(os, "password change", runv(false, "net.exe", "user", user, password, "/Y", NULL));
  }
  return 2;
}

static int add_membership(Os os, const char *user, const char *group) {
  bool numeric = is_numeric_id(group);
  bool sid = is_windows_sid(group);
  if (os == OS_MACOS && numeric) {
    fprintf(stderr, "sysperm: dseditgroup membership requires a group name, not a GID\n");
    return 2;
  }
  if (!(os == OS_LINUX && numeric) && !(os == OS_WINDOWS && sid)) {
    GroupSpec g = {.name = group};
    int rc = ensure_group(os, &g);
    if (rc) return rc;
  }
  if (os == OS_LINUX) return tool_result(os, "group membership update", runv(false, "usermod", "-a", "-G", group, user, NULL));
  if (os == OS_MACOS) return tool_result(os, "group membership update", runv(false, "dseditgroup", "-o", "edit", "-a", user, "-t", "user", group, NULL));
  if (os == OS_WINDOWS && sid) {
    fprintf(stderr, "sysperm: net.exe localgroup does not provide a SID form for membership; use the group name\n");
    return 2;
  }
  if (os == OS_WINDOWS) return tool_result(os, "group membership update", runv(false, "net.exe", "localgroup", group, user, "/add", NULL));
  return 2;
}

static int ensure_user(Os os, const UserSpec *u) {
  const char *username = u->name;
  bool exists = user_exists(os, username);
  const char *primary = u->primary_group;
  if (!primary && u->group_count) primary = u->groups[0];
  if (!primary && !exists && u->private_group && os != OS_WINDOWS) primary = u->name;
  if (u->absent) {
    if (!exists) return 0;
    if (os == OS_LINUX) return tool_result(os, "user deletion", runv(false, "userdel", username, NULL));
    if (os == OS_MACOS) {
      char node[512]; snprintf(node, sizeof(node), "/Users/%s", username);
      return tool_result(os, "user deletion", runv(false, "dscl", ".", "-delete", node, NULL));
    }
    if (os == OS_WINDOWS) return tool_result(os, "user deletion", runv(false, "net.exe", "user", username, "/delete", NULL));
    return 2;
  }

  const char *primary_backend = primary;
  char mac_primary_gid[32];
  if (primary && os == OS_LINUX && !is_numeric_id(primary)) {
    GroupSpec pg = {.name = primary};
    int rc = ensure_group(os, &pg);
    if (rc) return rc;
  } else if (primary && os == OS_MACOS) {
    if (is_numeric_id(primary)) {
      primary_backend = primary;
    } else {
      GroupSpec pg = {.name = primary};
      int rc = ensure_group(os, &pg);
      if (rc) return rc;
      rc = mac_group_gid(primary, mac_primary_gid);
      if (rc) return rc;
      primary_backend = mac_primary_gid;
    }
  }

  if (!exists) {
    int rc = 0;
    if (os == OS_LINUX) {
      char *av[MAX_ARGS]; int n = 0;
      av[n++] = "useradd";
      if (primary) { av[n++] = "-g"; av[n++] = (char *)primary_backend; }
      if (u->home) { av[n++] = "-d"; av[n++] = (char *)u->home; }
      av[n++] = "-s"; av[n++] = (char *)(u->shell ? u->shell : "/bin/sh");
      if (u->uid) { av[n++] = "-u"; av[n++] = (char *)u->uid; }
      if (u->gid) { av[n++] = "-g"; av[n++] = (char *)u->gid; }
      av[n++] = (char *)username; av[n] = NULL;
      rc = spawn_wait(av, false);
    } else if (os == OS_MACOS) {
      char *av[MAX_ARGS]; int n = 0;
      av[n++] = "sysadminctl"; av[n++] = "-addUser"; av[n++] = (char *)username;
      av[n++] = "-password"; av[n++] = (char *)(u->password ? u->password : "");
      if (u->home) { av[n++] = "-home"; av[n++] = (char *)u->home; }
      if (u->uid) { av[n++] = "-UID"; av[n++] = (char *)u->uid; }
      av[n++] = "-shell"; av[n++] = (char *)(u->shell ? u->shell : "/bin/zsh");
      av[n] = NULL;
      rc = spawn_wait(av, false);
      if (rc) {
        for (int i = 0; i < 5 && rc; ++i) {
          if (user_exists(os, username)) rc = 0;
          else sleep(1);
        }
      }
      if (!rc && (primary || u->gid)) {
        char gid[32];
        const char *value = u->gid;
        if (primary) value = primary_backend;
        char node[512]; snprintf(node, sizeof(node), "/Users/%s", username);
        rc = runv(false, "dscl", ".", "-create", node, "PrimaryGroupID", value, NULL);
      }
    } else if (os == OS_WINDOWS) {
      if (u->password && *u->password) {
        rc = runv(false, "net.exe", "user", username, u->password, "/add", "/Y", NULL);
      } else {
        rc = runv(false, "net.exe", "user", username, "", "/add", "/passwordreq:no", "/Y", NULL);
      }
    } else rc = 2;
    if (rc) return tool_error(os, "user creation", rc);
    if (os == OS_LINUX && (rc = set_password(os, username, u->password ? u->password : ""))) return rc;
  } else {
    int rc = 0;
    if (os == OS_LINUX) {
      if (u->home && (rc = runv(false, "usermod", "-d", u->home, username, NULL))) return tool_error(os, "user home update", rc);
      if (u->shell && (rc = runv(false, "usermod", "-s", u->shell, username, NULL))) return tool_error(os, "user shell update", rc);
      if (u->uid && (rc = runv(false, "usermod", "-u", u->uid, username, NULL))) return tool_error(os, "user ID update", rc);
      if (primary && (rc = runv(false, "usermod", "-g", primary_backend, username, NULL))) return tool_error(os, "primary group update", rc);
      else if (u->gid && (rc = runv(false, "usermod", "-g", u->gid, username, NULL))) return tool_error(os, "primary group update", rc);
    } else if (os == OS_MACOS) {
      char node[512]; snprintf(node, sizeof(node), "/Users/%s", username);
      if (u->home && (rc = runv(false, "dscl", ".", "-create", node, "NFSHomeDirectory", u->home, NULL))) return tool_error(os, "user home update", rc);
      if (u->shell && (rc = runv(false, "dscl", ".", "-create", node, "UserShell", u->shell, NULL))) return tool_error(os, "user shell update", rc);
      if (u->uid && (rc = runv(false, "dscl", ".", "-create", node, "UniqueID", u->uid, NULL))) return tool_error(os, "user ID update", rc);
      if (primary) {
        if ((rc = runv(false, "dscl", ".", "-create", node, "PrimaryGroupID", primary_backend, NULL))) return tool_error(os, "primary group update", rc);
      } else if (u->gid && (rc = runv(false, "dscl", ".", "-create", node, "PrimaryGroupID", u->gid, NULL))) return tool_error(os, "primary group update", rc);
    }
    if (u->password && (rc = set_password(os, username, u->password))) return rc;
  }

  for (int i = 0; i < u->group_count; ++i) {
    int rc = add_membership(os, username, u->groups[i]);
    if (rc) return rc;
  }
  return 0;
}

static bool is_named_acl(const char *e) {
  return !strncmp(e, "user:", 5) || !strncmp(e, "group:", 6) || !strncmp(e, "u:", 2) || !strncmp(e, "g:", 2);
}

static int perm_bits(const char *s) {
  int p = 0;
  for (; *s; ++s) {
    if (*s == 'r') p |= 4;
    else if (*s == 'w') p |= 2;
    else if (*s == 'x' || *s == 'X') p |= 1;
    else return -1;
  }
  return p;
}

static void rwx_string(int bits, char out[4]) {
  out[0] = bits & 4 ? 'r' : '-';
  out[1] = bits & 2 ? 'w' : '-';
  out[2] = bits & 1 ? 'x' : '-';
  out[3] = 0;
}

static int linux_acl_apply_one(const char *path, const char *expr, bool is_dir) {
  const char *p = strchr(expr, ':');
  if (!p) return 2;
  bool group = expr[0] == 'g';
  const char *name = p + 1;
  const char *op = strpbrk(name, "+-=");
  if (!op || op == name) return 2;
  char who[256];
  size_t n = (size_t)(op - name);
  if (n >= sizeof(who)) return 2;
  memcpy(who, name, n); who[n] = 0;
  int bits = perm_bits(op + 1);
  if (bits < 0) return 2;
  char rwx[4]; rwx_string(bits, rwx);
  char entry[512];
  snprintf(entry, sizeof(entry), "%c:%s:%s", group ? 'g' : 'u', who, rwx);

  int rc;
  if (*op == '-') {
    /* Named '-' means remove the named ACL entry entirely when no bits are
       supplied. Bit subtraction requires reading the current ACL; keep the
       explicit all-entry operation deterministic. */
    if (*(op + 1) == 0) {
      char remove_entry[512]; snprintf(remove_entry, sizeof(remove_entry), "%c:%s", group ? 'g' : 'u', who);
      rc = runv(false, "setfacl", "-x", remove_entry, path, NULL);
    } else {
      fprintf(stderr, "sysperm: Linux named ACL bit subtraction is not yet safe without per-entry readback; use '=' or NAME- to remove the entry\n");
      return 2;
    }
  } else {
    rc = runv(false, "setfacl", "-m", entry, path, NULL);
  }
  if (rc) return rc;

  if (is_dir && *op != '-') {
    char def[520]; snprintf(def, sizeof(def), "d:%s", entry);
    rc = runv(false, "setfacl", "-m", def, path, NULL);
  }
  return rc;
}

static int mac_acl_apply_one(const char *path, const char *expr) {
  const char *p = strchr(expr, ':');
  bool group = expr[0] == 'g';
  if (!p) return 2;
  const char *name = p + 1;
  const char *op = strpbrk(name, "+-=");
  if (!op || op == name) return 2;
  char who[256]; size_t n = (size_t)(op - name);
  if (n >= sizeof(who)) return 2;
  memcpy(who, name, n); who[n] = 0;
  int bits = perm_bits(op + 1); if (bits < 0) return 2;
  char rights[128] = "";
  if (bits & 4) strcat(rights, "read,");
  if (bits & 2) strcat(rights, "write,");
  if (bits & 1) strcat(rights, "execute,");
  size_t l = strlen(rights); if (l && rights[l - 1] == ',') rights[l - 1] = 0;
  char ace[512];
  snprintf(ace, sizeof(ace), "%s:%s %s %s", group ? "group" : "user", who, *op == '-' ? "deny" : "allow", rights);
  if (*op == '=') {
    /* '=a# 0' is positional; adding an explicit allow is safer than deleting
       unrelated ACLs. */
    return runv(false, "chmod", "+a", ace, path, NULL);
  }
  return runv(false, "chmod", "+a", ace, path, NULL);
}

static const char *win_rights(int bits) {
  if (bits == 7) return "F";
  if ((bits & 6) == 6) return "M";
  if (bits & 2) return "W";
  if (bits & 4) return "R";
  if (bits & 1) return "RX";
  return "R";
}

static int windows_acl_apply_one(const char *path, const char *expr, bool recursive) {
  const char *p = strchr(expr, ':');
  bool group = expr[0] == 'g';
  (void)group;
  if (!p) return 2;
  const char *name = p + 1;
  const char *op = strpbrk(name, "+-=");
  if (!op || op == name) return 2;
  char who[256]; size_t n = (size_t)(op - name);
  if (n >= sizeof(who)) return 2;
  memcpy(who, name, n); who[n] = 0;
  int bits = perm_bits(op + 1); if (bits < 0) return 2;
  char grant[512];
  snprintf(grant, sizeof(grant), "%s:(OI)(CI)%s", who, win_rights(bits));
  if (*op == '-') {
    char deny[512]; snprintf(deny, sizeof(deny), "%s:(OI)(CI)%s", who, win_rights(bits));
    return recursive ? runv(false, "icacls.exe", path, "/deny", deny, "/T", "/C", NULL)
                     : runv(false, "icacls.exe", path, "/deny", deny, NULL);
  }
  const char *flag = *op == '=' ? "/grant:r" : "/grant";
  return recursive ? runv(false, "icacls.exe", path, flag, grant, "/T", "/C", NULL)
                   : runv(false, "icacls.exe", path, flag, grant, NULL);
}

static int setgid_walk(const char *path, bool recursive) {
  struct stat st;
  if (lstat(path, &st)) return errno;
  if (S_ISDIR(st.st_mode)) {
    if (chmod(path, st.st_mode | S_ISGID)) return errno;
    if (recursive) {
      DIR *d = opendir(path);
      if (!d) return errno;
      struct dirent *de;
      while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char child[4096]; snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        struct stat cs; if (lstat(child, &cs)) continue;
        if (S_ISDIR(cs.st_mode)) {
          int rc = setgid_walk(child, true);
          if (rc) { closedir(d); return rc; }
        }
      }
      closedir(d);
    }
  }
  return 0;
}

static int acl_walk(Os os, const char *path, const char *expr, bool recursive) {
  struct stat st;
  if (lstat(path, &st)) { perror(path); return 1; }
  int rc = os == OS_LINUX
               ? linux_acl_apply_one(path, expr, S_ISDIR(st.st_mode))
               : mac_acl_apply_one(path, expr);
  if (rc || !recursive || !S_ISDIR(st.st_mode)) return rc;
  DIR *d = opendir(path); if (!d) return 1;
  struct dirent *de;
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
    char child[4096]; snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
    rc = acl_walk(os, child, expr, true);
    if (rc) break;
  }
  closedir(d);
  return rc;
}

static bool win_needs_quotes(const char *s) {
  if (!*s) return true;
  for (; *s; ++s) if (*s == ' ' || *s == '\t' || *s == '"') return true;
  return false;
}

static char *win_command_line(char **argv) {
  size_t cap = 1;
  for (int i = 0; argv[i]; ++i) cap += strlen(argv[i]) * 2 + 4;
  char *out = malloc(cap);
  if (!out) return NULL;
  char *p = out;
  for (int i = 0; argv[i]; ++i) {
    if (i) *p++ = ' ';
    const char *s = argv[i];
    bool quote = win_needs_quotes(s);
    if (quote) *p++ = '"';
    unsigned slashes = 0;
    for (;;) {
      char c = *s++;
      if (c == '\\') { ++slashes; continue; }
      if (c == '"') {
        for (unsigned j = 0; j < slashes * 2 + 1; ++j) *p++ = '\\';
        *p++ = '"';
        slashes = 0;
        continue;
      }
      if (!c) {
        for (unsigned j = 0; j < slashes * (quote ? 2 : 1); ++j) *p++ = '\\';
        break;
      }
      while (slashes--) *p++ = '\\';
      slashes = 0;
      *p++ = c;
    }
    if (quote) *p++ = '"';
  }
  *p = 0;
  return out;
}

typedef int32_t (__msabi *CreateProcessWithLogonWFn)(
    const char16_t *, const char16_t *, const char16_t *, uint32_t,
    const char16_t *, char16_t *, uint32_t, void *, const char16_t *,
    struct NtStartupInfo *, struct NtProcessInformation *);

static int windows_run_as_user(const char *user, const char *password, char **command) {
  if (!password) {
    fprintf(stderr, "sysperm: Windows exec requires -p PASSWORD\n");
    return 2;
  }
  void *advapi = cosmo_dlopen("advapi32.dll", RTLD_LAZY);
  void *raw_create = advapi ? cosmo_dlsym(advapi, "CreateProcessWithLogonW") : NULL;
  CreateProcessWithLogonWFn create = (CreateProcessWithLogonWFn)raw_create;
  if (!create) {
    fprintf(stderr, "sysperm: Windows native logon API is unavailable\n");
    return 127;
  }
  char *cmd8 = win_command_line(command);
  if (!cmd8) return 2;
  char16_t *u16 = utf8to16(user, strlen(user), NULL);
  char16_t *p16 = utf8to16(password, strlen(password), NULL);
  char16_t *c16 = utf8to16(cmd8, strlen(cmd8), NULL);
  free(cmd8);
  if (!u16 || !p16 || !c16) { free(u16); free(p16); free(c16); return 2; }
  struct NtStartupInfo si = {0};
  struct NtProcessInformation pi = {0};
  si.cb = sizeof(si);
  si.dwFlags = 0x00000100u; /* STARTF_USESTDHANDLES */
  si.hStdInput = GetStdHandle(0xfffffff6u);
  si.hStdOutput = GetStdHandle(0xfffffff5u);
  si.hStdError = GetStdHandle(0xfffffff4u);
  if (verbose) print_command(command);
  int32_t ok = create(u16, u".", p16, 0, NULL, c16, 0x08000000u, NULL, NULL, &si, &pi);
  uint32_t create_error = ok ? 0 : GetLastError();
  if (verbose) fprintf(stderr, "sysperm: CreateProcessWithLogonW ok=%d process=%lld thread=%lld error=%u\n", ok, (long long)pi.hProcess, (long long)pi.hThread, create_error);
  free(u16); free(p16); free(c16);
  if (!ok) {
    uint32_t e = create_error;
    if (e == 1326) fprintf(stderr, "sysperm: exec failed: invalid username or password\n");
    else if (e == 1385) fprintf(stderr, "sysperm: exec failed: this account is not allowed to log on this way\n");
    else if (e == 5) fprintf(stderr, "sysperm: exec failed: access denied\n");
    else fprintf(stderr, "sysperm: exec failed: Windows error %u\n", e);
    return e > 255 ? 1 : (int)e;
  }
  if (verbose) fprintf(stderr, "sysperm: closing child thread handle\n");
  CloseHandle(pi.hThread);
  if (verbose) fprintf(stderr, "sysperm: waiting for child process\n");
  if (WaitForSingleObject(pi.hProcess, 0xffffffffu) == 0xffffffffu) {
    CloseHandle(pi.hProcess);
    fprintf(stderr, "sysperm: exec failed while waiting for child process\n");
    return 1;
  }
  if (verbose) fprintf(stderr, "sysperm: child process signaled\n");
  uint32_t code = 1;
  if (!GetExitCodeProcess(pi.hProcess, &code)) code = 1;
  if (verbose) fprintf(stderr, "sysperm: child exit code %u\n", code);
  CloseHandle(pi.hProcess);
  return code > 255 ? 1 : (int)code;
}

static int run_as_user(Os os, const char *user, const char *password, char **command) {
  if (!command[0]) return 2;
  if (os == OS_WINDOWS) return windows_run_as_user(user, password, command);
  struct passwd *pw = getpwnam(user);
  uid_t uid;
  gid_t gid;
  const char *name = user;
  if (pw) {
    uid = pw->pw_uid;
    gid = pw->pw_gid;
    name = pw->pw_name;
  } else if (os == OS_MACOS) {
    char node[512], out[256];
    snprintf(node, sizeof(node), "/Users/%s", user);
    char *uidav[] = {"dscl", ".", "-read", node, "UniqueID", NULL};
    if (spawn_capture(uidav, out, sizeof(out))) { fprintf(stderr, "sysperm: local user %s was not found\n", user); return 2; }
    char *p = strrchr(out, ' '); if (!p) return 2; uid = (uid_t)strtoul(p + 1, NULL, 10);
    char *gidav[] = {"dscl", ".", "-read", node, "PrimaryGroupID", NULL};
    if (spawn_capture(gidav, out, sizeof(out))) return 2;
    p = strrchr(out, ' '); if (!p) return 2; gid = (gid_t)strtoul(p + 1, NULL, 10);
  } else { fprintf(stderr, "sysperm: local user %s was not found\n", user); return 2; }
  if (initgroups(name, gid)) { perror("sysperm: initgroups"); return 1; }
  if (setgid(gid)) { perror("sysperm: setgid"); return 1; }
  if (setuid(uid)) { perror("sysperm: setuid"); return 1; }
  execvp(command[0], command);
  fprintf(stderr, "sysperm: cannot exec %s: %s\n", command[0], strerror(errno));
  return 127;
}

static int ensure_perm(Os os, const PermSpec *p) {
  for (int i = 0; i < p->expr_count; ++i) {
    const char *e = p->exprs[i];
    int rc = 0;
    if (!is_named_acl(e)) {
      if (os == OS_WINDOWS) {
        fprintf(stderr, "sysperm: Windows standard u/g/o chmod expressions are not meaningful; use named ACL expressions\n");
        return 2;
      }
      rc = p->recursive ? runv(false, "chmod", "-R", e, p->path, NULL)
                        : runv(false, "chmod", e, p->path, NULL);
    } else if (os == OS_LINUX || os == OS_MACOS) {
      rc = acl_walk(os, p->path, e, p->recursive);
    } else if (os == OS_WINDOWS) {
      rc = windows_acl_apply_one(p->path, e, p->recursive);
    } else rc = 2;
    if (rc) return tool_error(os, is_named_acl(e) ? "ACL update" : "permission update", rc);
  }
  if (os == OS_LINUX && p->setgid_dirs) {
    int rc = setgid_walk(p->path, p->recursive);
    if (rc) { fprintf(stderr, "sysperm: directory setgid update failed: %s\n", strerror(rc)); return rc; }
  }
  return 0;
}

static void usage(FILE *f) {
  fprintf(f,
    "sysperm - cross-platform users, groups and filesystem permissions\n\n"
    "Usage:\n"
    "  sysperm user NAME [-g GROUP,...] [-pg GROUP] [-p TEXT] [--home PATH] [--shell PATH] [--uid N] [--absent]\n"
    "  sysperm group NAME [--absent] [--gid N]\n"
    "  sysperm perm PATH EXPR... [--no-recursive] [--no-setgid]\n"
    "  sysperm exec USER [-p PASSWORD] -- COMMAND [ARG...]\n"
    "  sysperm os\n\n"
    "Global options:\n"
    "  -v, --verbose                 show native commands and their output\n\n"
    "Permission expressions:\n"
    "  u+rwx g-w o=rx              standard chmod mode (Unix)\n"
    "  user:alice=rwx              named user ACL\n"
    "  group:developers=rwX        named group ACL\n"
    "  user:alice+rw               add/grant named ACL rights\n"
    "  user:alice-                 remove named ACL entry on Linux\n\n"
    "Defaults: recursive permission changes; Linux directory setgid; a newly\n"
    "created user gets a same-name primary group and an empty password by default;\n"
    "the first -g group is primary unless -pg overrides it. Existing users keep\n"
    "unspecified attributes unchanged. Default shell: /bin/sh Linux, /bin/zsh macOS.\n");
}

static int add_groups_csv(UserSpec *u, const char *csv) {
  const char *p = csv;
  while (*p) {
    const char *comma = strchr(p, ',');
    size_t n = comma ? (size_t)(comma - p) : strlen(p);
    if (!n || u->group_count >= MAX_GROUPS) return 2;
    char *g = malloc(n + 1);
    if (!g) return 2;
    memcpy(g, p, n);
    g[n] = 0;
    u->groups[u->group_count++] = g;
    if (!comma) break;
    p = comma + 1;
  }
  return 0;
}

static const char *need_arg(int argc, char **argv, int *i, const char *opt) {
  if (*i + 1 >= argc) { fprintf(stderr, "sysperm: %s needs a value\n", opt); exit(2); }
  return argv[++*i];
}

int main(int argc, char **argv) {
  if (argc < 2) { usage(stderr); return 2; }
  int first = 1;
  while (first < argc && (!strcmp(argv[first], "-v") || !strcmp(argv[first], "--verbose"))) {
    verbose = true;
    ++first;
  }
  if (first >= argc) { usage(stderr); return 2; }
  if (first != 1) {
    for (int i = first; i < argc; ++i) argv[i - first + 1] = argv[i];
    argc -= first - 1;
    argv[argc] = NULL;
  }
  Os os = host_os();
  if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) { usage(stdout); return 0; }
  if (!strcmp(argv[1], "os")) { puts(os_name(os)); return os == OS_OTHER ? 2 : 0; }
  if (os == OS_OTHER) { fprintf(stderr, "sysperm: unsupported operating system\n"); return 2; }

  if (!strcmp(argv[1], "group")) {
    if (argc < 3) { usage(stderr); return 2; }
    GroupSpec g = {.name = argv[2]};
    for (int i = 3; i < argc; ++i) {
      if (!strcmp(argv[i], "--absent")) g.absent = true;
      else if (!strcmp(argv[i], "--gid")) g.gid = need_arg(argc, argv, &i, "--gid");
      else { fprintf(stderr, "sysperm: unknown option %s\n", argv[i]); return 2; }
    }
    return ensure_group(os, &g);
  }

  if (!strcmp(argv[1], "user")) {
    if (argc < 3) { usage(stderr); return 2; }
    UserSpec u = {.name = argv[2], .private_group = true};
    for (int i = 3; i < argc; ++i) {
      if (!strcmp(argv[i], "--absent")) u.absent = true;
      else if (!strcmp(argv[i], "--home")) u.home = need_arg(argc, argv, &i, "--home");
      else if (!strcmp(argv[i], "--shell")) u.shell = need_arg(argc, argv, &i, "--shell");
      else if (!strcmp(argv[i], "--uid")) u.uid = need_arg(argc, argv, &i, "--uid");
      else if (!strcmp(argv[i], "--gid")) u.gid = need_arg(argc, argv, &i, "--gid");
      else if (!strcmp(argv[i], "--password") || !strcmp(argv[i], "-p")) u.password = need_arg(argc, argv, &i, argv[i]);
      else if (!strcmp(argv[i], "--groups") || !strcmp(argv[i], "--group") || !strcmp(argv[i], "-g")) {
        const char *csv = need_arg(argc, argv, &i, argv[i]);
        if (add_groups_csv(&u, csv)) { fprintf(stderr, "sysperm: invalid or too many groups\n"); return 2; }
      } else if (!strcmp(argv[i], "--primary-group") || !strcmp(argv[i], "-pg")) {
        u.primary_group = need_arg(argc, argv, &i, argv[i]);
      } else if (!strcmp(argv[i], "--no-private-group")) u.private_group = false;
      else { fprintf(stderr, "sysperm: unknown option %s\n", argv[i]); return 2; }
    }
    return ensure_user(os, &u);
  }

  if (!strcmp(argv[1], "exec")) {
    if (argc < 5) { usage(stderr); return 2; }
    const char *password = NULL;
    int i = 3;
    while (i < argc && strcmp(argv[i], "--")) {
      if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--password")) password = need_arg(argc, argv, &i, argv[i]);
      else { fprintf(stderr, "sysperm: unknown exec option %s\n", argv[i]); return 2; }
      ++i;
    }
    if (i >= argc - 1 || strcmp(argv[i], "--")) { usage(stderr); return 2; }
    return run_as_user(os, argv[2], password, &argv[i + 1]);
  }

  if (!strcmp(argv[1], "perm")) {
    if (argc < 4) { usage(stderr); return 2; }
    const char *exprs[MAX_ARGS]; int ec = 0;
    PermSpec p = {.recursive = true, .setgid_dirs = true, .path = argv[2]};
    for (int i = 3; i < argc; ++i) {
      if (!strcmp(argv[i], "--no-recursive")) p.recursive = false;
      else if (!strcmp(argv[i], "--no-setgid")) p.setgid_dirs = false;
      else if (ec < MAX_ARGS) exprs[ec++] = argv[i];
    }
    p.exprs = exprs; p.expr_count = ec;
    return ensure_perm(os, &p);
  }

  fprintf(stderr, "sysperm: unknown command %s\n", argv[1]);
  usage(stderr);
  return 2;
}
