#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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

extern char **environ;

#define MAX_ARGS 64
#define MAX_GROUPS 32

typedef enum { OS_LINUX, OS_MACOS, OS_WINDOWS, OS_OTHER } Os;

typedef struct {
  const char *name;
  bool absent;
  const char *home;
  const char *shell;
  const char *uid;
  const char *gid;
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

static int spawn_wait(char *const argv[], bool quiet) {
  pid_t pid;
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  int nullfd = -1;
  if (quiet) {
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
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  return 128;
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
    if (os == OS_LINUX) return runv(false, "groupdel", g->name, NULL);
    if (os == OS_MACOS) return runv(false, "dseditgroup", "-o", "delete", g->name, NULL);
    if (os == OS_WINDOWS) return runv(false, "net.exe", "localgroup", g->name, "/delete", NULL);
    return 2;
  }

  if (!exists) {
    if (os == OS_LINUX) {
      if (g->gid) return runv(false, "groupadd", "-g", g->gid, g->name, NULL);
      return runv(false, "groupadd", g->name, NULL);
    }
    if (os == OS_MACOS) {
      if (g->gid) return runv(false, "dseditgroup", "-o", "create", "-i", g->gid, g->name, NULL);
      return runv(false, "dseditgroup", "-o", "create", g->name, NULL);
    }
    if (os == OS_WINDOWS) return runv(false, "net.exe", "localgroup", g->name, "/add", NULL);
    return 2;
  }

  if (g->gid) {
    if (os == OS_LINUX) return runv(false, "groupmod", "-g", g->gid, g->name, NULL);
    if (os == OS_MACOS) {
      char node[512]; snprintf(node, sizeof(node), "/Groups/%s", g->name);
      return runv(false, "dscl", ".", "-create", node, "PrimaryGroupID", g->gid, NULL);
    }
  }
  return 0;
}

static int add_membership(Os os, const char *user, const char *group) {
  GroupSpec g = {.name = group};
  int rc = ensure_group(os, &g);
  if (rc) return rc;
  if (os == OS_LINUX) return runv(false, "usermod", "-a", "-G", group, user, NULL);
  if (os == OS_MACOS) return runv(false, "dseditgroup", "-o", "edit", "-a", user, "-t", "user", group, NULL);
  if (os == OS_WINDOWS) return runv(false, "net.exe", "localgroup", group, user, "/add", NULL);
  return 2;
}

static int ensure_user(Os os, const UserSpec *u) {
  bool exists = user_exists(os, u->name);
  if (u->absent) {
    if (!exists) return 0;
    if (os == OS_LINUX) return runv(false, "userdel", u->name, NULL);
    if (os == OS_MACOS) {
      char node[512]; snprintf(node, sizeof(node), "/Users/%s", u->name);
      return runv(false, "dscl", ".", "-delete", node, NULL);
    }
    if (os == OS_WINDOWS) return runv(false, "net.exe", "user", u->name, "/delete", NULL);
    return 2;
  }

  if (!exists && u->private_group) {
    GroupSpec pg = {.name = u->name};
    int rc = ensure_group(os, &pg);
    if (rc) return rc;
  }

  if (!exists) {
    int rc = 0;
    if (os == OS_LINUX) {
      char *av[MAX_ARGS]; int n = 0;
      av[n++] = "useradd";
      if (u->private_group) { av[n++] = "-g"; av[n++] = (char *)u->name; }
      if (u->home) { av[n++] = "-d"; av[n++] = (char *)u->home; }
      if (u->shell) { av[n++] = "-s"; av[n++] = (char *)u->shell; }
      if (u->uid) { av[n++] = "-u"; av[n++] = (char *)u->uid; }
      if (u->gid) { av[n++] = "-g"; av[n++] = (char *)u->gid; }
      av[n++] = (char *)u->name; av[n] = NULL;
      rc = spawn_wait(av, false);
    } else if (os == OS_MACOS) {
      char *av[MAX_ARGS]; int n = 0;
      av[n++] = "sysadminctl"; av[n++] = "-addUser"; av[n++] = (char *)u->name;
      av[n++] = "-password"; av[n++] = "-";
      if (u->home) { av[n++] = "-home"; av[n++] = (char *)u->home; }
      if (u->uid) { av[n++] = "-UID"; av[n++] = (char *)u->uid; }
      if (u->shell) { av[n++] = "-shell"; av[n++] = (char *)u->shell; }
      av[n] = NULL;
      rc = spawn_wait(av, false);
      if (!rc && u->gid) {
        char node[512]; snprintf(node, sizeof(node), "/Users/%s", u->name);
        rc = runv(false, "dscl", ".", "-create", node, "PrimaryGroupID", u->gid, NULL);
      }
    } else if (os == OS_WINDOWS) {
      rc = runv(false, "net.exe", "user", u->name, "/add", NULL);
    } else rc = 2;
    if (rc) return rc;
  } else {
    int rc = 0;
    if (os == OS_LINUX) {
      if (u->home && (rc = runv(false, "usermod", "-d", u->home, u->name, NULL))) return rc;
      if (u->shell && (rc = runv(false, "usermod", "-s", u->shell, u->name, NULL))) return rc;
      if (u->uid && (rc = runv(false, "usermod", "-u", u->uid, u->name, NULL))) return rc;
      if (u->gid && (rc = runv(false, "usermod", "-g", u->gid, u->name, NULL))) return rc;
    } else if (os == OS_MACOS) {
      char node[512]; snprintf(node, sizeof(node), "/Users/%s", u->name);
      if (u->home && (rc = runv(false, "dscl", ".", "-create", node, "NFSHomeDirectory", u->home, NULL))) return rc;
      if (u->shell && (rc = runv(false, "dscl", ".", "-create", node, "UserShell", u->shell, NULL))) return rc;
      if (u->uid && (rc = runv(false, "dscl", ".", "-create", node, "UniqueID", u->uid, NULL))) return rc;
      if (u->gid && (rc = runv(false, "dscl", ".", "-create", node, "PrimaryGroupID", u->gid, NULL))) return rc;
    }
  }

  for (int i = 0; i < u->group_count; ++i) {
    int rc = add_membership(os, u->name, u->groups[i]);
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
    if (rc) return rc;
  }
  if (os == OS_LINUX && p->setgid_dirs) return setgid_walk(p->path, p->recursive);
  return 0;
}

static void usage(FILE *f) {
  fprintf(f,
    "sysperm - cross-platform users, groups and filesystem permissions\n\n"
    "Usage:\n"
    "  sysperm user NAME [--absent] [--group GROUP]... [--home PATH] [--shell PATH] [--uid N] [--gid N] [--no-private-group]\n"
    "  sysperm group NAME [--absent] [--gid N]\n"
    "  sysperm perm PATH EXPR... [--no-recursive] [--no-setgid]\n"
    "  sysperm os\n\n"
    "Permission expressions:\n"
    "  u+rwx g-w o=rx              standard chmod mode (Unix)\n"
    "  user:alice=rwx              named user ACL\n"
    "  group:developers=rwX        named group ACL\n"
    "  user:alice+rw               add/grant named ACL rights\n"
    "  user:alice-                 remove named ACL entry on Linux\n\n"
    "Defaults: recursive permission changes; Linux directory setgid; a newly\n"
    "created user gets a same-name group unless --no-private-group is used.\n");
}

static const char *need_arg(int argc, char **argv, int *i, const char *opt) {
  if (*i + 1 >= argc) { fprintf(stderr, "sysperm: %s needs a value\n", opt); exit(2); }
  return argv[++*i];
}

int main(int argc, char **argv) {
  if (argc < 2) { usage(stderr); return 2; }
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
      else if (!strcmp(argv[i], "--group")) {
        if (u.group_count >= MAX_GROUPS) { fprintf(stderr, "sysperm: too many groups\n"); return 2; }
        u.groups[u.group_count++] = need_arg(argc, argv, &i, "--group");
      } else if (!strcmp(argv[i], "--no-private-group")) u.private_group = false;
      else { fprintf(stderr, "sysperm: unknown option %s\n", argv[i]); return 2; }
    }
    return ensure_user(os, &u);
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
