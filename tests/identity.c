#include "libc/dce.h"
#include "third_party/musl/passwd.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int dump(const char *name) {
  struct passwd *p = getpwnam(name);
  if (!p) {
    fprintf(stderr, "getpwnam(%s): %s\n", name, strerror(errno));
    return 2;
  }
  int n = 0;
  getgrouplist(p->pw_name, p->pw_gid, NULL, &n);
  gid_t *groups = calloc(n ? n : 1, sizeof(*groups));
  if (!groups) return 3;
  if (getgrouplist(p->pw_name, p->pw_gid, groups, &n) < 0) return 4;
  printf("name=%s uid=%u gid=%u home=%s shell=%s groups=", p->pw_name,
         (unsigned)p->pw_uid, (unsigned)p->pw_gid, p->pw_dir, p->pw_shell);
  for (int i = 0; i < n; ++i) printf("%s%u", i ? "," : "", (unsigned)groups[i]);
  putchar('\n');
  free(groups);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) return 64;
  return dump(argv[1]);
}
