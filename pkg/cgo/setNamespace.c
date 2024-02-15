#define _GNU_SOURCE
#define __USE_GNU
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * 进入命名空间并执行命令
*/
__attribute__((constructor)) void enter_namespace(void) {
    char *mydocker_pid;
    mydocker_pid = getenv("mydocker_pid");
    if (!mydocker_pid) {
        return;
    }
    char *mydocker_cmd;
    mydocker_cmd = getenv("mydocker_cmd");
    if (!mydocker_cmd) {
        return;
    }
    unsetenv("mydocker_pid");
    unsetenv("mydocker_cmd");
    int i;
    char nspath[1024];
    char *namespaces[] = { "ipc", "uts", "net", "pid", "mnt" };
    for (i=0; i<sizeof(namespaces)/sizeof(namespaces[0]); i++) {
        sprintf(nspath, "/proc/%s/ns/%s", mydocker_pid, namespaces[i]);
        int fd = open(nspath, O_RDONLY);
        if (setns(fd, 0) == -1) {
            fprintf(stderr, "setns on %s namespace failed: %s\n", namespaces[i], strerror(errno));
            close(fd);
            break;
        } 
        close(fd);
    }
    fprintf(stdout, "enter pid %s's namespace and to run %s\n",mydocker_pid,mydocker_cmd);
    int res = system(mydocker_cmd);
    exit(0);
    return;
}