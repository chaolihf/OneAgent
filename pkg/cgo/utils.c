#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <errno.h>
#include "common.h"
extern char tmp_path[MAX_PATH - 100];


// The first line of /proc/pid/sched looks like
// java (1234, #threads: 12)
// where 1234 is the host PID (before Linux 4.1)
int sched_get_host_pid(const char* path) {
    static char* line = NULL;
    size_t size;
    int result = -1;

    FILE* sched_file = fopen(path, "r");
    if (sched_file != NULL) {
        if (getline(&line, &size, sched_file) != -1) {
            char* c = strrchr(line, '(');
            if (c != NULL) {
                result = atoi(c + 1);
            }
        }
        fclose(sched_file);
    }

    return result;
}


// Linux kernels < 4.1 do not export NStgid field in /proc/pid/status.
// Fortunately, /proc/pid/sched in a container exposes a host PID,
// so the idea is to scan all container PIDs to find which one matches the host PID.
int alt_lookup_nspid(int pid) {
    char path[300];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);

    // Don't bother looking for container PID if we are already in the same PID namespace
    struct stat oldns_stat, newns_stat;
    if (stat("/proc/self/ns/pid", &oldns_stat) == 0 && stat(path, &newns_stat) == 0) {
        if (oldns_stat.st_ino == newns_stat.st_ino) {
            return pid;
        }
    }

    // Otherwise browse all PIDs in the namespace of the target process
    // trying to find which one corresponds to the host PID
    snprintf(path, sizeof(path), "/proc/%d/root/proc", pid);
    DIR* dir = opendir(path);
    if (dir != NULL) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] >= '1' && entry->d_name[0] <= '9') {
                // Check if /proc/<container-pid>/sched points back to <host-pid>
                snprintf(path, sizeof(path), "/proc/%d/root/proc/%s/sched", pid, entry->d_name);
                if (sched_get_host_pid(path) == pid) {
                    pid = atoi(entry->d_name);
                    break;
                }
            }
        }
        closedir(dir);
    }

    return pid;
}


int get_process_info(int pid, uid_t* uid, gid_t* gid, int* nspid) {
    // Parse /proc/pid/status to find process credentials
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* status_file = fopen(path, "r");
    if (status_file == NULL) {
        return -1;
    }

    char* line = NULL;
    size_t size;
    int nspid_found = 0;

    while (getline(&line, &size, status_file) != -1) {
        if (strncmp(line, "Uid:", 4) == 0 && strtok(line + 4, "\t ") != NULL) {
            // Get the effective UID, which is the second value in the line
            *uid = (uid_t)atoi(strtok(NULL, "\t "));
        } else if (strncmp(line, "Gid:", 4) == 0 && strtok(line + 4, "\t ") != NULL) {
            // Get the effective GID, which is the second value in the line
            *gid = (gid_t)atoi(strtok(NULL, "\t "));
        } else if (strncmp(line, "NStgid:", 7) == 0) {
            // PID namespaces can be nested; the last one is the innermost one
            char* s;
            for (s = strtok(line + 7, "\t "); s != NULL; s = strtok(NULL, "\t ")) {
                *nspid = atoi(s);
            }
            nspid_found = 1;
        }
    }

    free(line);
    fclose(status_file);

    if (!nspid_found) {
        *nspid = alt_lookup_nspid(pid);
    }

    return 0;
}

int get_tmp_path_r(int pid, char* buf, size_t bufsize) {
    if (snprintf(buf, bufsize, "/proc/%d/root/tmp", pid) >= bufsize) {
        return -1;
    }

    // Check if the remote /tmp can be accessed via /proc/[pid]/root
    struct stat stats;
    return stat(buf, &stats);
}

// Called just once to fill in tmp_path buffer
void get_tmp_path(int pid) {
    // Try user-provided alternative path first
    const char* jattach_path = getenv("JATTACH_PATH");
    if (jattach_path != NULL && strlen(jattach_path) < sizeof(tmp_path)) {
        strcpy(tmp_path, jattach_path);
        return;
    }

    if (get_tmp_path_r(pid, tmp_path, sizeof(tmp_path)) != 0) {
        strcpy(tmp_path, "/tmp");
    }
}

int enter_ns(int pid, const char* type) {
#ifdef __NR_setns
    char path[64], selfpath[64];
    snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, type);
    snprintf(selfpath, sizeof(selfpath), "/proc/self/ns/%s", type);

    struct stat oldns_stat, newns_stat;
    if (stat(selfpath, &oldns_stat) == 0 && stat(path, &newns_stat) == 0) {
        // Don't try to call setns() if we're in the same namespace already
        if (oldns_stat.st_ino != newns_stat.st_ino) {
            int newns = open(path, O_RDONLY);
            if (newns < 0) {
                return -1;
            }

            // Some ancient Linux distributions do not have setns() function
            int result = syscall(__NR_setns, newns, 0);
            close(newns);
            return result < 0 ? -1 : 1;
        }
    }
#endif // __NR_setns

    return 0;
}
