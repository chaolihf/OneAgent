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

#define MAX_PATH 1024

char tmp_path[MAX_PATH - 100];

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


int is_openj9_process(int pid) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/.com_ibm_tools_attach/%d/attachInfo", tmp_path, pid);

    struct stat stats;
    return stat(path, &stats) == 0;
}

// Check if remote JVM has already opened socket for Dynamic Attach
static int check_socket(int pid) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/.java_pid%d", tmp_path, pid);

    struct stat stats;
    return stat(path, &stats) == 0 && S_ISSOCK(stats.st_mode) ? 0 : -1;
}

// Check if a file is owned by current user
static uid_t get_file_owner(const char* path) {
    struct stat stats;
    return stat(path, &stats) == 0 ? stats.st_uid : (uid_t)-1;
}

// Force remote JVM to start Attach listener.
// HotSpot will start Attach listener in response to SIGQUIT if it sees .attach_pid file
static int start_attach_mechanism(int pid, int nspid,int mnt_changed) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "/proc/%d/cwd/.attach_pid%d", mnt_changed > 0 ? nspid : pid, nspid);

    int fd = creat(path, 0660);
    if (fd == -1 || (close(fd) == 0 && get_file_owner(path) != geteuid())) {
        // Some mounted filesystems may change the ownership of the file.
        // JVM will not trust such file, so it's better to remove it and try a different path
        unlink(path);

        // Failed to create attach trigger in current directory. Retry in /tmp
        snprintf(path, sizeof(path), "%s/.attach_pid%d", tmp_path, nspid);
        fd = creat(path, 0660);
        if (fd == -1) {
            return -1;
        }
        close(fd);
    }

    // We have to still use the host namespace pid here for the kill() call
    kill(pid, SIGQUIT);

    // Start with 20 ms sleep and increment delay each iteration. Total timeout is 6000 ms
    struct timespec ts = {0, 20000000};
    int result;
    do {
        nanosleep(&ts, NULL);
        result = check_socket(nspid);
    } while (result != 0 && (ts.tv_nsec += 20000000) < 500000000);

    unlink(path);
    return result;
}

// Connect to UNIX domain socket created by JVM for Dynamic Attach
static int connect_socket(int pid) {
    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        return -1;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;

    int bytes = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/.java_pid%d", tmp_path, pid);
    if (bytes >= sizeof(addr.sun_path)) {
        addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(fd);
        return -1;
    }
    return fd;
}

// Send command with arguments to socket
static int write_command(int fd, char * command, char* arguments) {
    char buf[8192];
    const char* const limit = buf + sizeof(buf);

    // Protocol version
    char* p = stpncpy(buf, "1", sizeof(buf)) + 1;

    p = stpncpy(p, command, limit - p) + 1;
    char * space=" ";
    p = stpncpy(p, space, limit - p) + 1;
    p = stpncpy(p, arguments, limit - p) + 1;
    for (;p < limit; ) {
        *p++ = 0;
    }

    const char* q = p < limit ? p : limit;
    for (p = buf; p < q; ) {
        ssize_t bytes = write(fd, p, q - p);
        if (bytes <= 0) {
            return -1;
        }
        p += (size_t)bytes;
    }
    return 0;
}

// Mirror response from remote JVM to stdout
static int read_response(int fd, char * command, char* arguments, int print_output) {
    char buf[8192];
    ssize_t bytes = read(fd, buf, sizeof(buf) - 1);
    if (bytes == 0) {
        fprintf(stderr, "Unexpected EOF reading response\n");
        return 1;
    } else if (bytes < 0) {
        perror("Error reading response");
        return 1;
    }

    // First line of response is the command result code
    buf[bytes] = 0;
    int result = atoi(buf);

    // Special treatment of 'load' command
    if (result == 0 && strcmp(command, "load") == 0) {
        size_t total = bytes;
        while (total < sizeof(buf) - 1 && (bytes = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0) {
            total += (size_t)bytes;
        }
        bytes = total;

        // The second line is the result of 'load' command; since JDK 9 it starts from "return code: "
        buf[bytes] = 0;
        result = atoi(strncmp(buf + 2, "return code: ", 13) == 0 ? buf + 15 : buf + 2);
    }

    if (print_output) {
        // Mirror JVM response to stdout
        printf("JVM response code = ");
        do {
            fwrite(buf, 1, bytes, stdout);
            bytes = read(fd, buf, sizeof(buf));
        } while (bytes > 0);
        printf("\n");
    }

    return result;
}

int jattach_hotspot(int pid, int nspid, char * command, char* arguments, int print_output,int mnt_changed) {
    if (check_socket(nspid) != 0 && start_attach_mechanism(pid, nspid,mnt_changed) != 0) {
        perror("Could not start attach mechanism");
        return 1;
    }

    int fd = connect_socket(nspid);
    if (fd == -1) {
        perror("Could not connect to socket");
        return 1;
    }

    if (print_output) {
        printf("Connected to remote JVM\n");
    }

    if (write_command(fd, command, arguments) != 0) {
        perror("Error writing to socket");
        close(fd);
        return 1;
    }

    int result = read_response(fd, command, arguments, print_output);
    close(fd);

    return result;
}


int jattach(int pid, char * command, char* arguments, int print_output) {
    printf("jattach %s %s\n",command,arguments);
    uid_t my_uid = geteuid();
    gid_t my_gid = getegid();
    uid_t target_uid = my_uid;
    gid_t target_gid = my_gid;
    int nspid;
    if (get_process_info(pid, &target_uid, &target_gid, &nspid) < 0) {
        fprintf(stderr, "Process %d not found\n", pid);
        return 1;
    }
    printf("get process info %d and namespace pid %d\n",pid,nspid);
    // Container support: switch to the target namespaces.
    // Network and IPC namespaces are essential for OpenJ9 connection.
    enter_ns(pid, "net");
    enter_ns(pid, "ipc");
    int mnt_changed = enter_ns(pid, "mnt");

    // In HotSpot, dynamic attach is allowed only for the clients with the same euid/egid.
    // If we are running under root, switch to the required euid/egid automatically.
    if ((my_gid != target_gid && setegid(target_gid) != 0) ||
        (my_uid != target_uid && seteuid(target_uid) != 0)) {
        perror("Failed to change credentials to match the target process");
        return 1;
    }

    get_tmp_path(mnt_changed > 0 ? nspid : pid);
    // Make write() return EPIPE instead of abnormal process termination
    signal(SIGPIPE, SIG_IGN);
    if (is_openj9_process(nspid)) {
        //return jattach_openj9(pid, nspid, argc, argv, print_output);
    } else {
        return jattach_hotspot(pid, nspid, command, arguments, print_output,mnt_changed);
    }
    return 0;
}