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
#include "utils.c"
#include "hotspot.c"
#include "openj9.c"

char tmp_path[MAX_PATH - 100];

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