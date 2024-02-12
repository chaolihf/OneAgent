package collector

/*
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

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

*/
import "C"
import (
	"os"
	"strconv"
	"strings"
)

/*
在新命名空间执行命令程序
*/
func ExecuteCommandOnNewNamesapce() {
	commands := make(map[string]string)
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "--") {
			leftIndex := strings.Index(arg, "=")
			if leftIndex != -1 {
				commands[arg[2:leftIndex]] = arg[leftIndex+1:]
			}
		}
	}
	command, isOk := commands["cmd"]
	if isOk {
		switch command {
		case "java":
			logger.Log(commands)
			executeJavaCommand(commands)
		}
		os.Exit(0)
	}
}

/*
注入Java程序
*/
func executeJavaCommand(commands map[string]string) {
	switch commands["p0"] {
	case "threaddump":
		pid, err := strconv.Atoi(commands["pid"])
		if err != nil {
			logger.Log(err.Error())
		} else {
			attachJava(pid)
		}

	}
}
