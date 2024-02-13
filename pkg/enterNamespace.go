package collector

/*
#include "cgo/setNamespace.c"
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
		pid, err := strconv.Atoi(commands["p1"])
		if err != nil {
			logger.Log(err.Error())
			return
		}
		nsPid, err := strconv.Atoi(commands["p2"])
		if err != nil {
			logger.Log(err.Error())
			return
		}
		attachJava(nsPid, pid)
	}
}
