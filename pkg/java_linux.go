package collector

/*
#include "cgo/jattach.c"
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/chaolihf/gopsutil/process"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

// see https://github.com/frohoff/jdk8u-jdk/blob/master/src/share/classes/sun/tools/attach/HotSpotVirtualMachine.java https://github.com/jattach/jattach
// https://github.com/openjdk/jdk search HotSpotVirtualMachine.java , all command
const ATTACH_ERROR_BADVERSION = 101
const JNI_ENOMEM = -4
const ATTACH_ERROR_BADJAR = 100
const ATTACH_ERROR_NOTONCP = 101
const ATTACH_ERROR_STARTFAIL = 102

/*
定义Java类
*/
type JavaCollector struct {
	enable bool
}

func init() {
	registerCollector("java", true, newJavaCollector)
}

/*
初始化收集器
*/
func newJavaCollector(g_logger log.Logger) (Collector, error) {
	return &JavaCollector{enable: true}, nil
}

func (javaCollector *JavaCollector) Update(ch chan<- prometheus.Metric) error {
	ScanAllProcess()
	return nil
}

func ScanAllProcess() error {
	allProcess, err := process.Processes()
	if err != nil {
		logger.Log(err.Error())
		return err
	}
	uid := os.Getuid()
	gid := os.Getgid()
	for _, process := range allProcess {
		name, err := process.Name()
		if err != nil {
			logger.Log(err.Error())
			return err
		}
		if name == "java" {
			pid := int(process.Pid)
			nsPid, err := process.GetNamespacePid()
			if err != nil {
				logger.Log(err.Error())
				continue
			}
			if nsPid > 0 && pid != int(nsPid) {
				err := callJavaAttach(pid, "threaddump", "")
				if err != nil {
					logger.Log(err.Error())
					continue
				}
				// os.Setenv("mydocker_pid", strconv.Itoa(int(pid)))
				// os.Setenv("mydocker_cmd", fmt.Sprintf("/OneAgent --cmd=java --p0=threaddump --p1=%d --p2=%d", pid, nsPid))
				// //os.Setenv("mydocker_cmd", "ls -l")
				// cmd := exec.Command("/proc/self/exe")
				// cmd.Stdin = os.Stdin
				// cmd.Stdout = os.Stdout
				// cmd.Stderr = os.Stderr

				// if err := cmd.Run(); err != nil {
				// 	logger.Log(err.Error())
				// }
			} else {
				uids, err := process.Uids()
				if err != nil {
					logger.Log(err.Error())
					return err
				}
				gids, err := process.Gids()
				if err != nil {
					logger.Log(err.Error())
					return err
				}
				newUid := int(uids[0])
				newGid := int(gids[0])
				if newGid != gid {
					syscall.Setgid(newUid)
				}
				if newUid != uid {
					syscall.Setuid(newUid)
				}
				attachJava(pid, pid)
				if newGid != gid {
					syscall.Setgid(gid)
				}
				if newUid != uid {
					syscall.Setuid(uid)
				}
			}
		}
	}
	return nil
}

func callJavaAttach(pid int, command string, params string) error {
	var byteArray *C.uchar
	var length C.size_t
	result := C.jattach(&byteArray, &length, C.int(pid), C.CString(command), C.CString(params), C.int(1))
	if result == 0 {
		goByteArray := C.GoBytes(unsafe.Pointer(byteArray), C.int(length))
		logger.Log("INFO", goByteArray)
		C.free(unsafe.Pointer(byteArray))
	}
	return nil
}

/*
pid为命名空间内对应的进程id，hostPid为宿主机的进程id
*/
func attachJava(pid int, hostPid int) {
	logger.Log("Info", fmt.Sprintf("Attach Java %d\n", pid))
	socketFileName := fmt.Sprintf("/proc/%d/root/tmp/.java_pid%d", pid, pid)
	if !FileExist(socketFileName) {
		// Force remote JVM to start Attach listener.
		// HotSpot will start Attach listener in response to SIGQUIT if it sees .attach_pid file
		// create attach file
		attachFile, err := createAttachFile(pid)
		if err != nil {
			logger.Log("fail to create attach file, %v\n", err)
			return
		}
		defer os.Remove(attachFile.Name())
		logger.Log("INFO", fmt.Sprintf("start to kill process %d\n", hostPid))
		err = syscall.Kill(hostPid, syscall.SIGQUIT)
		if err != nil {
			logger.Log("fail to send quit, %v\n", err)
		}
		delayStep := 100
		attachTimeout := 300000
		timeSpend := 0
		delay := 0
		for timeSpend <= attachTimeout && !FileExist(socketFileName) {
			delay += delayStep
			time.Sleep(time.Millisecond * time.Duration(delay))
			timeSpend += delay
			if timeSpend > attachTimeout/2 && !FileExist(socketFileName) {
				logger.Log("INFO", fmt.Sprintf("start to kill process %d again!\n", hostPid))
				syscall.Kill(int(hostPid), syscall.SIGQUIT)
			}
		}
		if !FileExist(socketFileName) {
			logger.Log("INFO", fmt.Sprintf("Unable to open socket file %s: "+
				"target process %d doesn't respond within %dms "+
				"or HotSpot VM not loaded\n", socketFileName, pid,
				timeSpend))
			return
		}
	}

	conn, err := net.Dial("unix", socketFileName)
	if err != nil {
		logger.Log("INFO", fmt.Sprintf("fail to connect socketpath: %s, %v\n", socketFileName, err))
	}
	defer conn.Close()
	//cmds := agentFilePath + "=" + options
	cmds := "threaddump"
	err = loadAgentLibrary(conn, "instrument", false, cmds)
	if err != nil {
		logger.Log(err)
	}
	logger.Log("load success!")
}

func createAttachFile(pid int) (*os.File, error) {
	fn := fmt.Sprintf(".attach_pid%d", pid)
	path := fmt.Sprintf("/proc/%d/cwd/%s", pid, fn)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		file, err = os.OpenFile("/tmp/"+fn, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return nil, err
		} else {
			logger.Log("Info", fmt.Sprintf("create attach pid file success2 %s!\n", path))
		}
	} else {
		logger.Log("Info", fmt.Sprintf("create attach pid file success %s!\n", path))
	}
	return file, nil

}

func FileExist(path string) bool {
	fs, err := os.Lstat(path)
	if err == nil {
		logger.Log("file exist success: %s, fs: %v\n", path, fs)
		return true
	}
	return !os.IsNotExist(err)
}

func loadAgentLibrary(conn net.Conn, agentLibrary string, isAbs bool, options string) error {
	args := make([]string, 3)
	args[0] = agentLibrary
	args[1] = strconv.FormatBool(isAbs)
	args[2] = options
	err := execute(conn, "threaddump", args)
	if err == nil {
		bytes, err := io.ReadAll(conn)
		if err != nil {
			return err
		}
		responseMessage := string(bytes)
		msgPrefix := "return code: "
		if responseMessage == "" {
			return errors.New("target VM did not respond")
		} else if strings.HasPrefix(responseMessage, msgPrefix) {
			retCode, err := strconv.Atoi(strings.TrimSpace(responseMessage[len(msgPrefix):]))
			if err != nil {
				return errors.New(fmt.Sprintf("retCode not a valid int, but: %s, err: %v", responseMessage[len(msgPrefix):], err))
			}
			if retCode != 0 {
				switch retCode {
				case JNI_ENOMEM:
					return fmt.Errorf("insuffient memory")
				case ATTACH_ERROR_BADJAR:
					return fmt.Errorf("agent JAR not found or no Agent-Class attribute")
				case ATTACH_ERROR_NOTONCP:
					return fmt.Errorf("unable to add JAR file to system class path")
				case ATTACH_ERROR_STARTFAIL:
					return fmt.Errorf("agent JAR loaded but agent failed to initialize")
				default:
					return fmt.Errorf("failed to load agent - unknown reason: %d", retCode)
				}
			}
			return nil
		} else {
			return errors.New(fmt.Sprintf("Agent load failed, response: %s", responseMessage))
		}
	} else {
		return err
	}
}

func execute(conn net.Conn, cmd string, args []string) error {
	if len(args) > 3 {
		logger.Log("args length > 3")
	}

	err := writeString(conn, "1")
	if err != nil {
		goto complete
	}
	err = writeString(conn, cmd)
	if err != nil {
		goto complete
	}
	for i := 0; i < 3; i++ {
		if i < len(args) {
			err = writeString(conn, args[i])
		} else {
			err = writeString(conn, "")
		}
		if err != nil {
			goto complete
		}
	}

complete:
	completionStatus, err := readInt(conn)
	if err != nil {
		return err
	}
	if completionStatus != 0 {
		errorMessage, _ := readErrorMessage(conn)
		if completionStatus == ATTACH_ERROR_BADVERSION {
			return errors.New("Protocol mismatch with target VM")
		}
		if cmd == "threaddump" {
			return errors.New("Failed to load agent library:" + errorMessage)
		} else {
			if errorMessage == "" {
				errorMessage = "Command failed in target VM"
			}
			return errors.New(errorMessage)
		}
	} else {
		result, err := readErrorMessage(conn)
		if err != nil {
			return err
		} else {
			logger.Log(result)
		}
	}
	return nil
}

func writeString(conn net.Conn, str string) error {
	_, err := conn.Write([]byte(str))
	if err != nil {
		return err
	}
	_, err = conn.Write(make([]byte, 1))
	if err != nil {
		return err
	}
	return nil
}

func readInt(conn net.Conn) (int, error) {
	buf := make([]byte, 1)
	str := ""
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return -1, err
		}
		if n > 0 {
			if buf[0] == '\n' {
				break
			} else {
				str = str + string(buf)
			}
		} else {
			break
		}
	}
	if len(str) == 0 {
		return -1, errors.New("Premature EOF")
	}
	value, err := strconv.Atoi(str)
	if err != nil {
		return -1, errors.New(fmt.Sprintf("Non-numeric value found - int expected, but: %s\n", str))
	}
	return value, nil
}

func readErrorMessage(conn net.Conn) (string, error) {
	bytes, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

/*
0: not namespace
1,-1: change result
*/
func enterNamespace(pid int, nstype string) int {
	targetFile := fmt.Sprintf("/proc/%d/ns/%s", pid, nstype)
	selfFile := fmt.Sprintf("/proc/self/ns/%s", nstype)
	var statTargetFile syscall.Stat_t
	var statSelfFile syscall.Stat_t
	if err := syscall.Stat(targetFile, &statTargetFile); err != nil {
		return 0
	}
	if err := syscall.Stat(selfFile, &statSelfFile); err != nil {
		return 0
	} // Don't try to call setns() if we're in the same namespace already
	if statTargetFile.Ino != statSelfFile.Ino {
		fd, err := os.Open(targetFile)
		if err != nil {
			return 0
		}
		defer fd.Close()
		const SYS_SETNS = 308
		res, _, _ := syscall.RawSyscall(SYS_SETNS, fd.Fd(), 0, 0)
		if res != 0 {
			return -1
		} else {
			return 1
		}

		//err = unix.Setns(int(fd.Fd()), 0)
		// if err == nil {
		// 	return 1
		// } else {
		// 	return -1
		// }
	}
	return 0
}
