package collector

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

	"github.com/chaolihf/gopsutil/process"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

//see https://github.com/frohoff/jdk8u-jdk/blob/master/src/share/classes/sun/tools/attach/HotSpotVirtualMachine.java https://github.com/jattach/jattach https://github.com/hengyoush/Java-Agent-Loader

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
	allProcess, err := process.Processes()
	if err == nil {
		logger.Log(err.Error())
	} else {
		for _, process := range allProcess {
			name, err := process.Name()
			if err == nil {
				logger.Log(err.Error())
			} else {
				if name == "java" {
					AttachJava(process.Pid)
				}
			}
		}
	}
	return nil
}

func AttachJava(pid int32) {
	fmt.Println("Attach Java")
	socketFileName := fmt.Sprintf("/proc/%d/root/tmp/.java_pid%d", pid, pid)
	if !FileExist(socketFileName) {
		// create attach file
		attachFile, err := createAttachFile(pid)
		if err != nil {
			logger.Log("fail to create attach file, %v\n", err)
		}
		defer os.Remove(attachFile.Name())
		err = syscall.Kill(int(pid), syscall.SIGQUIT)
		if err != nil {
			logger.Log("fail to send quit, %v\n", err)
		}
		delayStep := 100
		attachTimeout := 3000
		timeSpend := 0
		delay := 0
		for timeSpend <= attachTimeout && !FileExist(socketFileName) {
			delay += delayStep
			time.Sleep(time.Millisecond * time.Duration(delay))
			timeSpend += delay
			if timeSpend > attachTimeout/2 && !FileExist(socketFileName) {
				syscall.Kill(int(pid), syscall.SIGQUIT)
			}
		}
		if !FileExist(socketFileName) {
			logger.Log("Unable to open socket file %s: "+
				"target process %d doesn't respond within %dms "+
				"or HotSpot VM not loaded\n", socketFileName, pid,
				timeSpend)
		}
	}
	conn, err := net.Dial("unix", socketFileName)
	if err != nil {
		logger.Log("fail to connect socketpath: %s, %v\n", socketFileName, err)
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

func createAttachFile(pid int32) (*os.File, error) {
	fn := fmt.Sprintf(".attach_pid%d", pid)
	path := fmt.Sprintf("/proc/%d/cwd/%s", pid, fn)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		file, err = os.OpenFile("/tmp/"+fn, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return nil, err
		} else {
			logger.Log("create attach pid file success2!\n")
		}
	} else {
		logger.Log("create attach pid file success!\n")
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
			return errors.New("Target VM did not respond")
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
