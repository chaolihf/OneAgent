package main

import (
	"fmt"
	"testing"

	process "github.com/chaolihf/gopsutil/process"
	node_expoter_main "github.com/chaolihf/node_exporter"
)

// 包引用是包含模块名/路径名/包名
func TestNodeExpoterModule(t *testing.T) {
	node_expoter_main.Main()
}

func TestPsModule(t *testing.T) {
	allProcess, err := process.Processes()
	if err != nil {
		logger.Error(err.Error())
		return
	} else {
		for _, item := range allProcess {
			nsPid, _ := item.GetNamespacePid()
			fmt.Println(nsPid)
			username, _ := item.Username()
			fmt.Println(username)
			name, _ := item.Name()
			fmt.Println(name)
			command, _ := item.Cmdline()
			fmt.Println(command)
			memory, _ := item.MemoryInfo()
			fmt.Println(memory)
			numThread, _ := item.NumThreads()
			fmt.Println(numThread)
			numOpenFiles, _ := item.NumFDs()
			fmt.Println(numOpenFiles)
			createTime, _ := item.CreateTime()
			fmt.Println(createTime)
			parentId, _ := item.Ppid()
			fmt.Println(parentId)
			cpu, _ := item.CPUPercent()
			fmt.Println(cpu)
			exec, _ := item.Exe()
			fmt.Println(exec)
			ioCounters, _ := item.IOCounters()
			fmt.Println(ioCounters)
			if memory != nil {
				fmt.Println(int64(memory.RSS))
				fmt.Println(int64(memory.VMS))
			}
			fmt.Println(item.Pid)
			if ioCounters != nil {
				fmt.Println(int64(ioCounters.ReadBytes))
				fmt.Println(int64(ioCounters.WriteBytes))
				fmt.Println(int64(ioCounters.ReadCount))
				fmt.Println(int64(ioCounters.WriteCount))
			}
		}
	}
}
