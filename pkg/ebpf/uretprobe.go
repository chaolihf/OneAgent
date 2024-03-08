// This program demonstrates how to attach an eBPF program to a uretprobe.
// The program will be attached to the 'readline' symbol in the binary '/bin/bash' and print out
// the line which 'readline' functions returns to the caller.
//go:build amd64

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

//export BPF2GO_FLAGS="-O2 -g -Wall"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event -type fileEvent -type so_event bpf uretprobe.c -- -I /usr/src/linux-headers-6.5.0-17-generic/tools/bpf/resolve_btfids/libbpf/include

const (
	// The path to the ELF binary containing the function to trace.
	// On some distributions, the 'readline' function is provided by a
	// dynamically-linked library, so the path of the library will need
	// to be specified instead, e.g. /usr/lib/libreadline.so.8.
	// Use `ldd /bin/bash` to find these paths.
	binPath = "/bin/bash"
	symbol  = "readline"
)

func main() {
	go CountCC(1)
	goElf, err := elf.Open("/usr/sbin/sshd")
	goSymbols, err := goElf.Symbols()
	goDynSymbols, err := goElf.DynamicSymbols()
	goSymbols = append(goSymbols, goDynSymbols...)
	for _, symbol := range goSymbols {
		// if symbol.Name == "main.CountCC" {
		// 	section := goElf.Sections[symbol.Section]
		// 	elfText, _ := section.Data()
		// 	start := symbol.Value - section.Addr
		// 	end := start + symbol.Size
		// 	instHex := elfText[start:end]
		// 	decodeInstruction(instHex)

		// 	break
		// }
		fmt.Println(symbol.Name)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("load bpf error %v", err)
	}
	consts := map[string]interface{}{
		"catchFileMode": uint64(0x100000),
	}
	if err = spec.RewriteConstants(consts); err != nil {
		log.Fatalf("RewriteConstants error:%v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		// 输出校验日志，
		if errors.As(err, &ve) {
			fmt.Printf("Verifier error: %+v\n", ve)
		}
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open an ELF binary and read its symbols.
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	// Open a Uretprobe at the exit point of the symbol and attach
	// the pre-compiled eBPF program to it.
	up, err := ex.Uretprobe(symbol, objs.UretprobeBashReadline, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	defer up.Close()

	ifname := "enp0s3" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdpLink.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	/*
		处理kprobe事件
	*/
	kp, err := link.Kprobe("sys_execve", objs.HelloWorld, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	go func() {
		for {
			select {
			case <-tick:
				var count uint64
				err := objs.PktCount.Lookup(uint32(0), &count)
				if err != nil {
					log.Fatal("Map lookup:", err)
				}
				log.Printf("Received %d packets", count)

			case <-stop:
				log.Print("Received signal, exiting..")
				return
			}
		}
	}()

	if err := objs.bpfMaps.FileModeMap.Put(uint64(0), uint64(0x300000)); err != nil {
		log.Fatalf("init file mode map failed")
	}

	/*
	   增加vfs相关绑定
	   # newer kernels may don't fire vfs_create, call vfs_open instead:
	*/
	kpOpenOrCreate, err := link.Kprobe("vfs_open", objs.TraceVfsOpen, nil)
	if err != nil {
		log.Fatalf("opening kprobe vfs open : %s", err)
	}
	defer kpOpenOrCreate.Close()
	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	fileRingReader, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer fileRingReader.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := fileRingReader.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Printf("Listening for file create ring buffer events..")
	go func() {
		var fileEvent bpfFileEvent
		for {
			record, err := fileRingReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			// Parse the ringbuf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fileEvent); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			log.Printf("pid: %d\tfileName: %s,mode:%d\n", fileEvent.Pid,
				unix.ByteSliceToString(fileEvent.Filename[:]), fileEvent.Mode)
		}
	}()

	go func() {
		//开始处理perf event 事件
		// bpfEvent is generated by bpf2go.
		var event bpfEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			// Parse the perf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}

			log.Printf("%s:%s return value: %s", binPath, symbol, unix.ByteSliceToString(event.Line[:]))
		}
	}()

	/*
		测试tracing
	*/

	enterLink, err := link.Tracepoint("syscalls", "sys_enter_read", objs.bpfPrograms.SysEnterRead, nil)
	if err != nil {
		log.Fatal(err)
	}
	exitLink, err := link.Tracepoint("syscalls", "sys_exit_read", objs.bpfPrograms.SysExitRead, nil)
	if err != nil {
		log.Fatal(err)
	}
	acceptLink, err := link.Tracepoint("syscalls", "sys_enter_accept", objs.bpfPrograms.SysEnterAccept, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer enterLink.Close()
	defer exitLink.Close()
	defer acceptLink.Close()

	/*
		测试socket filter
	*/
	var linkIndex = 0
	sock, err := openRawSock(linkIndex)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock)
	const SO_ATTACH_BPF = 50
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, objs.SocketHandler.FD()); err != nil {
		panic(err)
	}

	fmt.Printf("Filtering on eth index: %d\n", linkIndex)
	fmt.Println("Packet stats:")

	socketRingReader, err := ringbuf.NewReader(objs.SocketEvents)
	if err != nil {
		log.Fatalf("opening socket ringbuf reader: %s", err)
	}
	defer socketRingReader.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := socketRingReader.Close(); err != nil {
			log.Fatalf("closing socket ringbuf reader: %s", err)
		}
	}()

	log.Printf("Listening for file create socket ring buffer events..")
	func() {
		var socketEvent bpfSoEvent
		for {
			record, err := socketRingReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received socket ring signal, exiting..")
					return
				}
				log.Printf("reading from socket reader: %s", err)
				continue
			}

			// Parse the socket ringbuf event entry into a socket Event structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &socketEvent); err != nil {
				log.Printf("parsing socket ringbuf event: %s", err)
				continue
			}
			portBytes := networkToHostOrder(socketEvent.Ports)
			log.Printf("http request from %s:%d to %s:%d , content:%s\n",
				uint32ToIPString(networkToHostOrder(socketEvent.SrcAddr)),
				int(portBytes[0])*256+int(portBytes[1]),
				uint32ToIPString(networkToHostOrder(socketEvent.DstAddr)),
				int(portBytes[2])*256+int(portBytes[3]),
				unix.ByteSliceToString(socketEvent.Payload[:]))
		}
	}()
	time.Sleep(30 * time.Second)
}

func networkToHostOrder(ip uint32) [4]byte {
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, ip)
	for i, j := 0, len(ipBytes)-1; i < j; i, j = i+1, j-1 {
		ipBytes[i], ipBytes[j] = ipBytes[j], ipBytes[i]
	}
	return [4]byte(ipBytes)
}

func uint32ToIPString(ipBytes [4]byte) string {
	netIP := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
	return netIP.String()
}

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

//go:noinline
func recursion(level, maxLevel int) int {
	if level > maxLevel {
		return level
	}
	return recursion(level+1, maxLevel)
}

//go:noinline
func NewTestFunc() int {
	//nothing
	print("NewTestFunc\n")
	return 100
}

// uretprobe挂载的目标函数
//
//go:noinline
func CountCC(maxLevel int) (a int) {
	a = NewTestFunc()
	fmt.Println(a)
	if a > 100 {
		return a
	}

	a = recursion(0, maxLevel)
	fmt.Printf("CountCC return :%d\n", a)
	return a
}

// decodeInstruction Decode into assembly instructions and identify the RET instruction to return the offset.
func decodeInstruction(instHex []byte) ([]int, error) {
	var offsets []int
	var s *bytes.Buffer
	s = bytes.NewBufferString("")
	for i := 0; i < len(instHex); {
		inst, err := x86asm.Decode(instHex[i:], 64)
		//fmt.Printf("%04X\t%s\n", i, inst.String())
		//s.WriteString(inst.String())
		s.WriteString(fmt.Sprintf("%04X\t%s", i, inst.String()))
		s.WriteString("\n")
		if err != nil {
			return nil, err
		}
		if inst.Op == x86asm.RET {
			offsets = append(offsets, i)
		}
		i += inst.Len
	}

	asmCode := s.String()
	fmt.Println(asmCode)
	return offsets, nil
}
