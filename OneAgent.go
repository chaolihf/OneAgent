package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"com.chinatelecom.oneops.exporter/OneAgent/exporter"
	node_exporter_main "github.com/chaolihf/node_exporter"

	//包引用是包含模块名/路径名/包名
	collector "com.chinatelecom.oneops.exporter/OneAgent/pkg"
	"github.com/chaolihf/udpgo/lang"
	"github.com/containerd/cgroups/v3/cgroup1"

	//"github.com/elastic/beats/v7/filebeat/cmd"
	//inputs "github.com/elastic/beats/v7/filebeat/input/default-inputs"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

type oneAgentCollector struct {
}

var logger *zap.Logger
var loggerDatas *exporter.LoggerData
var (
	showVersion   = flag.Bool("version", false, "Print version information.")
	listenAddress = flag.String("web.listen-address", ":19172", "The address to listen on for HTTP requests.")
	metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
)

func init() {
	//初始化插件
	logger = lang.InitProductLogger("logs/agent.log", 100, 5, 10)
}

/*
use cgroup to limit process resource,such as cpu,memory
*/
func limitResource() {
	shares := uint64(20)
	period := uint64(1000000)
	quota := int64(200000)
	memory := int64(10000000)
	swap := int64(1000000000)
	control, err := cgroup1.New(cgroup1.StaticPath("/test"), &specs.LinuxResources{
		CPU: &specs.LinuxCPU{
			Shares: &shares,
			Quota:  &quota,
			Period: &period,
		},
		Memory: &specs.LinuxMemory{
			Limit: &memory,
			Swap:  &swap,
		},
	})
	if err != nil {
		logger.Error(err.Error())
	} else {
		defer control.Delete()
		cmd := exec.Command("./mock/mock")
		if err := cmd.Start(); err != nil {
			fmt.Println("Error:", err)
			return
		}
		if err := control.Add(cgroup1.Process{Pid: cmd.Process.Pid}); err != nil {
			logger.Error(err.Error())
		}
		logger.Info("add")
	}
}

func main() {
	logger.Info("host collector\n")
	node_exporter_main.Main()
	flag.Parse()
	if !strings.Contains(*listenAddress, ":9172") {
		node_expoter_main.Main()
	}
	if *showVersion {
		fmt.Println("version V1.6.1")
		return
	}
	http.HandleFunc(*metricsPath, func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()
		registry.MustRegister(&oneAgentCollector{})
		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	})
	// prometheus.MustRegister(&hadoopCollector{})
	logger.Info("start to listen on " + *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Fatalf("Error starting HTTP server: %s", err)
	}
	//limitResource()
}

func (oneCollect *oneAgentCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (oneCollector *oneAgentCollector) Collect(ch chan<- prometheus.Metric) {
	for _, item := range collector.GetAllCollector() {
		item.Update(ch)
	}
}
