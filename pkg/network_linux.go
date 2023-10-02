package collector

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/net"
)

/*
连接的方向
*/
const (
	NET_Listen = iota
	NET_Income
	NET_Outcome
)

/*
保存的网络信息
*/
type NetworkInfo struct {
	pid            int32
	local_address  string
	local_port     uint32
	remote_address string
	remote_port    uint32
	net_type       uint32 //tcp 1 udp 2
	status         string
	direction      int
	counter        int
	key            string
}

/*
定义Shell类
*/
type NetworkCollector struct {
	interval        int
	lastCollectTime int64
	lastNetworkInfo []NetworkInfo
	counterOffset   int
	localLog        bool
}

func init() {
	registerCollector("network", true, newNetworkCollector)
}

/*
初始化收集器
*/
func newNetworkCollector(g_logger log.Logger) (Collector, error) {
	logger = g_logger
	filePath := "config.json"
	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Log("读取文件出错:"+filePath, err)
	} else {
		jsonConfigInfos, err := jjson.NewJsonObject([]byte(content))
		if err != nil {
			logger.Log("JSON文件格式出错:", err)
		} else {
			jsonNetworkInfo := jsonConfigInfos.GetJsonObject("network")
			return &NetworkCollector{
				interval:      jsonNetworkInfo.GetInt("interval"),
				counterOffset: jsonNetworkInfo.GetInt("counterOffset"),
				localLog:      jsonNetworkInfo.GetBool("localLog"),
			}, nil
		}
	}
	return &NetworkCollector{
		interval:      86400,
		counterOffset: 100,
		localLog:      true,
	}, nil
}

func (collector *NetworkCollector) Update(ch chan<- prometheus.Metric) error {
	lastTime := collector.lastCollectTime
	currentTime := time.Now().Unix()
	var err error
	var allNetworkInfo []NetworkInfo
	var isSendAll bool
	if lastTime == 0 || currentTime-lastTime > int64(collector.interval) {
		isSendAll = true
	} else {
		isSendAll = false
	}
	allNetworkInfo, err = getAllConnections(collector.localLog)
	if err != nil {
		logger.Log(err.Error())
		ch <- createSuccessMetric("network", 0)
	} else {
		sort.Slice(allNetworkInfo, func(i, j int) bool {
			return allNetworkInfo[i].key < allNetworkInfo[j].key
		})
		if !isSendAll {
			addNetworkInfos, changedNetworkInfos, removedNetworkInfos, newAllNetworkInfo := getChangedNetwork(collector, allNetworkInfo)
			for _, network := range addNetworkInfos {
				ch <- createNetworkMetric(&network, DT_Add)
			}
			for _, network := range changedNetworkInfos {
				ch <- createNetworkMetric(&network, DT_Changed)
			}
			for _, network := range removedNetworkInfos {
				ch <- createNetworkMetric(&network, DT_Delete)
			}
			collector.lastNetworkInfo = newAllNetworkInfo
		} else {
			for _, item := range allNetworkInfo {
				ch <- createNetworkMetric(&item, DT_All)
			}
			collector.lastNetworkInfo = allNetworkInfo
		}
		ch <- createSuccessMetric("network", 1)
		collector.lastCollectTime = currentTime

	}
	return nil
}

/*
比较新老网络信息获取增量变化信息
*/
func getChangedNetwork(collector *NetworkCollector, newNetworks []NetworkInfo) ([]NetworkInfo, []NetworkInfo, []NetworkInfo, []NetworkInfo) {
	var (
		newNetworksArr     []NetworkInfo
		changedNetworkAttr []NetworkInfo
		deletedNetworksArr []NetworkInfo
		allNetworksArr     []NetworkInfo
	)
	oldNetworks := collector.lastNetworkInfo
	oldIndex := 0
	newIndex := 0
	for oldIndex < len(oldNetworks) && newIndex < len(newNetworks) {
		oldKey := oldNetworks[oldIndex].key
		newKey := newNetworks[newIndex].key
		if oldKey == newKey {
			if areNetworkChanged(oldNetworks[oldIndex], newNetworks[newIndex], collector) {
				changedNetworkAttr = append(changedNetworkAttr, newNetworks[newIndex])
				allNetworksArr = append(allNetworksArr, newNetworks[newIndex])
			} else {
				allNetworksArr = append(allNetworksArr, oldNetworks[oldIndex])
			}
			oldIndex++
			newIndex++
		} else if oldKey < newKey {
			deletedNetworksArr = append(deletedNetworksArr, oldNetworks[oldIndex])
			oldIndex++
		} else {
			newNetworksArr = append(newNetworksArr, newNetworks[newIndex])
			allNetworksArr = append(allNetworksArr, newNetworks[newIndex])
			newIndex++
		}
	}
	for oldIndex < len(oldNetworks) {
		deletedNetworksArr = append(deletedNetworksArr, oldNetworks[oldIndex])
		oldIndex++
	}
	for newIndex < len(newNetworks) {
		newNetworksArr = append(newNetworksArr, newNetworks[newIndex])
		allNetworksArr = append(allNetworksArr, newNetworks[newIndex])
		newIndex++
	}
	return newNetworksArr, changedNetworkAttr, deletedNetworksArr, allNetworksArr
}

/*
比较网络参数是否发生较大的改变
*/
func areNetworkChanged(oldNetworkInfo, newNetworkInfo NetworkInfo, collector *NetworkCollector) bool {
	return math.Abs(float64(oldNetworkInfo.counter)-float64(newNetworkInfo.counter)) > float64(collector.counterOffset)
}

/*
创建网络指标
*/
func createNetworkMetric(connectionInfo *NetworkInfo, metricType int) prometheus.Metric {
	var tags = make(map[string]string)
	tags["pid"] = fmt.Sprintf("%d", connectionInfo.pid)
	tags["local_address"] = connectionInfo.local_address
	tags["local_port"] = fmt.Sprintf("%d", connectionInfo.local_port)
	tags["remote_address"] = connectionInfo.remote_address
	tags["remote_port"] = fmt.Sprintf("%d", connectionInfo.remote_port)
	tags["type"] = fmt.Sprintf("%d", connectionInfo.net_type)
	tags["status"] = connectionInfo.status
	tags["direction"] = fmt.Sprintf("%d", connectionInfo.direction)
	tags["counter"] = fmt.Sprintf("%d", connectionInfo.counter)
	metricDesc := prometheus.NewDesc("network", "network", nil, tags)
	return prometheus.MustNewConstMetric(metricDesc, prometheus.CounterValue, float64(metricType))
}

/*
get all connection and sort by pid,state
1、sort connection by process(pid)
2、get all state 'LISTEN'
2.1 if connection connect to listened port,it is income connection,else outcome connection
2.2 distinct income connection's ip address and listen port
2.3 distinct outcome connection's ip and port
return: listen connectionInfos,error
*/
func getAllConnections(localLog bool) ([]NetworkInfo, error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	allLocalAddress := make(map[string]bool)
	for _, item := range netInterfaces {
		for _, address := range item.Addrs {
			allLocalAddress[strings.Split(address.Addr, "/")[0]] = true
		}
	}
	connections, err := net.Connections("all")
	if err != nil {
		return nil, err
	} else {
		sort.Slice(connections, func(i, j int) bool {
			firstConn := connections[i]
			secondConn := connections[j]
			if firstConn.Pid != secondConn.Pid {
				return firstConn.Pid > secondConn.Pid
			} else if firstConn.Type != secondConn.Type {
				return firstConn.Type > secondConn.Type
			} else {
				return firstConn.Status > secondConn.Status
			}
		})
		//get all connections with same pid
		var pid int32 = -1
		var processStats []net.ConnectionStat
		//get all listen port
		var listenPorts = make(map[string]bool) //key is port+|+type
		for _, item := range connections {
			//family=2为v4,10为v6 type为以下值tcp 1 udp 2
			if !(item.Family == 1 || item.Family == 16 || item.Family == 17) { //af_unix,af_netlink,af_packet
				if item.Status == "LISTEN" {
					listenPorts[fmt.Sprintf("%d|%d", item.Laddr.Port, item.Type)] = true
				}
			}
			if localLog {
				logger.Log("Network", fmt.Sprintf("pid:%d,family:%d,type:%d,local:%s,remote:%s,status:%s",
					item.Pid, item.Family, item.Type, item.Laddr.String(), item.Raddr.String(), item.Status))
			}
		}
		allNetworkInfos := []NetworkInfo{}
		//遍历按照pid排序后的数据，获取这个pid下面所有的连接
		for _, item := range connections {
			if !(item.Family == 1 || item.Family == 16 || item.Family == 17) { //af_unix,af_netlink,af_packet
				if item.Pid == pid || pid == -1 {
					processStats = append(processStats, item)
					if pid == -1 {
						pid = item.Pid
					}
				} else {
					handleProcessConnection(pid, listenPorts, processStats, &allNetworkInfos)
					processStats = processStats[:0]
					processStats = append(processStats, item)
					pid = item.Pid
				}
			}

		}
		if pid != -1 {
			handleProcessConnection(pid, listenPorts, processStats, &allNetworkInfos)
		}
		return allNetworkInfos, nil
	}
}

/*
获取网咯信息
direction:方向
*/
func getNetworkInfo(connection net.ConnectionStat, direction int) NetworkInfo {
	networkInfo := NetworkInfo{
		pid:            connection.Pid,
		local_address:  connection.Laddr.IP,
		local_port:     connection.Laddr.Port,
		remote_address: connection.Raddr.IP,
		remote_port:    connection.Raddr.Port,
		net_type:       connection.Type,
		status:         connection.Status,
		direction:      direction,
	}
	var key string
	switch direction {
	case NET_Listen:
		{
			key = fmt.Sprintf("%d-%d-%d-%s-%d-%s", networkInfo.pid, direction, networkInfo.net_type,
				networkInfo.local_address, networkInfo.local_port, networkInfo.status)
			break
		}
	case NET_Income:
		{
			key = fmt.Sprintf("%d-%d-%d-%s-%d-%s-%s", networkInfo.pid, direction, networkInfo.net_type,
				networkInfo.local_address, networkInfo.local_port, networkInfo.status, networkInfo.remote_address)
			break
		}
	case NET_Outcome:
		{
			key = fmt.Sprintf("%d-%d-%d-%s-%d-%s-%s", networkInfo.pid, direction, networkInfo.net_type,
				networkInfo.local_address, networkInfo.remote_port, networkInfo.status, networkInfo.remote_address)
			break
		}
	}
	networkInfo.key = key
	return networkInfo
}

/*
handle connection per process
pid: process id
hostListenPorts:
*/
func handleProcessConnection(pid int32, hostListenPorts map[string]bool, processStats []net.ConnectionStat,
	allNetworkInfos *[]NetworkInfo) {
	mapConnections := make(map[string]NetworkInfo)
	for _, item := range processStats {
		if item.Status == "LISTEN" {
			networkInfo := getNetworkInfo(item, NET_Listen)
			networkInfo.counter = 1
			*allNetworkInfos = append(*allNetworkInfos, networkInfo)
		} else {
			_, ok := hostListenPorts[fmt.Sprintf("%d|%d", item.Laddr.Port, item.Type)]
			var dir int
			if ok {
				dir = NET_Income
			} else {
				dir = NET_Outcome
			}
			networkInfo := getNetworkInfo(item, dir)
			oldInfo, ok := mapConnections[networkInfo.key]
			if !ok {
				networkInfo.counter = 1
			} else {
				networkInfo.counter = oldInfo.counter + 1
			}
			mapConnections[networkInfo.key] = networkInfo
		}
	}
	for _, value := range mapConnections {
		*allNetworkInfos = append(*allNetworkInfos, value)
	}
}
