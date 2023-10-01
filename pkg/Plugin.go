package collector

import (
	"os"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

var collectors []Collector
var logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))

/*
定义数据变化值
*/
const (
	DT_All = iota
	DT_Add
	DT_Changed
	DT_Delete
)

func GetAllCollector() []Collector {
	return collectors
}

/*
创建成功或失败指标
*/
func createSuccessMetric(name string, isSuccess float64) prometheus.Metric {
	var tags = make(map[string]string)
	tags["name"] = name
	metricDesc := prometheus.NewDesc("success", "isSuccess", nil, tags)
	return prometheus.MustNewConstMetric(metricDesc, prometheus.CounterValue, isSuccess)
}
