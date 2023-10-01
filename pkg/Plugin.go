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

/*
输出插件接口类
*/
type Collector interface {

	/*
		实现获取指标的操作
	*/
	Update(ch chan<- prometheus.Metric) error
}

func registerCollector(collector string, isDefaultEnabled bool, factory func(logger log.Logger) (Collector, error)) {
	newCollector, err := factory(logger)
	if err == nil {
		collectors = append(collectors, newCollector)
	}

}

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
