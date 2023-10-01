package collector

/*
此文件和NodeExporter中类定义重复，不需要拷贝到Node_Exporter的collector目录下
*/
import (
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
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
