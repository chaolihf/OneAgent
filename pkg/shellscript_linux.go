package collector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

/*
定义Shell类
*/
type Shell_Script struct {
	lineParser *regexp.Regexp
	configs    []ShellConfig
}

/*
定义shell脚本配置
*/
type ShellConfig struct {
	Name     string
	Timeout  float64
	Argument []string
}

func init() {
	registerCollector("shell", true, newShellScriptCollector)
}

/*
初始化收集器
*/
func newShellScriptCollector(g_logger log.Logger) (Collector, error) {
	logger = g_logger
	lineParser, err := regexp.Compile(`([---a-zA-Z0-9_]+)({(.*)})? ([---NaN0-9e\\.\\+]+)( [0-9]+)*`)
	if err != nil {
		logger.Log(err.Error())
	}
	filePath := "config.json"
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("读取文件出错:"+filePath, err)
	} else {
		jsonScriptInfos, err := jjson.NewJsonObject([]byte(content))
		if err != nil {
			fmt.Println("JSON文件格式出错:", err)
		} else {
			var scriptConfigs []ShellConfig
			for _, jsonScriptInfo := range jsonScriptInfos.GetJsonArray("shellScript") {
				jsonArguments := jsonScriptInfo.GetJsonArray("arguments")
				arguments := []string{}
				for _, jsonArgInfo := range jsonArguments {
					arguments = append(arguments, jsonArgInfo.GetStringValue())
				}
				scriptConfig := ShellConfig{
					Name:     jsonScriptInfo.GetString("name"),
					Timeout:  jsonScriptInfo.GetFloat("timeout"),
					Argument: arguments,
				}
				scriptConfigs = append(scriptConfigs, scriptConfig)
			}
			return &Shell_Script{
				lineParser: lineParser,
				configs:    scriptConfigs,
			}, nil
		}
	}
	return &Shell_Script{
		lineParser: lineParser,
		configs:    nil,
	}, nil
}

func (collector *Shell_Script) Update(ch chan<- prometheus.Metric) error {
	if collector.configs == nil {
		return nil
	}
	scriptChannel := make([]chan string, len(collector.configs))
	for index, config := range collector.configs {
		scriptChannel[index] = make(chan string)
		go runScript(collector.lineParser, scriptChannel[index], ch, config)

	}
	for _, scriptChan := range scriptChannel {
		v := <-scriptChan
		fmt.Println("run script ", v)
	}
	return nil
}

func runScript(lineParser *regexp.Regexp, scriptChain chan<- string, ch chan<- prometheus.Metric, config ShellConfig) {
	deadline := time.Now().Add(time.Duration(config.Timeout * float64(time.Second)))
	var cmd *exec.Cmd
	var cancel context.CancelFunc
	ctx := context.Background()
	if config.Timeout > 0 {
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel()
	}
	//nolint:gosec
	cmd = exec.CommandContext(ctx, config.Argument[0], config.Argument[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		logger.Log(
			"msg", fmt.Sprintf("Script '%s' execution failed", config.Name),
			"cmd", strings.Join(config.Argument, " "),
			"stdout", stdout.String(),
			"stderr", stderr.String(),
			"env", strings.Join(cmd.Env, " "),
			"err", err,
		)
		ch <- createSuccessMetric(config.Name, 0)
		scriptChain <- config.Name + " failed"
	} else {
		rows := strings.Split(stdout.String(), "\n")
		for _, row := range rows {
			row = strings.TrimSpace(row)
			if len(row) > 0 && !strings.HasPrefix(row, "#") {
				metric, err := parseMetric(lineParser, row, config.Name)
				if err != nil {
					logger.Log(err.Error())
				} else {
					ch <- metric
				}
			}
		}
		ch <- createSuccessMetric(config.Name, 1)
		scriptChain <- config.Name + " success"
	}
}

/*
按行解析指标
*/
func parseMetric(lineParser *regexp.Regexp, row string, name string) (prometheus.Metric, error) {
	results := lineParser.FindStringSubmatch(row)
	if len(results) == 6 {
		var tags = make(map[string]string)
		tags["name"] = name
		floatValue, err := strconv.ParseFloat(results[4], 64)
		if err != nil {
			return nil, err
		}
		metricLabels := strings.Split(results[3], "\",")
		for i, metricLabel := range metricLabels {
			leftIndex := strings.Index(metricLabel, "=")
			if i != len(metricLabels)-1 {
				metricLabel += "\""
			}
			if leftIndex != -1 {
				tags[metricLabel[0:leftIndex]] = url.PathEscape(metricLabel[leftIndex+2 : len(metricLabel)-1])
			}
		}
		//补全标签
		for i := 1; i <= 3; i++ {
			key := "t" + strconv.Itoa(i)
			_, exists := tags[key]
			if !exists {
				tags[key] = ""
			}
		}
		metricDesc := prometheus.NewDesc(results[1], results[1], nil, tags)
		metric := prometheus.MustNewConstMetric(metricDesc, prometheus.CounterValue, floatValue)
		return metric, nil
	}
	return nil, errors.New("prom格式错误")
}
