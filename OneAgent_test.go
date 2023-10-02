package main

import (
	"testing"

	node_expoter_main "github.com/chaolihf/node_exporter"
)

// 包引用是包含模块名/路径名/包名
func TestNodeExpoterModule(t *testing.T) {
	node_expoter_main.Main()
}
