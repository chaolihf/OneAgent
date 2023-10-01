package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	go func() {
		for {
			rand.Intn(1000000000)
		}
	}()
	caches := [][]byte{}
	for {
		tempValue := make([]byte, 10240000)
		for i := range tempValue {
			tempValue[i] = 0x01
		}
		caches = append(caches, tempValue)
		fmt.Println(len(caches))
		time.Sleep(time.Second * 1)
	}
}
