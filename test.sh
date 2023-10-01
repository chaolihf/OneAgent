#!/bin/bash
preSecond=$(date +%s)
while true; do
  newSecond=$(date +%s)
  if [ $newSecond -ne $preSecond ]; then
    dd if=/dev/zero of=/dev/null bs=1M count=10
    preSecond=$newSecond
  fi
done
