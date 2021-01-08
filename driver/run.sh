#!/bin/bash
# Author: Huaicheng Li <t-huali@microsoft.com>
# Author: Huaicheng Li <huaicheng@cs.uchicago.edu>

# create char dev file
if [[ ! -e /dev/wpt ]]; then
    sudo mknod /dev/wpt c 200 0
fi

sleep 1

#echo 1 | sudo tee /sys/module/rcupdate/parameters/rcu_cpu_stall_suppress

if [[ "$(lsmod | grep nvme)" == "" ]]; then
    #sudo insmod ~/git/linux/drivers/nvme/host/nvme-core.ko
    #sudo insmod ~/git/linux/drivers/nvme/host/nvme.ko
    sudo modprobe nvme
fi

echo RT_RUNTIME_GREED | sudo tee /sys/kernel/debug/sched_features
echo NO_RT_RUNTIME_SHARE | sudo tee /sys/kernel/debug/sched_features

sleep 1


if [[ "$(lsmod | grep wpt)" != "" ]]; then
    sudo rmmod wpt
fi

if [[ $# > 1 ]]; then
    sudo rmmod wpt
else
    sudo insmod wpt.ko
fi
