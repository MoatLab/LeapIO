#!/bin/bash
# Author: Huaicheng Li <huaicheng@cs.uchicago.edu>

set -e

SCHED_FEAT=/sys/kernel/debug/sched_features
BF=/home/huaicheng/git/msr/femu/build-femu/
SYSCPUDIR=/sys/devices/system/cpu

# $1: CPU ID
set_cpu_offline() {
    local id=$1
    local cpuonline=$SYSCPUDIR/cpu${id}/online
    [[ -e $cpuonline ]] && echo 0 | sudo tee ${cpuonline} || echo "Failed to set CPU${id} offline"
}

set_cpu_online() {
    local id=$1
    local cpuonline=$SYSCPUDIR/cpu${id}/online
    [[ -e $cpuonline ]] && echo 1 | sudo tee ${cpuonline} || echo "Failed to set CPU${id} online"
}

#if [[ ! -e $SCHED_FEAT ]]; then
#    echo ""
#    echo "sched_features doesn't exist, recompile your kernel with DEBUG_SCHED"
#    echo ""
#    exit
#fi

# create char dev file
if [[ ! -e /dev/wpt ]]; then
    sudo mknod /dev/wpt c 200 0
    sleep 1
fi

#echo 1 | sudo tee /sys/module/rcupdate/parameters/rcu_cpu_stall_suppress

if [[ "$(lsmod | grep nvme)" == "" ]]; then
    sudo modprobe nvme_core
    sudo modprobe nvme
fi

#echo RT_RUNTIME_GREED | sudo tee ${SCHED_FEAT}
#echo NO_RT_RUNTIME_SHARE | sudo tee ${SCHED_FEAT}

sleep 1

if [[ $# > 1 ]]; then
    # rerun everything with a clean state
    # make sure VMs are shutdown first
    vmpids=$(ps -ef  |grep grep qemu | grep -v grep | grep -v sudo | awk '{print $2}')

    if [[ $vmpids != "" ]]; then
        echo "Shutting down VMs first"
        ./g
    fi
    sudo rmmod wpt && sudo modprobe -r nvme && sudo modprobe nvme && sudo insmod wpt.ko
else
    sudo insmod wpt.ko
    sleep 1
    # boot the VMs
    ./s
fi

# pin vCPUs on DBVM and SoCVM
#cd $BF && ./pin.sh
