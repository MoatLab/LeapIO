#!/bin/bash

sudo modprobe nvme
sleep 2

sudo mknod /dev/wpt c 200 0

sudo modprobe rdma_ucm
sudo modprobe rdma_cm

# params: client_mode_only=1 for running SoCVM-Client
sudo insmod wpt.ko
