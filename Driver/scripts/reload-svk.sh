#!/bin/bash

sudo rmmod wpt && sudo modprobe -r nvme && sleep 1 && sudo modprobe nvme && sleep 2 && sudo insmod wpt.ko use_rdma_for_vqp=1 client_mode_only=1
