#!/bin/bash

sudo rmmod wpt && sudo modprobe -r nvme && sleep 1 && sudo modprobe nvme && sleep 2 && sudo insmod wpt.ko
