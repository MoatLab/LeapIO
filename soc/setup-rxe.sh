#!/bin/bash

sudo modprobe ib_uverbs

cd ~/git/rdma-core
sudo ./build/providers/rxe/rxe_cfg.in start

sudo ./build/bin/ibv_devinfo
