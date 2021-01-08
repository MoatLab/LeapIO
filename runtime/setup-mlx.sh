#!/bin/bash

sudo modprobe ib_uverbs

sudo modprobe mlx5_ib

sudo modprobe rdma_ucm
sudo modprobe rdma_cm

sleep .5

sudo ibv_devinfo
