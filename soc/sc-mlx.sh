#!/bin/bash

sudo ifconfig eth2 192.168.88.88

sudo ./socp client rdma 192.168.88.89 6889 2>&1 | tee pc.log
