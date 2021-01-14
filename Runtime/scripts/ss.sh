#!/bin/bash

sudo ./socp server rdma 192.168.88.89 6889 2>&1 | tee pc.log
