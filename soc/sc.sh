#!/bin/bash

sudo ./socp client rdma 192.168.8.9 6889 2>&1 | tee pc.log
