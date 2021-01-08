#!/bin/bash

sudo ifconfig eth2 192.168.88.88

sudo ./socp client tcp 192.168.88.89 5678 2>&1 | tee pc.log
