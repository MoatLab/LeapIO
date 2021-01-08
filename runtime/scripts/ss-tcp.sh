#!/bin/bash

sudo ifconfig eth2 192.168.88.89 up

sudo ./socp server tcp 192.168.88.89 5678 2>&1 | tee pc.log
