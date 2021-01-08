#!/bin/bash

echo 1 | sudo tee /proc/sys/vm/drop_caches
