# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Open-Channel SSDs.
#

CFLAGS_core.o := -DDEBUG
CFLAGS_pblk.o := -DDEBUG
CFLAGS_pblk-init.o := -DDEBUG
CFLAGS_pblk-core.o := -DDEBUG
CFLAGS_pblk-rb.o := -DDEBUG
CFLAGS_pblk-write.o := -DDEBUG
CFLAGS_pblk-cache.o := -DDEBUG
CFLAGS_pblk-read.o := -DDEBUG
CFLAGS_pblk-gc.o := -DDEBUG
CFLAGS_pblk-recovery.o := -DDEBUG
CFLAGS_pblk-map.o := -DDEBUG
CFLAGS_pblk-rl.o := -DDEBUG
CFLAGS_pblk-sysfs.o := -DDEBUG

obj-$(CONFIG_NVM)		:= core.o
obj-$(CONFIG_NVM_PBLK)		+= pblk.o
pblk-y				:= pblk-init.o pblk-core.o pblk-rb.o \
				   pblk-write.o pblk-cache.o pblk-read.o \
				   pblk-gc.o pblk-recovery.o pblk-map.o \
				   pblk-rl.o pblk-sysfs.o
