# avoid module verification failure due to missing signature and key
CONFIG_MODULE_SIG=n
WPT_TARGET=wpt
OCT_TARGET=oct

#-DDEBUG
LCFLAGS += -g
ccflags-y += ${LCFLAGS}

ifeq ($(rdma_vqps), true)
ccflags-y += -DRDMA_VQPS
endif

CC += ${WPT_CFLAGS}

obj-m += $(WPT_TARGET).o
obj-m += $(OCT_TARGET).o

# ats.o must come after wpt-qp.o
wpt-objs := wpt-util.o wpt-qpmap.o pnvme.o ats.o wpt-dbg.o wpt-core.o
ifeq ($(rdma_vqps), true)
wpt-objs += rdma.o
endif

oct-objs := oct-core.o pnvme.o wpt-qpmap.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
