# avoid module verification failure due to missing signature and key
CONFIG_MODULE_SIG=n
RDMA_TARGET=rt

#-DDEBUG
LCFLAGS += -g
ccflags-y += ${LCFLAGS}
CC += ${WPT_CFLAGS}

obj-m += $(RDMA_TARGET).o

# ats.o after wpt-qp.o
rdma-objs := rdma.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
