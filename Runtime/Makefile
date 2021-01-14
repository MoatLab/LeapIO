#
# LeapIO Project Makefile
# Huaicheng Li <huaicheng@cs.uchicago.edu>
#

CC=g++
# -std=gnu++11 -Wno-pointer-arith
#RDMATOPDIR=/home/huaicheng/git/rdma-core/build
INC=-I${RDMATOPDIR}/include -I./
LDLIBS=-L${RDMATOPDIR}/lib -libverbs -lrdmacm
CCFLAGS=-Wall -g -O3 -pthread -std=gnu++11 -Wno-pointer-arith -Wno-sign-compare ${LDLIBS} ${INC} -DUSE_RTE_RING

# default: "make", assert() on, no debug msg
all: s t

# "make debug", debug version, assert() on, debug msgs on
debug: CCFLAGS += -DDEBUG_VQP -DDEBUG_PQP
debug: s

# "make release", no assert(), no debug msg
# -DNDEBUG to optimize out assert()
release: CCFLAGS += -DNDEBUG
release: s

# for building socp
s: socp.o tcp.o dmabuf.o rte_ring.o rdma-leap.o rdma-pcie.o rdma-util.o svk.o pagemap.o abc.o
	$(CC) -o socp socp.o tcp.o dmabuf.o rte_ring.o rdma-leap.o rdma-pcie.o rdma-util.o svk.o pagemap.o abc.o $(CCFLAGS) -L../../service/quantumleapservice/build.release/quantumleapservice -lquantumleapservice -lssl -lcrypto -lcpprest -lazurestorage -lboost_system

# for building tcptest
t: tcptest.o tcp.o
	$(CC) -o tcptest tcptest.o tcp.o $(CCFLAGS)

# for building rdmatest
#r: rdmatest.o rdma-leap.o rdma-util.o
#	$(CC) -o rdmatest rdmatest.o rdma-leap.o rdma-util.o $(CCFLAGS)

socp.o: socp.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c socp.c $(CCFLAGS)

rte_ring.o: rte_ring.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c rte_ring.c $(CCFLAGS)

dmabuf.o: dmabuf.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c dmabuf.c $(CCFLAGS)

tcptest.o: tcptest.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c tcptest.c $(CCFLAGS)

tcp.o: tcp.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c tcp.c $(CCFLAGS)

rdmatest.o: rdmatest.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c rdmatest.c $(CCFLAGS)

rdma-leap.o: rdma-leap.c rdma-util.o
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c rdma-leap.c $(CCFLAGS)

rdma-pcie.o: rdma-pcie.c rdma-util.o
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c rdma-pcie.c $(CCFLAGS)

rdma-util.o: rdma-util.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c rdma-util.c $(CCFLAGS)

svk.o: svk.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c svk.c $(CCFLAGS)

pagemap.o: pagemap.c
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c pagemap.c $(CCFLAGS)

abc.o: abc.cc
	$(CC) -I ../../service/quantumleapservice/quantumleapservice -c abc.cc $(CCFLAGS)

.PHONY: clean
clean:
	rm -f a.out *.o *~ core socp tcptest rdmatest abc

