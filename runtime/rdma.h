#ifndef __LEAP_RDMA_H__
#define __LEAP_RDMA_H__

#include <infiniband/verbs.h>

enum {
	PINGPONG_RECV_WRID = 1,
	PINGPONG_SEND_WRID = 2,
};

struct pingpong_context {
    struct ibv_context	*context;
    struct ibv_comp_channel *channel;
    struct ibv_pd		*pd;
    struct ibv_mr		*mr;
    struct ibv_dm		*dm;
    union {
        struct ibv_cq		*cq;
        struct ibv_cq_ex	*cq_ex;
    } cq_s;
    struct ibv_qp		*qp;
    char			*buf;
    int			 size;
    int			 send_flags;
    int			 rx_depth;
    int			 pending;
    struct ibv_port_attr     portinfo;
    uint64_t		 completion_timestamp_mask;
};

#ifndef min
#define min(x,y) ({ \
                typeof(x) _x = (x); \
                typeof(y) _y = (y); \
                (void) (&_x == &_y); \
                _x < _y ? _x : _y; })
#endif

#ifndef max
#define max(x,y) ({ \
                typeof(x) _x = (x); \
                typeof(y) _y = (y); \
                (void) (&_x == &_y); \
                _x > _y ? _x : _y; })
#endif


int leap_rdma_main(int argc, char *argv[]);
int rdma_test_main(int argc, char *argv[]);

enum ibv_mtu pp_mtu_to_enum(int mtu);
int pp_get_port_info(struct ibv_context *context, int port,
		     struct ibv_port_attr *attr);
void wire_gid_to_gid(const char *wgid, union ibv_gid *gid);
void gid_to_wire_gid(const union ibv_gid *gid, char wgid[]);

#endif
