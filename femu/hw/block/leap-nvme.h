#ifndef __LEAP_NVME_H
#define __LEAP_NVME_H

#include "nvme.h"
#include "util/leap-util.h"

#define QEMU_NVME_MAX_NVQS  64


void leap_print_nvme_cmd(NvmeCmd *cmd);
void leap_print_nvme_cqe(NvmeCqe *cqe);
int leap_nvme_cmd_cmp(NvmeCmd *a, NvmeCmd *b);
int leap_nvme_cqe_cmp(NvmeCqe *a, NvmeCqe *b);
int leap_qpbuf_init(NvmeCtrl *n);
int leap_qpbuf_free(NvmeCtrl *n);
NvmeCmd *leap_qpbuf_get_sqe(NvmeCtrl *n, int sqid, int sq_head);
NvmeCqe *leap_qpbuf_get_cqe(NvmeCtrl *n, int cqid, int cq_tail);
void leap_qpbuf_debug_cqe(NvmeCQueue *cq, NvmeCqe *qcqe);

int leap_qpbuf_register_sq(NvmeSQueue *sq);
void leap_qpbuf_unregister_sq(NvmeSQueue *sq);
int leap_qpbuf_register_db(NvmeCtrl *n);
void leap_qpbuf_unregister_db(NvmeCtrl *n);
int leap_qpbuf_register_cq(NvmeCQueue *cq);
void leap_qpbuf_unregister_cq(NvmeCQueue *cq);

#endif
