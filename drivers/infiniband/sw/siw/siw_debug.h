/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */

/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

#ifndef _SIW_DEBUG_H
#define _SIW_DEBUG_H

#define siw_dbg(ddev, fmt, ...)                                                \
	dev_dbg(&(ddev)->base_dev.dev, "cpu%2d %s: " fmt, smp_processor_id(),  \
		__func__, ##__VA_ARGS__)

#define siw_dbg_qp(qp, fmt, ...)                                               \
	siw_dbg(qp->sdev, "[QP %u]: " fmt, qp->id, ##__VA_ARGS__)

#define siw_dbg_cq(cq, fmt, ...)                                               \
	siw_dbg(cq->sdev, "[CQ %u]: " fmt, cq->id, ##__VA_ARGS__)

#define siw_dbg_pd(pd, fmt, ...)                                               \
	siw_dbg(pd->sdev, "[PD %u]: " fmt, pd->base_pd.res.id, ##__VA_ARGS__)

#define siw_dbg_mem(mem, fmt, ...)                                             \
	siw_dbg(mem->sdev, "[MEM 0x%08x]: " fmt, mem->stag, ##__VA_ARGS__)

#define siw_dbg_cep(cep, fmt, ...)                                             \
	siw_dbg(cep->sdev, "[CEP 0x%p]: " fmt, cep, ##__VA_ARGS__)

#ifdef DEBUG_HDR

#define siw_dprint_hdr(hdr, qpn, msg) siw_print_hdr(hdr, qpn, msg)

#else

#define siw_dprint_hdr(hdr, qpn, msg)                                          \
	do {                                                                   \
	} while (0)

#endif

#endif
