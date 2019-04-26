// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

#include <linux/types.h>
#include <linux/printk.h>

#include "siw.h"

#define ddp_data_len(op, mpa_len)                                              \
	(mpa_len - (iwarp_pktinfo[op].hdr_len - MPA_HDR_SIZE))

void siw_print_hdr(union iwarp_hdr *hdr, int qp_id, char *string)
{
	enum rdma_opcode op = __rdmap_get_opcode(&hdr->ctrl);
	u16 mpa_len = be16_to_cpu(hdr->ctrl.mpa_len);

	switch (op) {
	case RDMAP_RDMA_WRITE:
		pr_info("siw: [QP %u]: %s(WRITE, DDP len %d): %08x %016llx\n",
			qp_id, string, ddp_data_len(op, mpa_len),
			hdr->rwrite.sink_stag, hdr->rwrite.sink_to);
		break;

	case RDMAP_RDMA_READ_REQ:
		pr_info("siw: [QP %u]: %s(RREQ, DDP len %d): %08x %08x %08x %08x %016llx %08x %08x %016llx\n",
			qp_id, string, ddp_data_len(op, mpa_len),
			be32_to_cpu(hdr->rreq.ddp_qn),
			be32_to_cpu(hdr->rreq.ddp_msn),
			be32_to_cpu(hdr->rreq.ddp_mo),
			be32_to_cpu(hdr->rreq.sink_stag),
			be64_to_cpu(hdr->rreq.sink_to),
			be32_to_cpu(hdr->rreq.read_size),
			be32_to_cpu(hdr->rreq.source_stag),
			be64_to_cpu(hdr->rreq.source_to));

		break;

	case RDMAP_RDMA_READ_RESP:
		pr_info("siw: [QP %u]: %s(RRESP, DDP len %d): %08x %016llx\n",
			qp_id, string, ddp_data_len(op, mpa_len),
			be32_to_cpu(hdr->rresp.sink_stag),
			be64_to_cpu(hdr->rresp.sink_to));
		break;

	case RDMAP_SEND:
		pr_info("siw: [QP %u]: %s(SEND, DDP len %d): %08x %08x %08x\n",
			qp_id, string, ddp_data_len(op, mpa_len),
			be32_to_cpu(hdr->send.ddp_qn),
			be32_to_cpu(hdr->send.ddp_msn),
			be32_to_cpu(hdr->send.ddp_mo));
		break;

	case RDMAP_SEND_INVAL:
		pr_info("siw: [QP %u]: %s(S_INV, DDP len %d): %08x %08x %08x %08x\n",
			qp_id, string, ddp_data_len(op, mpa_len),
			be32_to_cpu(hdr->send_inv.inval_stag),
			be32_to_cpu(hdr->send_inv.ddp_qn),
			be32_to_cpu(hdr->send_inv.ddp_msn),
			be32_to_cpu(hdr->send_inv.ddp_mo));
		break;

	case RDMAP_SEND_SE:
		pr_info("siw: [QP %u]: %s(S_SE, DDP len %d): %08x %08x %08x\n",
			qp_id, string, ddp_data_len(op, mpa_len),
			be32_to_cpu(hdr->send.ddp_qn),
			be32_to_cpu(hdr->send.ddp_msn),
			be32_to_cpu(hdr->send.ddp_mo));
		break;

	case RDMAP_SEND_SE_INVAL:
		pr_info("siw: [QP %u]: %s(S_SE_INV, DDP len %d): %08x %08x %08x %08x\n",
			qp_id, string, ddp_data_len(op, mpa_len),
			be32_to_cpu(hdr->send_inv.inval_stag),
			be32_to_cpu(hdr->send_inv.ddp_qn),
			be32_to_cpu(hdr->send_inv.ddp_msn),
			be32_to_cpu(hdr->send_inv.ddp_mo));
		break;

	case RDMAP_TERMINATE:
		pr_info("siw: [QP %u]: %s(TERM, DDP len %d):\n", qp_id, string,
			ddp_data_len(op, mpa_len));
		break;

	default:
		pr_info("siw: [QP %u]: %s (undefined opcode %d)", qp_id, string,
			op);
		break;
	}
}
