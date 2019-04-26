// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_cm.h"
#include "siw_verbs.h"
#include "siw_mem.h"
#include "siw_debug.h"

/*
 * ----------------------------
 * DDP reassembly for Softiwarp
 * ----------------------------
 * For the ordering of transmitted DDP segments, the relevant iWARP ordering
 * rules are as follows:
 *
 * - RDMAP (RFC 5040): Section 7.5, Rule 17:
 *   "RDMA Read Response Message processing at the Remote Peer (reading
 *    the specified Tagged Buffer) MUST be started only after the RDMA
 *    Read Request Message has been Delivered by the DDP layer (thus,
 *    all previous RDMA Messages have been properly submitted for
 *    ordered Placement)."
 *
 * - DDP (RFC 5041): Section 5.3:
 *   "At the Data Source, DDP:
 *    o MUST transmit DDP Messages in the order they were submitted to
 *      the DDP layer,
 *    o SHOULD transmit DDP Segments within a DDP Message in increasing
 *      MO order for Untagged DDP Messages, and in increasing TO order
 *      for Tagged DDP Messages."
 *
 * Combining these rules implies that, although RDMAP does not provide
 * ordering between operations that are generated from the two ends of an
 * RDMAP stream, DDP *must not* transmit an RDMA Read Response Message before
 * it has finished transmitting SQ operations that were already submitted
 * to the DDP layer. It follows that an iWARP transmitter must fully
 * serialize RDMAP messages belonging to the same QP.
 *
 * Given that a TCP socket receives DDP segments in peer transmit order,
 * we obtain the following ordering of received DDP segments:
 *
 * (i)  the received DDP segments of RDMAP messages for the same QP
 *      cannot be interleaved
 * (ii) the received DDP segments of a single RDMAP message *should*
 *      arrive in order.
 *
 * The Softiwarp transmitter obeys rule #2 in DDP Section 5.3.
 * With this property, the "should" becomes a "must" in (ii) above,
 * which simplifies DDP reassembly considerably.
 * The Softiwarp receiver currently relies on this property
 * and reports an error if DDP segments of the same RDMAP message
 * do not arrive in sequence.
 */

static inline int siw_crc_rxhdr(struct siw_iwarp_rx *ctx)
{
	crypto_shash_init(ctx->mpa_crc_hd);

	return siw_crc_array(ctx->mpa_crc_hd, (u8 *)&ctx->hdr,
			     ctx->fpdu_part_rcvd);
}

/*
 * siw_rx_umem()
 *
 * Receive data of @len into target referenced by @dest_addr.
 *
 * @rctx:	Receive Context
 * @umem:	siw representation of target memory
 * @dest_addr:	user virtual address
 * @len:	number of bytes to place
 */
static int siw_rx_umem(struct siw_iwarp_rx *rctx, struct siw_umem *umem,
		       u64 dest_addr, int len)
{
	int copied = 0;

	while (len) {
		struct page *p;
		int pg_off, bytes, rv;
		void *dest;

		p = siw_get_upage(umem, dest_addr);
		if (unlikely(!p)) {
			pr_warn("siw: %s: [QP %u]: bogus addr: %p, %p\n",
				__func__, rx_qp(rctx)->id,
				(void *)dest_addr, (void *)umem->fp_addr);
			/* siw internal error */
			rctx->skb_copied += copied;
			rctx->skb_new -= copied;
			copied = -EFAULT;

			goto out;
		}
		pg_off = dest_addr & ~PAGE_MASK;
		bytes = min(len, (int)PAGE_SIZE - pg_off);

		siw_dbg_qp(rx_qp(rctx), "page %p, bytes=%u\n", p, bytes);

		dest = kmap_atomic(p);

		rv = skb_copy_bits(rctx->skb, rctx->skb_offset, dest + pg_off,
				   bytes);
		kunmap_atomic(dest);

		if (likely(!rv)) {
			if (rctx->mpa_crc_hd)
				rv = siw_crc_page(rctx->mpa_crc_hd, p, pg_off,
						  bytes);

			rctx->skb_offset += bytes;
			copied += bytes;
			len -= bytes;
			dest_addr += bytes;
			pg_off = 0;
		}

		if (unlikely(rv)) {
			rctx->skb_copied += copied;
			rctx->skb_new -= copied;
			copied = -EFAULT;

			pr_warn("siw: [QP %u]: %s, len %d, page %p, rv %d\n",
				rx_qp(rctx)->id, __func__, len, p, rv);

			goto out;
		}
	}
	/*
	 * store chunk position for resume
	 */
	rctx->skb_copied += copied;
	rctx->skb_new -= copied;
out:
	return copied;
}

static int siw_rx_kva(struct siw_iwarp_rx *rctx, void *kva, int len)
{
	int rv;

	siw_dbg_qp(rx_qp(rctx), "kva: 0x%p, len: %u\n", kva, len);

	rv = skb_copy_bits(rctx->skb, rctx->skb_offset, kva, len);
	if (likely(!rv)) {
		rctx->skb_offset += len;
		rctx->skb_copied += len;
		rctx->skb_new -= len;
		if (rctx->mpa_crc_hd) {
			rv = siw_crc_array(rctx->mpa_crc_hd, kva, len);
			if (rv)
				goto error;
		}
		return len;
	}
	pr_warn("siw: [QP %u]: %s, len %d, kva 0x%p, rv %d\n",
		rx_qp(rctx)->id, __func__, len, kva, rv);
error:
	return rv;
}

static int siw_rx_pbl(struct siw_iwarp_rx *rctx, struct siw_mr *mr, u64 addr,
		      int len)
{
	struct siw_pbl *pbl = mr->pbl;
	u64 offset = addr - mr->mem.va;
	int copied = 0;

	while (len) {
		int bytes;
		u64 buf_addr =
			siw_pbl_get_buffer(pbl, offset, &bytes, &rctx->pbl_idx);
		if (!buf_addr)
			break;

		bytes = min(bytes, len);
		if (siw_rx_kva(rctx, (void *)buf_addr, bytes) == bytes) {
			copied += bytes;
			offset += bytes;
			len -= bytes;
		} else
			break;
	}
	return copied;
}

/*
 * siw_rresp_check_ntoh()
 *
 * Check incoming RRESP fragment header against expected
 * header values and update expected values for potential next
 * fragment.
 *
 * NOTE: This function must be called only if a RRESP DDP segment
 *       starts but not for fragmented consecutive pieces of an
 *       already started DDP segment.
 */
static inline int siw_rresp_check_ntoh(struct siw_iwarp_rx *rctx)
{
	struct iwarp_rdma_rresp *rresp = &rctx->hdr.rresp;
	struct siw_wqe *wqe = &rctx->wqe_active;
	enum ddp_ecode ecode;

	u32 sink_stag = be32_to_cpu(rresp->sink_stag);
	u64 sink_to = be64_to_cpu(rresp->sink_to);

	if (rctx->first_ddp_seg) {
		rctx->ddp_stag = wqe->sqe.sge[0].lkey;
		rctx->ddp_to = wqe->sqe.sge[0].laddr;
		rctx->pbl_idx = 0;
	}
	/* Below checks extend beyond the smeantics of DDP, and
	 * into RDMAP:
	 * We check if the read response matches exactly the
	 * read request which was send to the remote peer to
	 * trigger this read response. RFC5040/5041 do not
	 * always have a proper error code for the detected
	 * error cases. We choose 'base or bounds error' for
	 * cases where the inbound STag is valid, but offset
	 * or length do not match our response receive state.
	 */
	if (unlikely(rctx->ddp_stag != sink_stag)) {
		pr_warn("siw: [QP %u]: rresp stag: %08x != %08x\n",
			rx_qp(rctx)->id, sink_stag, rctx->ddp_stag);
		ecode = DDP_ECODE_T_INVALID_STAG;
		goto error;
	}
	if (unlikely(rctx->ddp_to != sink_to)) {
		pr_warn("siw: [QP %u]: rresp off: %016llx != %016llx\n",
			rx_qp(rctx)->id, (unsigned long long)sink_to,
			(unsigned long long)rctx->ddp_to);
		ecode = DDP_ECODE_T_BASE_BOUNDS;
		goto error;
	}
	if (unlikely(!rctx->more_ddp_segs &&
		     (wqe->processed + rctx->fpdu_part_rem != wqe->bytes))) {
		pr_warn("siw: [QP %u]: rresp len: %d != %d\n",
			rx_qp(rctx)->id,
			wqe->processed + rctx->fpdu_part_rem, wqe->bytes);
		ecode = DDP_ECODE_T_BASE_BOUNDS;
		goto error;
	}
	return 0;
error:
	siw_init_terminate(rx_qp(rctx), TERM_ERROR_LAYER_DDP,
			   DDP_ETYPE_TAGGED_BUF, ecode, 0);
	return -EINVAL;
}

/*
 * siw_write_check_ntoh()
 *
 * Check incoming WRITE fragment header against expected
 * header values and update expected values for potential next
 * fragment
 *
 * NOTE: This function must be called only if a WRITE DDP segment
 *       starts but not for fragmented consecutive pieces of an
 *       already started DDP segment.
 */
static inline int siw_write_check_ntoh(struct siw_iwarp_rx *rctx)
{
	struct iwarp_rdma_write *write = &rctx->hdr.rwrite;
	enum ddp_ecode ecode;

	u32 sink_stag = be32_to_cpu(write->sink_stag);
	u64 sink_to = be64_to_cpu(write->sink_to);

	if (rctx->first_ddp_seg) {
		rctx->ddp_stag = sink_stag;
		rctx->ddp_to = sink_to;
		rctx->pbl_idx = 0;
	} else {
		if (unlikely(rctx->ddp_stag != sink_stag)) {
			pr_warn("siw: [QP %u]: write stag: %08x != %08x\n",
				rx_qp(rctx)->id, sink_stag,
				rctx->ddp_stag);
			ecode = DDP_ECODE_T_INVALID_STAG;
			goto error;
		}
		if (unlikely(rctx->ddp_to != sink_to)) {
			pr_warn("siw: [QP %u]: write off: %016llx != %016llx\n",
				rx_qp(rctx)->id,
				(unsigned long long)sink_to,
				(unsigned long long)rctx->ddp_to);
			ecode = DDP_ECODE_T_BASE_BOUNDS;
			goto error;
		}
	}
	return 0;
error:
	siw_init_terminate(rx_qp(rctx), TERM_ERROR_LAYER_DDP,
			   DDP_ETYPE_TAGGED_BUF, ecode, 0);
	return -EINVAL;
}

/*
 * siw_send_check_ntoh()
 *
 * Check incoming SEND fragment header against expected
 * header values and update expected MSN if no next
 * fragment expected
 *
 * NOTE: This function must be called only if a SEND DDP segment
 *       starts but not for fragmented consecutive pieces of an
 *       already started DDP segment.
 */
static inline int siw_send_check_ntoh(struct siw_iwarp_rx *rctx)
{
	struct iwarp_send_inv *send = &rctx->hdr.send_inv;
	struct siw_wqe *wqe = &rctx->wqe_active;
	enum ddp_ecode ecode;

	u32 ddp_msn = be32_to_cpu(send->ddp_msn);
	u32 ddp_mo = be32_to_cpu(send->ddp_mo);
	u32 ddp_qn = be32_to_cpu(send->ddp_qn);

	if (unlikely(ddp_qn != RDMAP_UNTAGGED_QN_SEND)) {
		pr_warn("siw: [QP %u]: invalid ddp qn %d for send\n",
			rx_qp(rctx)->id, ddp_qn);
		ecode = DDP_ECODE_UT_INVALID_QN;
		goto error;
	}
	if (unlikely(ddp_msn != rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND])) {
		pr_warn("siw: [QP %u]: send msn: %u != %u\n",
			rx_qp(rctx)->id, ddp_msn,
			rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]);
		ecode = DDP_ECODE_UT_INVALID_MSN_RANGE;
		goto error;
	}
	if (unlikely(ddp_mo != wqe->processed)) {
		pr_warn("siw: [QP %u], send mo: %u != %u\n",
			rx_qp(rctx)->id, ddp_mo, wqe->processed);
		ecode = DDP_ECODE_UT_INVALID_MO;
		goto error;
	}
	if (rctx->first_ddp_seg) {
		/* initialize user memory write position */
		rctx->sge_idx = 0;
		rctx->sge_off = 0;
		rctx->pbl_idx = 0;

		/* only valid for SEND_INV and SEND_SE_INV operations */
		rctx->inval_stag = be32_to_cpu(send->inval_stag);
	}
	if (unlikely(wqe->bytes < wqe->processed + rctx->fpdu_part_rem)) {
		siw_dbg_qp(rx_qp(rctx), "receive space short: %d - %d < %d\n",
			   wqe->bytes, wqe->processed, rctx->fpdu_part_rem);
		wqe->wc_status = SIW_WC_LOC_LEN_ERR;
		ecode = DDP_ECODE_UT_INVALID_MSN_NOBUF;
		goto error;
	}
	return 0;
error:
	siw_init_terminate(rx_qp(rctx), TERM_ERROR_LAYER_DDP,
			   DDP_ETYPE_UNTAGGED_BUF, ecode, 0);
	return -EINVAL;
}

static struct siw_wqe *siw_rqe_get(struct siw_qp *qp)
{
	struct siw_rqe *rqe;
	struct siw_srq *srq;
	struct siw_wqe *wqe = NULL;
	bool srq_event = false;
	unsigned long flags;

	srq = qp->srq;
	if (srq) {
		spin_lock_irqsave(&srq->lock, flags);
		if (unlikely(!srq->num_rqe))
			goto out;

		rqe = &srq->recvq[srq->rq_get % srq->num_rqe];
	} else {
		if (unlikely(!qp->recvq))
			goto out;

		rqe = &qp->recvq[qp->rq_get % qp->attrs.rq_size];
	}
	if (likely(rqe->flags == SIW_WQE_VALID)) {
		int num_sge = rqe->num_sge;

		if (likely(num_sge <= SIW_MAX_SGE)) {
			int i = 0;

			wqe = rx_wqe(qp);
			rx_type(wqe) = SIW_OP_RECEIVE;
			wqe->wr_status = SIW_WR_INPROGRESS;
			wqe->bytes = 0;
			wqe->processed = 0;

			wqe->rqe.id = rqe->id;
			wqe->rqe.num_sge = num_sge;

			while (i < num_sge) {
				wqe->rqe.sge[i].laddr = rqe->sge[i].laddr;
				wqe->rqe.sge[i].lkey = rqe->sge[i].lkey;
				wqe->rqe.sge[i].length = rqe->sge[i].length;
				wqe->bytes += wqe->rqe.sge[i].length;
				wqe->mem[i] = NULL;
				i++;
			}
			/* can be re-used by appl */
			smp_store_mb(rqe->flags, 0);
		} else {
			siw_dbg_qp(qp, "too many sge's: %d\n", rqe->num_sge);
			if (srq)
				spin_unlock_irqrestore(&srq->lock, flags);
			return NULL;
		}
		if (!srq) {
			qp->rq_get++;
		} else {
			if (srq->armed) {
				/* Test SRQ limit */
				u32 off = (srq->rq_get + srq->limit) %
					  srq->num_rqe;
				struct siw_rqe *rqe2 = &srq->recvq[off];

				if (!(rqe2->flags & SIW_WQE_VALID)) {
					srq->armed = 0;
					srq_event = true;
				}
			}
			srq->rq_get++;
		}
	}
out:
	if (srq) {
		spin_unlock_irqrestore(&srq->lock, flags);
		if (srq_event)
			siw_srq_event(srq, IB_EVENT_SRQ_LIMIT_REACHED);
	}
	return wqe;
}

/*
 * siw_proc_send:
 *
 * Process one incoming SEND and place data into memory referenced by
 * receive wqe.
 *
 * Function supports partially received sends (suspending/resuming
 * current receive wqe processing)
 *
 * return value:
 *	0:       reached the end of a DDP segment
 *	-EAGAIN: to be called again to finish the DDP segment
 */
int siw_proc_send(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe *wqe;
	struct siw_sge *sge;
	u32 data_bytes; /* all data bytes available */
	u32 rcvd_bytes; /* sum of data bytes rcvd */
	int rv = 0;

	if (rctx->first_ddp_seg) {
		wqe = siw_rqe_get(qp);
		if (unlikely(!wqe)) {
			siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
					   DDP_ETYPE_UNTAGGED_BUF,
					   DDP_ECODE_UT_INVALID_MSN_NOBUF, 0);
			return -ENOENT;
		}
	} else {
		wqe = rx_wqe(qp);
	}
	if (rctx->state == SIW_GET_DATA_START) {
		rv = siw_send_check_ntoh(rctx);
		if (unlikely(rv)) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			return rv;
		}
		if (!rctx->fpdu_part_rem) /* zero length SEND */
			return 0;
	}
	data_bytes = min(rctx->fpdu_part_rem, rctx->skb_new);
	rcvd_bytes = 0;

	/* A zero length SEND will skip below loop */
	while (data_bytes) {
		struct siw_pd *pd;
		struct siw_mr *mr;
		struct siw_mem **mem;
		u32 sge_bytes; /* data bytes avail for SGE */

		sge = &wqe->rqe.sge[rctx->sge_idx];

		if (!sge->length) {
			/* just skip empty sge's */
			rctx->sge_idx++;
			rctx->sge_off = 0;
			rctx->pbl_idx = 0;
			continue;
		}
		sge_bytes = min(data_bytes, sge->length - rctx->sge_off);
		mem = &wqe->mem[rctx->sge_idx];

		/*
		 * check with QP's PD if no SRQ present, SRQ's PD otherwise
		 */
		pd = qp->srq == NULL ? qp->pd : qp->srq->pd;

		rv = siw_check_sge(pd, sge, mem, IB_ACCESS_LOCAL_WRITE,
				   rctx->sge_off, sge_bytes);
		if (unlikely(rv)) {
			siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
					   DDP_ETYPE_CATASTROPHIC,
					   DDP_ECODE_CATASTROPHIC, 0);

			siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);
			break;
		}
		mr = siw_mem2mr(*mem);
		if (mr->mem_obj == NULL)
			rv = siw_rx_kva(rctx,
					(void *)(sge->laddr + rctx->sge_off),
					sge_bytes);
		else if (!mr->mem.is_pbl)
			rv = siw_rx_umem(rctx, mr->umem,
					 sge->laddr + rctx->sge_off, sge_bytes);
		else
			rv = siw_rx_pbl(rctx, mr, sge->laddr + rctx->sge_off,
					sge_bytes);

		if (unlikely(rv != sge_bytes)) {
			wqe->processed += rcvd_bytes;

			siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
					   DDP_ETYPE_CATASTROPHIC,
					   DDP_ECODE_CATASTROPHIC, 0);
			return -EINVAL;
		}
		rctx->sge_off += rv;

		if (rctx->sge_off == sge->length) {
			rctx->sge_idx++;
			rctx->sge_off = 0;
			rctx->pbl_idx = 0;
		}
		data_bytes -= rv;
		rcvd_bytes += rv;

		rctx->fpdu_part_rem -= rv;
		rctx->fpdu_part_rcvd += rv;
	}
	wqe->processed += rcvd_bytes;

	if (!rctx->fpdu_part_rem)
		return 0;

	return (rv < 0) ? rv : -EAGAIN;
}

/*
 * siw_proc_write:
 *
 * Place incoming WRITE after referencing and checking target buffer

 * Function supports partially received WRITEs (suspending/resuming
 * current receive processing)
 *
 * return value:
 *	0:       reached the end of a DDP segment
 *	-EAGAIN: to be called again to finish the DDP segment
 */
int siw_proc_write(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_device *dev = qp->sdev;
	struct siw_mem *mem;
	struct siw_mr *mr;
	int bytes, rv;

	if (rctx->state == SIW_GET_DATA_START) {
		if (!rctx->fpdu_part_rem) /* zero length WRITE */
			return 0;

		rv = siw_write_check_ntoh(rctx);
		if (unlikely(rv)) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			return rv;
		}
	}
	bytes = min(rctx->fpdu_part_rem, rctx->skb_new);

	if (rctx->first_ddp_seg) {
		struct siw_wqe *wqe = rx_wqe(qp);

		rx_mem(qp) = siw_mem_id2obj(dev, rctx->ddp_stag >> 8);
		if (unlikely(!rx_mem(qp))) {
			siw_dbg_qp(qp,
				   "sink stag not found/invalid, stag 0x%08x\n",
				   rctx->ddp_stag);

			siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
					   DDP_ETYPE_TAGGED_BUF,
					   DDP_ECODE_T_INVALID_STAG, 0);
			return -EINVAL;
		}
		wqe->rqe.num_sge = 1;
		rx_type(wqe) = SIW_OP_WRITE;
		wqe->wr_status = SIW_WR_INPROGRESS;
	}
	mem = rx_mem(qp);

	/*
	 * Check if application re-registered memory with different
	 * key field of STag.
	 */
	if (unlikely(mem->stag != rctx->ddp_stag)) {
		siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
				   DDP_ETYPE_TAGGED_BUF,
				   DDP_ECODE_T_INVALID_STAG, 0);
		return -EINVAL;
	}
	rv = siw_check_mem(qp->pd, mem, rctx->ddp_to + rctx->fpdu_part_rcvd,
			   IB_ACCESS_REMOTE_WRITE, bytes);
	if (unlikely(rv)) {
		siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
				   DDP_ETYPE_TAGGED_BUF, siw_tagged_error(-rv),
				   0);

		siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);

		return -EINVAL;
	}

	mr = siw_mem2mr(mem);
	if (mr->mem_obj == NULL)
		rv = siw_rx_kva(rctx,
				(void *)(rctx->ddp_to + rctx->fpdu_part_rcvd),
				bytes);
	else if (!mr->mem.is_pbl)
		rv = siw_rx_umem(rctx, mr->umem,
				 rctx->ddp_to + rctx->fpdu_part_rcvd, bytes);
	else
		rv = siw_rx_pbl(rctx, mr, rctx->ddp_to + rctx->fpdu_part_rcvd,
				bytes);

	if (unlikely(rv != bytes)) {
		siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
				   DDP_ETYPE_CATASTROPHIC,
				   DDP_ECODE_CATASTROPHIC, 0);
		return -EINVAL;
	}
	rctx->fpdu_part_rem -= rv;
	rctx->fpdu_part_rcvd += rv;

	if (!rctx->fpdu_part_rem) {
		rctx->ddp_to += rctx->fpdu_part_rcvd;
		return 0;
	}
	return -EAGAIN;
}

/*
 * Inbound RREQ's cannot carry user data.
 */
int siw_proc_rreq(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	if (!rctx->fpdu_part_rem)
		return 0;

	pr_warn("siw: [QP %u]: rreq with mpa len %d\n", qp->id,
		be16_to_cpu(rctx->hdr.ctrl.mpa_len));

	return -EPROTO;
}

/*
 * siw_init_rresp:
 *
 * Process inbound RDMA READ REQ. Produce a pseudo READ RESPONSE WQE.
 * Put it at the tail of the IRQ, if there is another WQE currently in
 * transmit processing. If not, make it the current WQE to be processed
 * and schedule transmit processing.
 *
 * Can be called from softirq context and from process
 * context (RREAD socket loopback case!)
 *
 * return value:
 *	0:      success,
 *		failure code otherwise
 */

static int siw_init_rresp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe *tx_work = tx_wqe(qp);
	struct siw_sqe *resp;

	uint64_t raddr = be64_to_cpu(rctx->hdr.rreq.sink_to),
		 laddr = be64_to_cpu(rctx->hdr.rreq.source_to);
	uint32_t length = be32_to_cpu(rctx->hdr.rreq.read_size),
		 lkey = be32_to_cpu(rctx->hdr.rreq.source_stag),
		 rkey = be32_to_cpu(rctx->hdr.rreq.sink_stag),
		 msn = be32_to_cpu(rctx->hdr.rreq.ddp_msn);

	int run_sq = 1, rv = 0;
	unsigned long flags;

	if (unlikely(msn != rctx->ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ])) {
		siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
				   DDP_ETYPE_UNTAGGED_BUF,
				   DDP_ECODE_UT_INVALID_MSN_RANGE, 0);
		return -EPROTO;
	}
	spin_lock_irqsave(&qp->sq_lock, flags);

	if (tx_work->wr_status == SIW_WR_IDLE) {
		/*
		 * immediately schedule READ response w/o
		 * consuming IRQ entry: IRQ must be empty.
		 */
		tx_work->processed = 0;
		tx_work->mem[0] = NULL;
		tx_work->wr_status = SIW_WR_QUEUED;
		resp = &tx_work->sqe;
	} else {
		resp = irq_alloc_free(qp);
		run_sq = 0;
	}
	if (likely(resp)) {
		resp->opcode = SIW_OP_READ_RESPONSE;

		resp->sge[0].length = length;
		resp->sge[0].laddr = laddr;
		resp->sge[0].lkey = lkey;

		/* Keep aside message sequence number for potential
		 * error reporting during Read Response generation.
		 */
		resp->sge[1].length = msn;

		resp->raddr = raddr;
		resp->rkey = rkey;
		resp->num_sge = length ? 1 : 0;

		/* RRESP now valid as current TX wqe or placed into IRQ */
		smp_store_mb(resp->flags, SIW_WQE_VALID);
	} else {
		pr_warn("siw: [QP %u]: irq %d exceeded %d\n", qp->id,
			qp->irq_put % qp->attrs.irq_size, qp->attrs.irq_size);

		siw_init_terminate(qp, TERM_ERROR_LAYER_RDMAP,
				   RDMAP_ETYPE_REMOTE_OPERATION,
				   RDMAP_ECODE_CATASTROPHIC_STREAM, 0);
		rv = -EPROTO;
	}

	spin_unlock_irqrestore(&qp->sq_lock, flags);

	if (run_sq)
		rv = siw_sq_start(qp);

	return rv;
}

/*
 * Only called at start of Read.Resonse processing.
 * Transfer pending Read from tip of ORQ into currrent rx wqe,
 * but keep ORQ entry valid until Read.Response processing done.
 * No Queue locking needed.
 */
static int siw_orqe_start_rx(struct siw_qp *qp)
{
	struct siw_sqe *orqe;
	struct siw_wqe *wqe = NULL;

	/* make sure ORQ indices are current */
	smp_mb();

	orqe = orq_get_current(qp);
	if (READ_ONCE(orqe->flags) & SIW_WQE_VALID) {
		wqe = rx_wqe(qp);
		wqe->sqe.id = orqe->id;
		wqe->sqe.opcode = orqe->opcode;
		wqe->sqe.sge[0].laddr = orqe->sge[0].laddr;
		wqe->sqe.sge[0].lkey = orqe->sge[0].lkey;
		wqe->sqe.sge[0].length = orqe->sge[0].length;
		wqe->sqe.flags = orqe->flags;
		wqe->sqe.num_sge = 1;
		wqe->bytes = orqe->sge[0].length;
		wqe->processed = 0;
		wqe->mem[0] = NULL;
		/* make sure WQE is completely written before valid */
		smp_wmb();
		wqe->wr_status = SIW_WR_INPROGRESS;

		return 0;
	}
	return -EPROTO;
}

/*
 * siw_proc_rresp:
 *
 * Place incoming RRESP data into memory referenced by RREQ WQE
 * which is at the tip of the ORQ
 *
 * Function supports partially received RRESP's (suspending/resuming
 * current receive processing)
 */
int siw_proc_rresp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe *wqe = rx_wqe(qp);
	struct siw_mem **mem;
	struct siw_sge *sge;
	struct siw_mr *mr;
	int bytes, rv;

	if (rctx->first_ddp_seg) {
		if (unlikely(wqe->wr_status != SIW_WR_IDLE)) {
			pr_warn("siw: [QP %u]: proc RRESP: status %d, op %d\n",
				qp->id, wqe->wr_status, wqe->sqe.opcode);
			rv = -EPROTO;
			goto error_term;
		}
		/*
		 * fetch pending RREQ from orq
		 */
		rv = siw_orqe_start_rx(qp);
		if (rv) {
			pr_warn("siw: [QP %u]: ORQ empty at idx %d\n",
				qp->id, qp->orq_get % qp->attrs.orq_size);
			goto error_term;
		}
		rv = siw_rresp_check_ntoh(rctx);
		if (unlikely(rv)) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			return rv;
		}
	} else {
		if (unlikely(wqe->wr_status != SIW_WR_INPROGRESS)) {
			pr_warn("siw: [QP %u]: resume RRESP: status %d\n",
				qp->id, wqe->wr_status);
			rv = -EPROTO;
			goto error_term;
		}
	}
	if (!rctx->fpdu_part_rem) /* zero length RRESPONSE */
		return 0;

	sge = wqe->sqe.sge; /* there is only one */
	mem = &wqe->mem[0];

	if (!(*mem)) {
		/*
		 * check target memory which resolves memory on first fragment
		 */
		rv = siw_check_sge(qp->pd, sge, mem, IB_ACCESS_LOCAL_WRITE, 0,
				   wqe->bytes);
		if (unlikely(rv)) {
			siw_dbg_qp(qp, "target mem check: %d\n", rv);
			wqe->wc_status = SIW_WC_LOC_PROT_ERR;

			siw_init_terminate(qp, TERM_ERROR_LAYER_DDP,
					   DDP_ETYPE_TAGGED_BUF,
					   siw_tagged_error(-rv), 0);

			siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);

			return -EINVAL;
		}
	}
	bytes = min(rctx->fpdu_part_rem, rctx->skb_new);

	mr = siw_mem2mr(*mem);
	if (mr->mem_obj == NULL)
		rv = siw_rx_kva(rctx, (void *)(sge->laddr + wqe->processed),
				bytes);
	else if (!mr->mem.is_pbl)
		rv = siw_rx_umem(rctx, mr->umem, sge->laddr + wqe->processed,
				 bytes);
	else
		rv = siw_rx_pbl(rctx, mr, sge->laddr + wqe->processed, bytes);
	if (rv != bytes) {
		wqe->wc_status = SIW_WC_GENERAL_ERR;
		rv = -EINVAL;
		goto error_term;
	}
	rctx->fpdu_part_rem -= rv;
	rctx->fpdu_part_rcvd += rv;
	wqe->processed += rv;

	if (!rctx->fpdu_part_rem) {
		rctx->ddp_to += rctx->fpdu_part_rcvd;
		return 0;
	}
	return -EAGAIN;

error_term:
	siw_init_terminate(qp, TERM_ERROR_LAYER_DDP, DDP_ETYPE_CATASTROPHIC,
			   DDP_ECODE_CATASTROPHIC, 0);
	return rv;
}

int siw_proc_terminate(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct sk_buff *skb = rctx->skb;
	struct iwarp_terminate *term = &rctx->hdr.terminate;
	union iwarp_hdr term_info;
	u8 *infop = (u8 *)&term_info;
	enum rdma_opcode op;
	u16 to_copy = sizeof(struct iwarp_ctrl);

	pr_info("siw: [QP %u]: got TERMINATE. layer %d, type %d, code %d\n",
		qp->id, __rdmap_term_layer(term), __rdmap_term_etype(term),
		__rdmap_term_ecode(term));

	if (be32_to_cpu(term->ddp_qn) != RDMAP_UNTAGGED_QN_TERMINATE ||
	    be32_to_cpu(term->ddp_msn) !=
		    qp->rx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_TERMINATE] ||
	    be32_to_cpu(term->ddp_mo) != 0) {
		pr_warn("siw: [QP %u]: received malformed TERM\n", qp->id);
		pr_warn("     [QN x%08x, MSN x%08x, MO x%08x]\n",
			be32_to_cpu(term->ddp_qn), be32_to_cpu(term->ddp_msn),
			be32_to_cpu(term->ddp_mo));
		return -ECONNRESET;
	}
	/*
	 * Receive remaining pieces of TERM if indicated
	 */
	if (!term->flag_m)
		return -ECONNRESET;

	/* Do not take the effort to reassemble a network fragmented
	 * TERM message
	 */
	if (rctx->skb_new < sizeof(struct iwarp_ctrl_tagged))
		return -ECONNRESET;

	memset(infop, 0, sizeof(term_info));

	skb_copy_bits(skb, rctx->skb_offset, infop, to_copy);

	op = __rdmap_get_opcode(&term_info.ctrl);
	if (op >= RDMAP_TERMINATE)
		goto out;

	infop += to_copy;
	rctx->skb_offset += to_copy;
	rctx->skb_new -= to_copy;
	rctx->skb_copied += to_copy;
	rctx->fpdu_part_rcvd += to_copy;
	rctx->fpdu_part_rem -= to_copy;

	to_copy = iwarp_pktinfo[op].hdr_len - to_copy;

	/* Again, no network fragmented TERM's */
	if (to_copy + MPA_CRC_SIZE > rctx->skb_new)
		return -ECONNRESET;

	skb_copy_bits(skb, rctx->skb_offset, infop, to_copy);

	if (term->flag_m) {
		/* Adjust len to packet hdr print function */
		u32 mpa_len = be16_to_cpu(term_info.ctrl.mpa_len);

		mpa_len += iwarp_pktinfo[op].hdr_len - MPA_HDR_SIZE;
		term_info.ctrl.mpa_len = cpu_to_be16(mpa_len);
	}
	if (term->flag_r) {
		if (term->flag_m)
			siw_print_hdr(
				&term_info, qp->id,
				"TERMINATE reports RDMAP HDR (len valid): ");
		else
			siw_print_hdr(
				&term_info, qp->id,
				"TERMINATE reports RDMAP HDR (len invalid): ");
	} else if (term->flag_d) {
		if (term->flag_m)
			siw_print_hdr(
				&term_info, qp->id,
				"TERMINATE reports DDP HDR (len valid): ");
		else
			siw_print_hdr(
				&term_info, qp->id,
				"TERMINATE reports DDP HDR (len invalid): ");
	}
out:
	rctx->skb_new -= to_copy;
	rctx->skb_offset += to_copy;
	rctx->skb_copied += to_copy;
	rctx->fpdu_part_rcvd += to_copy;
	rctx->fpdu_part_rem -= to_copy;

	return -ECONNRESET;
}

static int siw_get_trailer(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct sk_buff *skb = rctx->skb;
	u8 *tbuf = (u8 *)&rctx->trailer.crc - rctx->pad;
	int avail;

	avail = min(rctx->skb_new, rctx->fpdu_part_rem);

	siw_dbg_qp(qp, "expected %d, available %d, pad %d, skb_new %d\n",
		   rctx->fpdu_part_rem, avail, rctx->pad, rctx->skb_new);

	skb_copy_bits(skb, rctx->skb_offset, tbuf + rctx->fpdu_part_rcvd,
		      avail);

	rctx->fpdu_part_rcvd += avail;
	rctx->fpdu_part_rem -= avail;

	rctx->skb_new -= avail;
	rctx->skb_offset += avail;
	rctx->skb_copied += avail;

	if (!rctx->fpdu_part_rem) {
		__be32 crc_in, crc_own = 0;
		/*
		 * check crc if required
		 */
		if (!rctx->mpa_crc_hd)
			return 0;

		if (rctx->pad &&
		    siw_crc_array(rctx->mpa_crc_hd, tbuf, rctx->pad) != 0)
			return -EINVAL;

		crypto_shash_final(rctx->mpa_crc_hd, (u8 *)&crc_own);

		/*
		 * CRC32 is computed, transmitted and received directly in NBO,
		 * so there's never a reason to convert byte order.
		 */
		crc_in = rctx->trailer.crc;

		if (unlikely(crc_in != crc_own)) {
			pr_warn("siw: crc error. in: %08x, computed %08x\n",
				crc_in, crc_own);

			siw_init_terminate(qp, TERM_ERROR_LAYER_LLP,
					   LLP_ETYPE_MPA,
					   LLP_ECODE_RECEIVED_CRC, 0);
			return -EINVAL;
		}
		return 0;
	}
	return -EAGAIN;
}

#define MIN_DDP_HDR sizeof(struct iwarp_ctrl_tagged)

static int siw_get_hdr(struct siw_iwarp_rx *rctx)
{
	struct sk_buff *skb = rctx->skb;
	struct iwarp_ctrl *c_hdr = &rctx->hdr.ctrl;
	u8 opcode;
	int bytes;

	if (rctx->fpdu_part_rcvd < MIN_DDP_HDR) {
		/*
		 * copy a mimimum sized (tagged) DDP frame control part
		 */
		bytes = min_t(int, rctx->skb_new,
			      MIN_DDP_HDR - rctx->fpdu_part_rcvd);

		skb_copy_bits(skb, rctx->skb_offset,
			      (char *)c_hdr + rctx->fpdu_part_rcvd, bytes);

		rctx->fpdu_part_rcvd += bytes;

		rctx->skb_new -= bytes;
		rctx->skb_offset += bytes;
		rctx->skb_copied += bytes;

		if (rctx->fpdu_part_rcvd < MIN_DDP_HDR)
			return -EAGAIN;

		if (unlikely(__ddp_get_version(c_hdr) != DDP_VERSION)) {
			enum ddp_etype etype;
			enum ddp_ecode ecode;

			pr_warn("siw: received ddp version unsupported %d\n",
				__ddp_get_version(c_hdr));

			if (c_hdr->ddp_rdmap_ctrl & DDP_FLAG_TAGGED) {
				etype = DDP_ETYPE_TAGGED_BUF;
				ecode = DDP_ECODE_T_VERSION;
			} else {
				etype = DDP_ETYPE_UNTAGGED_BUF;
				ecode = DDP_ECODE_UT_VERSION;
			}
			siw_init_terminate(rx_qp(rctx), TERM_ERROR_LAYER_DDP,
					   etype, ecode, 0);
			return -EINVAL;
		}
		if (unlikely(__rdmap_get_version(c_hdr) != RDMAP_VERSION)) {
			pr_warn("siw: received rdmap version unsupported %d\n",
				__rdmap_get_version(c_hdr));

			siw_init_terminate(rx_qp(rctx), TERM_ERROR_LAYER_RDMAP,
					   RDMAP_ETYPE_REMOTE_OPERATION,
					   RDMAP_ECODE_VERSION, 0);
			return -EINVAL;
		}
		opcode = __rdmap_get_opcode(c_hdr);

		if (opcode > RDMAP_TERMINATE) {
			pr_warn("siw: received unknown packet type %d\n",
				opcode);

			siw_init_terminate(rx_qp(rctx), TERM_ERROR_LAYER_RDMAP,
					   RDMAP_ETYPE_REMOTE_OPERATION,
					   RDMAP_ECODE_OPCODE, 0);
			return -EINVAL;
		}
		siw_dbg_qp(rx_qp(rctx), "new header, opcode %d\n", opcode);
	} else {
		opcode = __rdmap_get_opcode(c_hdr);
	}

	/*
	 * Figure out len of current hdr: variable length of
	 * iwarp hdr may force us to copy hdr information in
	 * two steps. Only tagged DDP messages are already
	 * completely received.
	 */
	if (iwarp_pktinfo[opcode].hdr_len > sizeof(struct iwarp_ctrl_tagged)) {
		bytes = iwarp_pktinfo[opcode].hdr_len - MIN_DDP_HDR;

		if (rctx->skb_new < bytes)
			return -EAGAIN;

		skb_copy_bits(skb, rctx->skb_offset,
			      (char *)c_hdr + rctx->fpdu_part_rcvd, bytes);

		rctx->fpdu_part_rcvd += bytes;

		rctx->skb_new -= bytes;
		rctx->skb_offset += bytes;
		rctx->skb_copied += bytes;
	}
	/*
	 * DDP/RDMAP header receive completed. Check if the current
	 * DDP segment starts a new RDMAP message or continues a previously
	 * started RDMAP message.
	 *
	 * Note well from the comments on DDP reassembly:
	 * - Support for unordered reception of DDP segments
	 *   (or FPDUs) from different RDMAP messages is not needed.
	 * - Unordered reception of DDP segments of the same
	 *   RDMAP message is not supported. It is probably not
	 *   needed with most peers.
	 */
	siw_dprint_hdr(&rctx->hdr, rx_qp(rctx)->id, "HDR received");

	if (rctx->more_ddp_segs) {
		rctx->first_ddp_seg = 0;
		if (rctx->prev_rdmap_opcode != opcode) {
			pr_warn("siw: packet intersection: %d : %d\n",
				rctx->prev_rdmap_opcode, opcode);
			return -EPROTO;
		}
	} else {
		rctx->prev_rdmap_opcode = opcode;
		rctx->first_ddp_seg = 1;
	}
	rctx->more_ddp_segs = c_hdr->ddp_rdmap_ctrl & DDP_FLAG_LAST ? 0 : 1;

	return 0;
}

static inline int siw_fpdu_payload_len(struct siw_iwarp_rx *rctx)
{
	return be16_to_cpu(rctx->hdr.ctrl.mpa_len) - rctx->fpdu_part_rcvd +
	       MPA_HDR_SIZE;
}

static inline int siw_fpdu_trailer_len(struct siw_iwarp_rx *rctx)
{
	int mpa_len = be16_to_cpu(rctx->hdr.ctrl.mpa_len) + MPA_HDR_SIZE;

	return MPA_CRC_SIZE + (-mpa_len & 0x3);
}

static int siw_check_tx_fence(struct siw_qp *qp)
{
	struct siw_wqe *tx_waiting = tx_wqe(qp);
	struct siw_sqe *rreq;
	int resume_tx = 0, rv = 0;
	unsigned long flags;

	spin_lock_irqsave(&qp->orq_lock, flags);

	rreq = orq_get_current(qp);

	/* free current orq entry */
	WRITE_ONCE(rreq->flags, 0);

	if (qp->tx_ctx.orq_fence) {
		if (unlikely(tx_waiting->wr_status != SIW_WR_QUEUED)) {
			pr_warn("siw: [QP %u]: fence resume: bad status %d\n",
				qp->id, tx_waiting->wr_status);
			rv = -EPROTO;
			goto out;
		}
		/* resume SQ processing */
		if (tx_waiting->sqe.opcode == SIW_OP_READ ||
		    tx_waiting->sqe.opcode == SIW_OP_READ_LOCAL_INV) {
			rreq = orq_get_tail(qp);
			if (unlikely(!rreq)) {
				pr_warn("siw: [QP %u]: no ORQE\n", qp->id);
				rv = -EPROTO;
				goto out;
			}
			siw_read_to_orq(rreq, &tx_waiting->sqe);

			qp->orq_put++;
			qp->tx_ctx.orq_fence = 0;
			resume_tx = 1;

		} else if (siw_orq_empty(qp)) {
			qp->tx_ctx.orq_fence = 0;
			resume_tx = 1;
		} else {
			pr_warn("siw: [QP %u]: fence resume: orq idx: %d:%d\n",
				qp->id, qp->orq_get, qp->orq_put);
			rv = -EPROTO;
		}
	}
	qp->orq_get++;
out:
	spin_unlock_irqrestore(&qp->orq_lock, flags);

	if (resume_tx)
		rv = siw_sq_start(qp);

	return rv;
}

/*
 * siw_rdmap_complete()
 *
 * Complete processing of an RDMA message after receiving all
 * DDP segmens or ABort processing after encountering error case.
 *
 *   o SENDs + RRESPs will need for completion,
 *   o RREQs need for  READ RESPONSE initialization
 *   o WRITEs need memory dereferencing
 *
 * TODO: Failed WRITEs need local error to be surfaced.
 */
static inline int siw_rdmap_complete(struct siw_qp *qp, int error)
{
	struct siw_iwarp_rx *rctx = &qp->rx_ctx;
	struct siw_wqe *wqe = rx_wqe(qp);
	enum siw_wc_status wc_status = wqe->wc_status;

	u8 opcode = __rdmap_get_opcode(&rctx->hdr.ctrl);
	int rv = 0;

	switch (opcode) {
	case RDMAP_SEND_SE:
	case RDMAP_SEND_SE_INVAL:
		wqe->rqe.flags |= SIW_WQE_SOLICITED;
	case RDMAP_SEND:
	case RDMAP_SEND_INVAL:
		if (wqe->wr_status == SIW_WR_IDLE)
			break;

		rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]++;

		if (error != 0 && wc_status == SIW_WC_SUCCESS)
			wc_status = SIW_WC_GENERAL_ERR;
		/*
		 * Handle STag invalidation request
		 */
		if (wc_status == SIW_WC_SUCCESS &&
		    (opcode == RDMAP_SEND_INVAL ||
		     opcode == RDMAP_SEND_SE_INVAL)) {
			rv = siw_invalidate_stag(qp->pd, rctx->inval_stag);
			if (rv) {
				siw_init_terminate(
					qp, TERM_ERROR_LAYER_RDMAP,
					rv == -EACCES ?
						RDMAP_ETYPE_REMOTE_PROTECTION :
						RDMAP_ETYPE_REMOTE_OPERATION,
					RDMAP_ECODE_CANNOT_INVALIDATE, 0);

				wc_status = SIW_WC_REM_INV_REQ_ERR;
			}
			rv = siw_rqe_complete(qp, &wqe->rqe, wqe->processed,
					      rv ? 0 : rctx->inval_stag,
					      wc_status);
		} else {
			rv = siw_rqe_complete(qp, &wqe->rqe, wqe->processed,
					      0, wc_status);
		}
		siw_wqe_put_mem(wqe, SIW_OP_RECEIVE);

		break;

	case RDMAP_RDMA_READ_RESP:
		if (wqe->wr_status == SIW_WR_IDLE)
			break;

		if (error != 0) {
			if (rctx->state == SIW_GET_HDR || error == -ENODATA)
				/*  eventual RREQ in ORQ left untouched */
				break;

			if (wc_status == SIW_WC_SUCCESS)
				wc_status = SIW_WC_GENERAL_ERR;
		} else if (qp->kernel_verbs &&
			   rx_type(wqe) == SIW_OP_READ_LOCAL_INV) {
			/*
			 * Handle any STag invalidation request
			 */
			rv = siw_invalidate_stag(qp->pd, wqe->sqe.sge[0].lkey);
			if (rv) {
				siw_init_terminate(qp, TERM_ERROR_LAYER_RDMAP,
						   RDMAP_ETYPE_CATASTROPHIC,
						   RDMAP_ECODE_UNSPECIFIED, 0);

				if (wc_status == SIW_WC_SUCCESS) {
					wc_status = SIW_WC_GENERAL_ERR;
					error = rv;
				}
			}
		}
		/*
		 * All errors turn the wqe into signalled.
		 */
		if ((wqe->sqe.flags & SIW_WQE_SIGNALLED) || error != 0)
			rv = siw_sqe_complete(qp, &wqe->sqe, wqe->processed,
					      wc_status);
		siw_wqe_put_mem(wqe, SIW_OP_READ);

		if (!error)
			rv = siw_check_tx_fence(qp);
		else
			/* Disable current ORQ eleement */
			WRITE_ONCE(orq_get_current(qp)->flags, 0);
		break;

	case RDMAP_RDMA_READ_REQ:
		if (!error) {
			rv = siw_init_rresp(qp, rctx);
			rctx->ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ]++;
		}
		break;

	case RDMAP_RDMA_WRITE:
		if (wqe->wr_status == SIW_WR_IDLE)
			break;

		/*
		 * Free References from memory object if
		 * attached to receive context (inbound WRITE).
		 * While a zero-length WRITE is allowed,
		 * no memory reference got created.
		 */
		if (rx_mem(qp)) {
			siw_mem_put(rx_mem(qp));
			rx_mem(qp) = NULL;
		}
		break;

	default:
		break;
	}
	wqe->wr_status = SIW_WR_IDLE;

	return rv;
}

/*
 * siw_tcp_rx_data()
 *
 * Main routine to consume inbound TCP payload
 *
 * @rd_desc:	read descriptor
 * @skb:	socket buffer
 * @off:	offset in skb
 * @len:	skb->len - offset : payload in skb
 */
int siw_tcp_rx_data(read_descriptor_t *rd_desc, struct sk_buff *skb,
		    unsigned int off, size_t len)
{
	struct siw_qp *qp = rd_desc->arg.data;
	struct siw_iwarp_rx *rctx = &qp->rx_ctx;
	int rv;

	rctx->skb = skb;
	rctx->skb_new = skb->len - off;
	rctx->skb_offset = off;
	rctx->skb_copied = 0;

	siw_dbg_qp(qp, "new data, len %d\n", rctx->skb_new);

	while (rctx->skb_new) {
		int run_completion = 1;

		if (unlikely(rctx->rx_suspend)) {
			/* Do not process any more data */
			rctx->skb_copied += rctx->skb_new;
			break;
		}
		switch (rctx->state) {
		case SIW_GET_HDR:
			rv = siw_get_hdr(rctx);
			if (!rv) {
				if (rctx->mpa_crc_hd &&
				    siw_crc_rxhdr(rctx) != 0) {
					rv = -EINVAL;
					break;
				}
				rctx->fpdu_part_rem =
					siw_fpdu_payload_len(rctx);

				if (rctx->fpdu_part_rem)
					rctx->pad = -rctx->fpdu_part_rem & 0x3;
				else
					rctx->pad = 0;

				rctx->state = SIW_GET_DATA_START;
				rctx->fpdu_part_rcvd = 0;
			}
			break;

		case SIW_GET_DATA_MORE:
			/*
			 * Another data fragment of the same DDP segment.
			 * Setting first_ddp_seg = 0 avoids repeating
			 * initializations that shall occur only once per
			 * DDP segment.
			 */
			rctx->first_ddp_seg = 0;
			/* Fall through */

		case SIW_GET_DATA_START:
			/*
			 * Headers will be checked by the opcode-specific
			 * data receive function below.
			 */
			rv = siw_rx_data(qp, rctx);
			if (!rv) {
				rctx->fpdu_part_rem =
					siw_fpdu_trailer_len(rctx);
				rctx->fpdu_part_rcvd = 0;
				rctx->state = SIW_GET_TRAILER;
			} else {
				if (unlikely(rv == -ECONNRESET))
					run_completion = 0;
				else
					rctx->state = SIW_GET_DATA_MORE;
			}
			break;

		case SIW_GET_TRAILER:
			/*
			 * read CRC + any padding
			 */
			rv = siw_get_trailer(qp, rctx);
			if (likely(!rv)) {
				/*
				 * FPDU completed.
				 * complete RDMAP message if last fragment
				 */
				rctx->state = SIW_GET_HDR;
				rctx->fpdu_part_rcvd = 0;

				if (!(rctx->hdr.ctrl.ddp_rdmap_ctrl &
				      DDP_FLAG_LAST))
					/* more frags */
					break;

				rv = siw_rdmap_complete(qp, 0);
				run_completion = 0;
			}
			break;

		default:
			pr_warn("QP[%u]: RX out of state\n", qp->id);
			rv = -EPROTO;
			run_completion = 0;
		}

		if (unlikely(rv != 0 && rv != -EAGAIN)) {
			if (rctx->state > SIW_GET_HDR && run_completion)
				siw_rdmap_complete(qp, rv);

			siw_dbg_qp(qp, "rx error %d, rx state %d\n", rv,
				   rctx->state);

			siw_qp_cm_drop(qp, 1);

			break;
		}
		if (rv) {
			siw_dbg_qp(qp, "fpdu fragment, state %d, missing %d\n",
				   rctx->state, rctx->fpdu_part_rem);
			break;
		}
	}
	return rctx->skb_copied;
}
