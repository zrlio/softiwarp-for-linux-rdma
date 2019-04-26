// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

#include <linux/version.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <rdma/ib_verbs.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>

#include "siw.h"
#include "siw_debug.h"
#include "siw_mem.h"

/*
 * Stag lookup is based on its index part only (24 bits).
 * The code avoids special Stag of zero and tries to randomize
 * STag values between 1 and SIW_STAG_MAX_INDEX.
 */
int siw_mem_add(struct siw_device *sdev, struct siw_mem *m)
{
	unsigned long flags;
	int id;
	int start_id, max_id = 0x00FFFFFF;

	do {
		get_random_bytes(&start_id, 4);
		start_id &= 0x00FFFFFF;
	} while (start_id <= 0);
again:
	spin_lock_irqsave(&sdev->lock, flags);
	id = idr_alloc(&sdev->mem_idr, m, start_id, max_id, GFP_KERNEL);
	spin_unlock_irqrestore(&sdev->lock, flags);

	if (id == -ENOMEM)
		return -ENOMEM;

	if (id == -ENOSPC) {
		max_id = start_id;
		start_id /= 2;
		if (start_id == 0) {
			pr_warn("siw: memory ID space\n");
			return -ENOSPC;
		}
		goto again;
	}
	m->sdev = sdev;

	/* Set the STag index part */
	m->stag = id << 8;
	kref_init(&m->ref);
	siw_dbg_mem(m, "new MEM object\n");

	return 0;
}

/*
 * siw_mem_id2obj()
 *
 * resolves memory from stag given by id. might be called from:
 * o process context before sending out of sgl, or
 * o in softirq when resolving target memory
 */
struct siw_mem *siw_mem_id2obj(struct siw_device *sdev, int stag_index)
{
	struct siw_mem *mem;

	rcu_read_lock();
	mem = idr_find(&sdev->mem_idr, stag_index);
	rcu_read_unlock();

	if (likely(mem) && kref_get_unless_zero(&mem->ref)) {
		siw_dbg_mem(mem, "new refcount: %d\n",
			    kref_read(&mem->ref));
		return mem;
	}
	return NULL;
}

static void siw_free_plist(struct siw_page_chunk *chunk, int num_pages,
			   bool dirty)
{
	struct page **p = chunk->p;

	while (num_pages--) {
		if (!PageDirty(*p) && dirty)
			set_page_dirty_lock(*p);
		put_page(*p);
		p++;
	}
}

void siw_umem_release(struct siw_umem *umem, bool dirty)
{
	struct mm_struct *mm_s = umem->owning_mm;
	int i, num_pages = umem->num_pages;

	for (i = 0; num_pages; i++) {
		int to_free = min_t(int, PAGES_PER_CHUNK, num_pages);

		siw_free_plist(&umem->page_chunk[i], to_free,
			       umem->writable && dirty);
		kfree(umem->page_chunk[i].p);
		num_pages -= to_free;
	}
	atomic64_sub(umem->num_pages, &mm_s->pinned_vm);

	mmdrop(mm_s);
	kfree(umem->page_chunk);
	kfree(umem);
}

void siw_free_mem(struct kref *ref)
{
	struct siw_mem *mem;
	struct siw_device *sdev;

	mem = container_of(ref, struct siw_mem, ref);
	sdev = mem->sdev;

	siw_dbg_mem(mem, "free mem\n");

	atomic_dec(&sdev->num_mr);

	if (SIW_MEM_IS_MW(mem)) {
		struct siw_mw *mw = container_of(mem, struct siw_mw, mem);

		kfree_rcu(mw, rcu);
	} else {
		struct siw_mr *mr = container_of(mem, struct siw_mr, mem);
		struct siw_mem *found;
		unsigned long flags;

		siw_dbg_mem(mem, "has pbl: %s\n", mr->mem.is_pbl ? "y" : "n");

		if (mr->mem_obj) {
			if (mr->mem.is_pbl == 0)
				siw_umem_release(mr->umem, true);
			else
				kfree(mr->pbl);
		}
		spin_lock_irqsave(&sdev->lock, flags);
		found = idr_remove(&sdev->mem_idr, mem->stag >> 8);
		WARN_ON(found != mem);
		list_del(&mr->devq);
		spin_unlock_irqrestore(&sdev->lock, flags);

		kfree_rcu(mr, rcu);
	}
}

static inline void siw_unref_mem_sgl(struct siw_mem **mem, unsigned int num_sge)
{
	while (num_sge) {
		if (*mem == NULL)
			break;

		siw_mem_put(*mem);
		*mem = NULL;
		mem++;
		num_sge--;
	}
}

/*
 * siw_check_mem()
 *
 * Check protection domain, STAG state, access permissions and
 * address range for memory object.
 *
 * @pd:		Protection Domain memory should belong to
 * @mem:	memory to be checked
 * @addr:	starting addr of mem
 * @perms:	requested access permissions
 * @len:	len of memory interval to be checked
 *
 */
int siw_check_mem(struct siw_pd *pd, struct siw_mem *mem, u64 addr,
		  enum ib_access_flags perms, int len)
{
	if (!mem->stag_valid) {
		siw_dbg_pd(pd, "STag 0x%08x invalid\n", mem->stag);
		return -E_STAG_INVALID;
	}
	if (siw_mem2mr(mem)->pd != pd) {
		siw_dbg_pd(pd, "STag 0x%08x: PD mismatch\n", mem->stag);
		return -E_PD_MISMATCH;
	}
	/*
	 * check access permissions
	 */
	if ((mem->perms & perms) < perms) {
		siw_dbg_pd(pd, "permissions 0x%08x < 0x%08x\n",
			   mem->perms, perms);
		return -E_ACCESS_PERM;
	}
	/*
	 * Check if access falls into valid memory interval.
	 */
	if (addr < mem->va || addr + len > mem->va + mem->len) {
		siw_dbg_pd(pd, "MEM interval len %d\n", len);
		siw_dbg_pd(pd, "[0x%016llx, 0x%016llx] out of bounds\n",
			   (unsigned long long)addr,
			   (unsigned long long)(addr + len));
		siw_dbg_pd(pd, "[0x%016llx, 0x%016llx] STag=0x%08x\n",
			   (unsigned long long)mem->va,
			   (unsigned long long)(mem->va + mem->len),
			   mem->stag);

		return -E_BASE_BOUNDS;
	}
	return E_ACCESS_OK;
}

/*
 * siw_check_sge()
 *
 * Check SGE for access rights in given interval
 *
 * @pd:		Protection Domain memory should belong to
 * @sge:	SGE to be checked
 * @mem:	location of memory reference within array
 * @perms:	requested access permissions
 * @off:	starting offset in SGE
 * @len:	len of memory interval to be checked
 *
 * NOTE: Function references SGE's memory object (mem->obj)
 * if not yet done. New reference is kept if check went ok and
 * released if check failed. If mem->obj is already valid, no new
 * lookup is being done and mem is not released it check fails.
 */
int siw_check_sge(struct siw_pd *pd, struct siw_sge *sge, struct siw_mem *mem[],
		  enum ib_access_flags perms, u32 off, int len)
{
	struct siw_device *sdev = pd->sdev;
	struct siw_mem *new = NULL;
	int rv = E_ACCESS_OK;

	if (len + off > sge->length) {
		rv = -E_BASE_BOUNDS;
		goto fail;
	}
	if (*mem == NULL) {
		new = siw_mem_id2obj(sdev, sge->lkey >> 8);
		if (unlikely(!new)) {
			siw_dbg_pd(pd, "STag unknown: 0x%08x\n", sge->lkey);
			rv = -E_STAG_INVALID;
			goto fail;
		}
		*mem = new;
	}
	/* Check if user re-registered with different STag key */
	if (unlikely((*mem)->stag != sge->lkey)) {
		siw_dbg_mem((*mem), "STag mismatch: 0x%08x\n", sge->lkey);
		rv = -E_STAG_INVALID;
		goto fail;
	}
	rv = siw_check_mem(pd, *mem, sge->laddr + off, perms, len);
	if (unlikely(rv))
		goto fail;

	return 0;

fail:
	if (new) {
		*mem = NULL;
		siw_mem_put(new);
	}
	return rv;
}

void siw_wqe_put_mem(struct siw_wqe *wqe, enum siw_opcode op)
{
	switch (op) {
	case SIW_OP_SEND:
	case SIW_OP_WRITE:
	case SIW_OP_SEND_WITH_IMM:
	case SIW_OP_SEND_REMOTE_INV:
	case SIW_OP_READ:
	case SIW_OP_READ_LOCAL_INV:
		if (!(wqe->sqe.flags & SIW_WQE_INLINE))
			siw_unref_mem_sgl(wqe->mem, wqe->sqe.num_sge);
		break;

	case SIW_OP_RECEIVE:
		siw_unref_mem_sgl(wqe->mem, wqe->rqe.num_sge);
		break;

	case SIW_OP_READ_RESPONSE:
		siw_unref_mem_sgl(wqe->mem, 1);
		break;

	default:
		/*
		 * SIW_OP_INVAL_STAG and SIW_OP_REG_MR
		 * do not hold memory references
		 */
		break;
	}
}

int siw_invalidate_stag(struct siw_pd *pd, u32 stag)
{
	struct siw_mem *mem = siw_mem_id2obj(pd->sdev, stag >> 8);
	int rv = 0;

	if (unlikely(!mem)) {
		siw_dbg_pd(pd, "STag 0x%08x unknown\n", stag);
		return -EINVAL;
	}
	if (unlikely(siw_mem2mr(mem)->pd != pd)) {
		siw_dbg_pd(pd, "PD mismatch for STag 0x%08x\n", stag);
		rv = -EACCES;
		goto out;
	}
	/*
	 * Per RDMA verbs definition, an STag may already be in invalid
	 * state if invalidation is requested. So no state check here.
	 */
	mem->stag_valid = 0;

	siw_dbg_pd(pd, "STag 0x%08x now invalid\n", stag);
out:
	siw_mem_put(mem);
	return rv;
}

/*
 * Gets physical address backed by PBL element. Address is referenced
 * by linear byte offset into list of variably sized PB elements.
 * Optionally, provides remaining len within current element, and
 * current PBL index for later resume at same element.
 */
u64 siw_pbl_get_buffer(struct siw_pbl *pbl, u64 off, int *len, int *idx)
{
	int i = idx ? *idx : 0;

	while (i < pbl->num_buf) {
		struct siw_pble *pble = &pbl->pbe[i];

		if (pble->pbl_off + pble->size > off) {
			u64 pble_off = off - pble->pbl_off;

			if (len)
				*len = pble->size - pble_off;
			if (idx)
				*idx = i;

			return pble->addr + pble_off;
		}
		i++;
	}
	if (len)
		*len = 0;
	return 0;
}

struct siw_pbl *siw_pbl_alloc(u32 num_buf)
{
	struct siw_pbl *pbl;
	int buf_size = sizeof(*pbl);

	if (num_buf == 0)
		return ERR_PTR(-EINVAL);

	buf_size += ((num_buf - 1) * sizeof(struct siw_pble));

	pbl = kzalloc(buf_size, GFP_KERNEL);
	if (!pbl)
		return ERR_PTR(-ENOMEM);

	pbl->max_buf = num_buf;

	return pbl;
}

struct siw_umem *siw_umem_get(u64 start, u64 len, bool writable)
{
	struct siw_umem *umem;
	struct mm_struct *mm_s;
	u64 first_page_va;
	unsigned long mlock_limit;
	unsigned int foll_flags = FOLL_WRITE;
	int num_pages, num_chunks, i, rv = 0;

	if (!can_do_mlock())
		return ERR_PTR(-EPERM);

	if (!len)
		return ERR_PTR(-EINVAL);

	first_page_va = start & PAGE_MASK;
	num_pages = PAGE_ALIGN(start + len - first_page_va) >> PAGE_SHIFT;
	num_chunks = (num_pages >> CHUNK_SHIFT) + 1;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);

	mm_s = current->mm;
	umem->owning_mm = mm_s;
	umem->writable = writable;

	mmgrab(mm_s);

	if (!writable)
		foll_flags |= FOLL_FORCE;

	down_read(&mm_s->mmap_sem);

	mlock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	if (num_pages + atomic64_read(&mm_s->pinned_vm) > mlock_limit) {
		rv = -ENOMEM;
		goto out_sem_up;
	}
	umem->fp_addr = first_page_va;

	umem->page_chunk =
		kcalloc(num_chunks, sizeof(struct siw_page_chunk), GFP_KERNEL);
	if (!umem->page_chunk) {
		rv = -ENOMEM;
		goto out_sem_up;
	}
	for (i = 0; num_pages; i++) {
		int got, nents = min_t(int, num_pages, PAGES_PER_CHUNK);

		umem->page_chunk[i].p =
			kcalloc(nents, sizeof(struct page *), GFP_KERNEL);
		if (!umem->page_chunk[i].p) {
			rv = -ENOMEM;
			goto out_sem_up;
		}
		got = 0;
		while (nents) {
			struct page **plist = &umem->page_chunk[i].p[got];

			rv = get_user_pages_longterm(first_page_va, nents,
						     foll_flags, plist, NULL);
			if (rv < 0)
				goto out_sem_up;

			umem->num_pages += rv;
			atomic64_add(rv, &mm_s->pinned_vm);
			first_page_va += rv * PAGE_SIZE;
			nents -= rv;
			got += rv;
		}
		num_pages -= got;
	}
out_sem_up:
	up_read(&mm_s->mmap_sem);

	if (rv > 0)
		return umem;

	siw_umem_release(umem, false);

	return ERR_PTR(rv);
}
