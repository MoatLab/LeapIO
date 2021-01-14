/*
 * File mm/leap-mm.c
 *
 * Page table utility functions adapted from mm/ for LeapIO project
 * Used by LeapIO driver for shared memory mapping between x86 and SoC as well
 * as VM address translation
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/kallsyms.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#include <linux/dma-debug.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>
#include <linux/oom.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include "internal.h"

inline int follow_pte(struct mm_struct *mm, unsigned long address,
			     pte_t **ptepp, spinlock_t **ptlp);

int wpt_remap_pte_range(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pte_t *ptep;
	spinlock_t *ptl;

	struct flush_tlb_info info = {
		.mm = mm,
	};

	struct vm_area_struct *vma = find_vma(mm, addr);
	if (!vma) {
		return -ENOMEM;
	}

	///
	mmu_notifier_invalidate_range_start(mm, addr, end);
	///

	ptep = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!ptep)
		return -ENOMEM;
	//arch_enter_lazy_mmu_mode();
	do {
		if (pte_none(*ptep)) {
			printk("Coperd,%s,SoC needs to alloc buffer first\n", __func__);
		}
#if 0
		printk("Coperd,%s,addr=%lx,old-pfn=%lx,new-pfn=%lx\n", __func__,
		       addr, pte_pfn(*pte), pfn);

		BUG_ON(!pte_none(*pte));
#endif
		get_page(pfn_to_page(pfn));
		flush_cache_page(vma, addr, pfn);
		ptep_clear_flush_notify(vma, addr, ptep);
		//SetPageReserved(pfn_to_page(pfn));
		set_pte_at_notify(mm, addr, ptep, pte_mkspecial(pfn_pte(pfn, prot)));
		flush_tlb_page(vma, addr);
        /* Coperd: mm_cpumask(mm) */
		flush_tlb_others(cpu_online_mask, &info);
		update_mmu_cache(vma, addr, ptep);
		//ClearPageReserved(pfn_to_page(pfn));
		pfn++;
	} while (ptep++, addr += PAGE_SIZE, addr != end);
	//arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(ptep - 1, ptl);

	///
	mmu_notifier_invalidate_range_end(mm, addr, end);

	return 0;
}
EXPORT_SYMBOL(wpt_remap_pte_range);

static inline int wpt_remap_pmd_range(struct mm_struct *mm, pud_t *pud,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	pfn -= addr >> PAGE_SHIFT;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd || pmd_none(*pmd) || pmd_bad(*pmd)) {
		printk("Coperd,%s,bad pmd: %lx\n", __func__, pmd_val(*pmd));
		return -ENOMEM;
	}
	VM_BUG_ON(pmd_trans_huge(*pmd));
	do {
		next = pmd_addr_end(addr, end);
		if (wpt_remap_pte_range(mm, pmd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int wpt_remap_pud_range(struct mm_struct *mm, p4d_t *p4d,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	pfn -= addr >> PAGE_SHIFT;
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (wpt_remap_pmd_range(mm, pud, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static inline int wpt_remap_p4d_range(struct mm_struct *mm, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	p4d_t *p4d;
	unsigned long next;

	pfn -= addr >> PAGE_SHIFT;
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		if (wpt_remap_pud_range(mm, p4d, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot))
			return -ENOMEM;
	} while (p4d++, addr = next, addr != end);
	return 0;
}

int wpt_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long pfn, unsigned long size, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + PAGE_ALIGN(size);
	struct mm_struct *mm = vma->vm_mm;
	unsigned long remap_pfn = pfn;
	int err;

	/*
	 * Physically remapped pages are special. Tell the
	 * rest of the world about it:
	 *   VM_IO tells people not to look at these pages
	 *	(accesses can have side effects).
	 *   VM_PFNMAP tells the core MM that the base pages are just
	 *	raw PFN mappings, and do not have a "struct page" associated
	 *	with them.
	 *   VM_DONTEXPAND
	 *      Disable vma merging and expanding with mremap().
	 *   VM_DONTDUMP
	 *      Omit vma from core dump, even when VM_IO turned off.
	 *
	 * There's a horrible special case to handle copy-on-write
	 * behaviour that some programs depend on. We mark the "original"
	 * un-COW'ed pages by matching them up with "vma->vm_pgoff".
	 * See vm_normal_page() for details.
	 */

	/* Coperd: HACK for Leap */
#if 0
	if (is_cow_mapping(vma->vm_flags)) {
		if (addr != vma->vm_start || end != vma->vm_end) {
			printk("Coperd,%s,addr != vm_start | vm_end\n", __func__);
			return -EINVAL;
		}
		vma->vm_pgoff = pfn;
	}
#endif

#if 0
	err = track_pfn_remap(vma, &prot, remap_pfn, addr, PAGE_ALIGN(size));
	if (err) {
		printk("Coperd,%s,track_pfn_remap failed\n", __func__);
		return -EINVAL;
	}
#endif

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;

	BUG_ON(addr >= end);
	pfn -= addr >> PAGE_SHIFT;
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		err = wpt_remap_p4d_range(mm, pgd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err) {
			pr_err("Coperd,%s,remap_p4d_range err,%d\n", __func__, err);
			break;
		}
	} while (pgd++, addr = next, addr != end);

#if 0
	if (err)
		untrack_pfn(vma, remap_pfn, PAGE_ALIGN(size));
#endif

	return err;
}
EXPORT_SYMBOL(wpt_remap_pfn_range);


int wpt_follow_phys(struct mm_struct *mm, unsigned long address, u64 *phys)
{
	int ret = -EINVAL;
	pte_t *ptep, pte;
	spinlock_t *ptl;

	if (follow_pte(mm, address, &ptep, &ptl))
		goto out;
	pte = *ptep;

	*phys = ((u64)pte_pfn(pte) << PAGE_SHIFT) + (address & (PAGE_SIZE - 1));

	ret = 0;
	pte_unmap_unlock(ptep, ptl);
out:
	return ret;
}
EXPORT_SYMBOL(wpt_follow_phys);
