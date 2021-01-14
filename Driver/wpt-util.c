/*
 * File wpt-util.c
 *
 * LeapIO utilities for walking page table
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include "wpt.h"

//#define DEBUG_PT_WALK

#if 0
static int printbinary(char *buf, unsigned long x, int nbits)
{
    u64 mask = 1UL << (nbits - 1);

    while (mask != 0) {
        *buf++ = (mask & x ? '1' : '0');
        mask >>= 1;
    }
    *buf = '\0';

    return nbits;
}
#endif

void get_pgt_macro(void)
{
    printk("PAGE_OFFSET = 0x%lx\n", PAGE_OFFSET);
    printk("PGDIR_SHIFT = %d\n", PGDIR_SHIFT);
    printk("P4D_SHIFT = %d\n", P4D_SHIFT);
    printk("PUD_SHIFT = %d\n", PUD_SHIFT);
    printk("PMD_SHIFT = %d\n", PMD_SHIFT);
    printk("PTE_SHIFT = %d\n", PAGE_SHIFT);

    printk("PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
    printk("PTRS_PER_P4D = %d\n", PTRS_PER_P4D);
    printk("PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
    printk("PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
    printk("PTRS_PER_PTE = %d\n", PTRS_PER_PTE);

    printk("PAGE_MASK = 0x%lx\n", PAGE_MASK);
}

/*
 * Coperd: page table walk, return the corresponding PTE
 * need to call pte_unmap() later, TODO: support hugepages
 */
pte_t *va2pte(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
        printk("Coperd,invalid pgd [%p]\n", pgd);
        goto out;
    }

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d))) {
        printk("Coperd, invalid p4d [%p]", p4d);
        goto out;
    }

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
        printk("Coperd, invalid pud [%p]", pud);
        goto out;
    }

    pmd = pmd_offset(pud, addr);
    /* Coperd: TODO: sometimes pmd_bad() is true */
    if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
        printk("Coperd, invalid pmd [%p]", pmd);
        goto out;
    }

    ptep = pte_offset_map(pmd, addr);
    //ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
    if (!ptep) {
        printk("Coperd,%d,pt_offset_map() failed\n", __LINE__);
        goto out;
    }

    return ptep;

out:
    return NULL;
}

static int pud_huge(pud_t pud)
{
    return !!(pud_val(pud) & _PAGE_PSE);
}

static int pmd_huge(pmd_t pmd)
{
    return !!(pmd_val(pmd) & _PAGE_PSE);
}

/* Coperd: hva2hpa translation, with hugepage support */
u64 hva2hpa(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    u64 hpa = 0;
    unsigned long offset;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
        pr_err("Coperd,invalid PGD [%lx]\n", pgd_val(*pgd));
        goto out;
    }

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d))) {
        pr_err("Coperd, invalid P4D [%lx]", p4d_val(*p4d));
        goto out;
    }

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || !pud_present(*pud)) {
        pr_err("Coperd, invalid PUD [%lx]", pud_val(*pud));
        goto out;
    }

    /* Coperd: 1GB hugepage */
    if (pud_huge(*pud)) {
        hpa = pud_pfn(*pud) << PAGE_SHIFT;
        offset = addr & ~PUD_PAGE_MASK;
#ifdef DEBUG_PT_WALK
        printk("Coperd,1GB huagepage,0x%llx\n", hpa);
#endif
        return (hpa | offset);
    }

    if (unlikely(pud_bad(*pud))) {
        pr_err("Coperd,bad PUD [%lx]\n", pud_val(*pud));
        goto out;
    }

    pmd = pmd_offset(pud, addr);
    /* Coperd: TODO: sometimes pmd_bad() is true */
    if (pmd_none(*pmd) || !pmd_present(*pmd)) {
        pr_err("Coperd, invalid PMD [%lx]", pmd_val(*pmd));
        goto out;
    }

    /* Coperd: 2MB hugepage */
    if (pmd_huge(*pmd)) {
        hpa = pmd_pfn(*pmd) << PAGE_SHIFT;
        offset = addr & ~PMD_PAGE_MASK;
#ifdef DEBUG_PT_WALK
        printk("Coperd,2MB huagepage,0x%llx\n", hpa);
#endif
        return (hpa | offset);
    }

    if (unlikely(pmd_bad(*pmd))) {
        pr_err("Coperd, bad PMD [%lx]", pmd_val(*pmd));
        goto out;
    }

    ptep = pte_offset_map(pmd, addr);
    //ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
    if (!ptep) {
        pr_err("Coperd,%d,pt_offset_map() failed\n", __LINE__);
        goto out;
    }

    hpa = pte_pfn(*ptep) << PAGE_SHIFT;
    pte_unmap(ptep);
#ifdef DEBUG_PT_WALK
    printk("Coperd,4KB page,0x%llx\n", hpa);
#endif
    offset = addr & ~PAGE_MASK;
    return (hpa | offset);

out:
    return WPT_INVALID_PFN;
}

struct kvm *get_kvm(pid_t vm_pid)
{
    struct kvm *kvm;
    list_for_each_entry(kvm, &vm_list, vm_list) {
        if (kvm->userspace_pid == vm_pid) {
            printk("===> pid[%d]: kvm[%lx]\n", vm_pid, (unsigned long)kvm);
            return kvm;
        }
    }

    return NULL;
}

/*
 * Some mappings aren't backed by a struct page, for example an mmap'd
 * MMIO range for our own or another device.  These use a different
 * pfn conversion and shouldn't be tracked as locked pages.
 */
static bool is_invalid_reserved_pfn(unsigned long pfn)
{
	if (pfn_valid(pfn)) {
		bool reserved;
		struct page *tail = pfn_to_page(pfn);
		struct page *head = compound_head(tail);
		reserved = !!(PageReserved(head));
		if (head != tail) {
			/*
			 * "head" is not a dangling pointer
			 * (compound_head takes care of that)
			 * but the hugepage may have been split
			 * from under us (and we may not hold a
			 * reference count on the head page so it can
			 * be reused before we run PageReferenced), so
			 * we've to check PageTail before returning
			 * what we just read.
			 */
			smp_rmb();
			if (PageTail(tail))
				return reserved;
		}
		return PageReserved(tail);
	}

	return true;
}

int vaddr_get_pfn(struct mm_struct *mm, unsigned long vaddr, unsigned long *pfn)
{
    struct page *page[1];
    //struct vm_area_struct *vma;
    int ret;

    if (mm == current->mm) {
        ret = get_user_pages_fast(vaddr, 1, 0, page);
    } else {
        down_read(&mm->mmap_sem);
        ret = get_user_pages_remote(NULL, mm, vaddr, 1, 0, page, NULL, NULL);
        up_read(&mm->mmap_sem);
    }

    if (ret == 1) {
        *pfn = page_to_pfn(page[0]);
        return 0;
    }

    pr_err("%s,vaddr[%lx] translation failed\n", __func__, vaddr);
    return -1;

#if 0
    down_read(&mm->mmap_sem);

    vma = find_vma_intersection(mm, vaddr, vaddr + 1);

    if (vma && vma->vm_flags & VM_PFNMAP) {
        *pfn = ((vaddr - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
        if (is_invalid_reserved_pfn(*pfn))
            ret = 0;
    }

    up_read(&mm->mmap_sem);
    return ret;
#endif
}

int put_pfn(unsigned long pfn)
{
    if (!is_invalid_reserved_pfn(pfn)) {
        struct page *page = pfn_to_page(pfn);
        put_page(page);
        return 1;
    }

    return 0;
}
