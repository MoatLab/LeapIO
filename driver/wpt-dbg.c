/* File wpt-dbg.c
 *
 * LeapIO driver debugging utilities
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include "wpt.h"

int wpt_do_cmd_dump(unsigned long vaddr)
{
    pte_t *ptep;

    ptep = va2pte(current->mm, vaddr);
    if (!ptep) {
        printk("Coperd,va2pte() failed\n");
        return -ENOMEM;
    }

    printk("=========================\n");
    printk("PTE:0x%lx\n", pte_val(*ptep));
    printk("PFN:0x%lx\n", pte_pfn(*ptep));
    printk("FLG:0x%lx\n", pte_flags(*ptep));
    printk("=========================\n\n\n");

    /* Coperd: release mapping */
    pte_unmap(ptep);

    return 0;
}

int wpt_do_cmd_swap(unsigned long vaddr)
{
    pte_t *ptep, *ptep2, pte;

    ptep = va2pte(current->mm, vaddr);
    ptep2 = va2pte(current->mm, vaddr+0x1000);

    printk("========================\n");
    printk("PTE1:0x%lx\n", pte_val(*ptep));
    printk("PTE2:0x%lx\n\n\n", pte_val(*ptep2));

    pte = *ptep;
    set_pte(ptep, *ptep2);
    set_pte(ptep2, pte);

    printk("=========================\n");
    printk("PTE1:0x%lx\n", pte_val(*ptep));
    printk("PTE2:0x%lx\n\n\n", pte_val(*ptep2));

    pte_unmap(ptep);
    pte_unmap(ptep2);

    return 0;
}
