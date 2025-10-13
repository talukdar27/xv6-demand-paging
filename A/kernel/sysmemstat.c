#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "memstat.h"

// Helper function to check if a page is resident
int
is_page_resident(pagetable_t pagetable, uint64 va)
{
  pte_t *pte = walk(pagetable, PGROUNDDOWN(va), 0);
  return (pte && (*pte & PTE_V));
}

// Helper function to get swap slot (placeholder for now)
int
get_swap_slot(struct proc *p, uint64 va)
{
  // We'll implement this when we add swapping
  struct page_info *pinfo = find_page_info(p, va);
  if(pinfo) {
    return pinfo->swap_slot;
  }
  return -1; // -1 means not swapped
}

uint64
sys_memstat(void)
{
  uint64 user_addr;
  struct proc *p = myproc();

  // Get user pointer to proc_mem_stat structure
  argaddr(0, &user_addr);
  if(user_addr == 0)
    return -1;

  struct proc_mem_stat info;

  // Fill basic info
  info.pid = p->pid;
  info.num_pages_total = (p->sz + PGSIZE - 1) / PGSIZE;  // Total pages in process
  info.num_resident_pages = 0;  // We'll count this below
  info.num_swapped_pages = 0;   // We'll implement this with swapping
  info.next_fifo_seq = p->next_fifo_seq;

  // Scan through virtual address space
  int pages_collected = 0;
  for(uint64 va = 0; va < p->sz && pages_collected < MAX_PAGES_INFO; va += PGSIZE) {
    struct page_stat *page = &info.pages[pages_collected];
    page->va = va;

    if(is_page_resident(p->pagetable, va)) {
      page->state = RESIDENT;
      info.num_resident_pages++;
      page->is_dirty = is_page_dirty(p, va);
      page->seq = get_page_seq(p, va);
    } else {
      int swap_slot = get_swap_slot(p, va);
      if(swap_slot >= 0) {
        page->state = SWAPPED;
        info.num_swapped_pages++;
        page->is_dirty = 0;  // Swapped pages are considered clean
        page->seq = 0;       // Sequence doesn't apply to swapped pages
      } else {
        page->state = UNMAPPED;
        page->is_dirty = 0;
        page->seq = 0;
      }
    }
    page->swap_slot = get_swap_slot(p, va);

    pages_collected++;
  }

  // Copy results back to user space
  if(copyout(p->pagetable, user_addr, (char *)&info, sizeof(info)) < 0)
    return -1;

  return 0;
}
