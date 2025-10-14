#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"

/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x4000000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // allocate and map a kernel stack for each process.
  proc_mapstacks(kpgtbl);

  return kpgtbl;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Initialize the kernel_pagetable, shared by all CPUs.
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch the current CPU's h/w page table register to
// the kernel's page table, and enable paging.
void
kvminithart()
{
  // wait for any previous writes to the page table memory to finish.
  sfence_vma();

  w_satp(MAKE_SATP(kernel_pagetable));

  // flush stale entries from the TLB.
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa.
// va and size MUST be page-aligned.
// Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("mappages: va not aligned");

  if((size % PGSIZE) != 0)
    panic("mappages: size not aligned");

  if(size == 0)
    panic("mappages: size");

  a = va;
  last = va + size - PGSIZE;
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Remove npages of mappings starting from va. va must be
// page-aligned. It's OK if the mappings don't exist.
// Optionally free the physical memory.
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0) // leaf page table entry allocated?
      continue;
    if((*pte & PTE_V) == 0)  // has physical page been allocated?
      continue;
    if(do_free){
      uint64 pa = PTE2PA(*pte);
      kfree((void*)pa);
    }
    *pte = 0;
  }
}

// Allocate PTEs and physical memory to grow a process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz, int xperm)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_R|PTE_U|xperm) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    } else if(pte & PTE_V){
      panic("freewalk: leaf");
    }
  }
  kfree((void*)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      continue;   // page table entry hasn't been allocated
    if((*pte & PTE_V) == 0)
      continue;   // physical page hasn't been allocated
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto err;
    memmove(mem, (char*)pa, PGSIZE);
    if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
      kfree(mem);
      goto err;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;
  pte_t *pte;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    if(va0 >= MAXVA)
      return -1;

    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 1)) == 0) {  // 1 = write access
        return -1;
      }
    }

    pte = walk(pagetable, va0, 0);
    // forbid copyout over read-only user text pages.
    if((*pte & PTE_W) == 0)
      return -1;

    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 0)) == 0) {  // 0 = read access
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if(n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;

  while(got_null == 0 && max > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (srcva - va0);
    if(n > max)
      n = max;

    char *p = (char *) (pa0 + (srcva - va0));
    while(n > 0){
      if(*p == '\0'){
        *dst = '\0';
        got_null = 1;
        break;
      } else {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if(got_null){
    return 0;
  } else {
    return -1;
  }
}

// Helper function to find page info by VA
struct page_info*
find_page_info(struct proc *p, uint64 va)
{
  for(int i = 0; i < MAX_TRACKED_PAGES; i++) {
    if(p->page_table[i].va == va) {
      return &p->page_table[i];
    }
  }
  return 0;
}

// Helper function to add page info
struct page_info*
add_page_info(struct proc *p, uint64 va)
{
  // Find empty slot
  for(int i = 0; i < MAX_TRACKED_PAGES; i++) {
    if(p->page_table[i].va == 0) {
      p->page_table[i].va = va;
      p->page_table[i].seq = p->next_fifo_seq++;
      p->page_table[i].is_dirty = 0;
      p->page_table[i].swap_slot = -1;
      return &p->page_table[i];
    }
  }

  // No empty slot found
  printf("WARNING: No empty page_info slot found\n");
  return 0;
}

// Helper function to remove page info
void
remove_page_info(struct proc *p, uint64 va)
{
  for(int i = 0; i < MAX_TRACKED_PAGES; i++) {
    if(p->page_table[i].va == va) {
      p->page_table[i].va = 0;
      p->page_table[i].seq = 0;
      p->page_table[i].is_dirty = 0;
      p->page_table[i].swap_slot = -1;
      return;
    }
  }
}

// Get sequence number for a page
int
get_page_seq(struct proc *p, uint64 va)
{
  struct page_info *pinfo = find_page_info(p, va);
  if(pinfo) {
    return pinfo->seq;
  }
  return -1; // Page not found in tracking table
}

// Find the oldest resident page (lowest sequence number) for FIFO replacement
struct page_info*
find_fifo_victim(struct proc *p)
{
  struct page_info *victim = 0;

  for(int i = 0; i < MAX_TRACKED_PAGES; i++) {
    if(p->page_table[i].va != 0 && p->page_table[i].swap_slot == -1) {
      // Page is resident (not swapped out)
      if(victim == 0 || p->page_table[i].seq < victim->seq) {
        victim = &p->page_table[i];
      }
    }
  }

  if(victim) {
    printf("[pid %d] VICTIM va=0x%lx seq=%d algo=FIFO\n",
           p->pid, victim->va, victim->seq);
  }

  return victim;
}

// Allocate a free swap slot
int
alloc_swap_slot(struct proc *p)
{
  for(int i = 0; i < 1024; i++) {
    if(p->swap_slots[i] == 0) {
      p->swap_slots[i] = 1;  // Mark as used
      return i;
    }
  }
  return -1; // No free slots
}

// Real implementation of write_to_swap - writes page content to swap file
int
write_to_swap(struct proc *p, uint64 va)
{
  // Get physical address of the page
  uint64 pa = walkaddr(p->pagetable, va);
  if(pa == 0) {
    return -1;
  }

  // Allocate a swap slot
  int swap_slot = alloc_swap_slot(p);
  if(swap_slot < 0) {
    printf("write_to_swap: no free swap slots\n");
    return -1;
  }

  // Write page to swap file at offset = swap_slot * PGSIZE
  if(p->swap_ip == 0) {
    printf("write_to_swap: no swap file\n");
    p->swap_slots[swap_slot] = 0;  // Free the slot
    return -1;
  }

  // Perform the write
  ilock(p->swap_ip);
  int bytes_written = writei(p->swap_ip, 0, pa, swap_slot * PGSIZE, PGSIZE);
  iunlock(p->swap_ip);

  if(bytes_written != PGSIZE) {
    // Free the swap slot if write failed
    p->swap_slots[swap_slot] = 0;
    printf("write_to_swap: write failed, only wrote %d bytes\n", bytes_written);
    return -1;
  }

  return swap_slot;
}

// Real implementation of read_from_swap - reads page content from swap file
int
read_from_swap(struct proc *p, uint64 va, int swap_slot)
{
  // Get physical address where we'll load the page
  uint64 pa = walkaddr(p->pagetable, va);
  if(pa == 0) {
    return -1;
  }

  if(p->swap_ip == 0) {
    printf("read_from_swap: no swap file\n");
    return -1;
  }

  if(swap_slot < 0 || swap_slot >= 1024) {
    printf("read_from_swap: invalid swap slot %d\n", swap_slot);
    return -1;
  }

  // Read page from swap file
  ilock(p->swap_ip);
  int bytes_read = readi(p->swap_ip, 0, pa, swap_slot * PGSIZE, PGSIZE);
  iunlock(p->swap_ip);

  if(bytes_read != PGSIZE) {
    printf("read_from_swap: read failed, only read %d bytes\n", bytes_read);
    return -1;
  }

  return 0;
}

// Evict a page from memory
int
evict_page(struct proc *p, struct page_info *victim)
{
  uint64 va = victim->va;

  // Check if page is dirty
  int is_dirty = is_page_dirty(p, va);

  printf("[pid %d] EVICT va=0x%lx state=%s\n",
         p->pid, va, is_dirty ? "dirty" : "clean");

  if(is_dirty) {
    // Write dirty page to swap
    int swap_slot = write_to_swap(p, va);
    if(swap_slot < 0) {
      printf("[pid %d] SWAPFULL\n", p->pid);
      printf("[pid %d] KILL swap-exhausted\n", p->pid);
      return -1;  // Will cause process termination
    }
    victim->swap_slot = swap_slot;
    p->num_swapped_pages++;
    printf("[pid %d] SWAPOUT va=0x%lx slot=%d\n", p->pid, va, swap_slot);
  } else {
    // Clean page - just discard, don't swap out
    printf("[pid %d] DISCARD va=0x%lx\n", p->pid, va);
    // victim->swap_slot remains -1 for clean pages
  }

  // Unmap the page from page table and free physical memory
  pte_t *pte = walk(p->pagetable, va, 0);
  if(pte && (*pte & PTE_V)) {
    uint64 pa = PTE2PA(*pte);
    kfree((void*)pa);  // Free the physical frame
    *pte = 0;          // Clear PTE
  }

  // Update tracking
  p->num_resident_pages--;

  return 0;
}

// Find if a page is swapped out
struct page_info*
find_swapped_page(struct proc *p, uint64 va)
{
  for(int i = 0; i < MAX_TRACKED_PAGES; i++) {
    if(p->page_table[i].va == va && p->page_table[i].swap_slot >= 0) {
      return &p->page_table[i];
    }
  }
  return 0;
}

// Free swap slot when page is loaded back
void
free_swap_slot(struct proc *p, int swap_slot)
{
  // In Phase 3: Mark swap slot as free in bitmap
  // For now, just log
  if(swap_slot >= 0 && swap_slot < 1024) {
    p->swap_slots[swap_slot] = 0;  // Mark as free
    printf("DEBUG: Freed swap slot %d\n", swap_slot);
  }
}

// allocate and map user memory if process is referencing a page
// that was lazily allocated in sys_sbrk() or exec().
// returns 0 if va is invalid or already mapped, or if
// out of physical memory, and physical address if successful.
uint64
vmfault(pagetable_t pagetable, uint64 va, int write_access)
{
  uint64 mem;
  struct proc *p = myproc();
  int i;
  struct page_info *pinfo;

  if (va >= p->sz) {
    printf("vmfault: va 0x%lx >= process size 0x%lx (out of bounds)\n", va, p->sz);
    return 0;
  }

  va = PGROUNDDOWN(va);

  // If already mapped, just return the physical address
  if(ismapped(pagetable, va)) {
    uint64 pa = walkaddr(pagetable, va);
    if(pa != 0) {
      // Mark page dirty if this is a write access
      if(write_access) {
        mark_page_dirty(p, va);
        pinfo = find_page_info(p, va);
        if(pinfo) {
          pinfo->is_dirty = 1;
        }
      }
      return pa;
    }
    printf("vmfault: va 0x%lx marked as mapped but walkaddr failed\n", va);
    return 0;
  }

  // Check if this page is swapped out
  struct page_info *swapped_page = find_swapped_page(p, va);
  if(swapped_page && swapped_page->swap_slot >= 0) {
    printf("swap\n");  // Complete PAGEFAULT cause

    // Allocate physical memory
    mem = (uint64) kalloc();
    if(mem == 0) {
      // Memory full - trigger page replacement
      printf("[pid %d] MEMFULL\n", p->pid);

      // Find FIFO victim
      struct page_info *victim = find_fifo_victim(p);
      if(victim == 0) {
        printf("vmfault: no victim found during swap-in\n");
        return 0;
      }

      // Evict the victim
      if(evict_page(p, victim) != 0) {
        printf("vmfault: eviction failed during swap-in\n");
        return 0;
      }

      // Retry allocation after eviction
      mem = (uint64) kalloc();
      if(mem == 0) {
        printf("vmfault: still no memory after eviction during swap-in\n");
        return 0;
      }
    }

    int old_slot = swapped_page->swap_slot;

    // Map the page first so walkaddr can find it
    if(mappages(p->pagetable, va, PGSIZE, mem, PTE_W|PTE_U|PTE_R) != 0) {
      kfree((void*)mem);
      return 0;
    }

    // Now read from swap into the mapped page
    if(read_from_swap(p, va, old_slot) == 0) {
      printf("[pid %d] SWAPIN va=0x%lx slot=%d\n", p->pid, va, old_slot);

      // Update page info
      swapped_page->swap_slot = -1;  // No longer swapped
      swapped_page->seq = p->next_fifo_seq++;  // Update sequence
      p->num_resident_pages++;
      p->num_swapped_pages--;

      // Free the swap slot
      free_swap_slot(p, old_slot);

      printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, swapped_page->seq);

      return mem;
    } else {
      // Read failed - unmap and free
      uvmunmap(p->pagetable, va, 1, 1);
      printf("vmfault: read_from_swap failed\n");
      return 0;
    }
  }

  // Try to allocate physical page
  mem = (uint64) kalloc();
  if(mem == 0) {
    // Memory full - trigger page replacement
    printf("[pid %d] MEMFULL\n", p->pid);

    // Find FIFO victim
    struct page_info *victim = find_fifo_victim(p);
    if(victim == 0) {
      printf("vmfault: no victim found\n");
      return 0;
    }

    // Evict the victim
    if(evict_page(p, victim) != 0) {
      printf("vmfault: eviction failed\n");
      return 0;
    }

    // Retry allocation after eviction
    mem = (uint64) kalloc();
    if(mem == 0) {
      printf("vmfault: still no memory after eviction\n");
      return 0;
    }
  }

  memset((void *) mem, 0, PGSIZE);

  // Check if this page belongs to a program segment that needs to be loaded
  if(p->ip != 0 && p->phnum > 0) {
    for(i = 0; i < p->phnum; i++) {
      struct proghdr *ph = &p->ph[i];
      uint64 seg_start = ph->vaddr;
      uint64 seg_end = ph->vaddr + ph->memsz;

      if(va >= seg_start && va < seg_end) {
        printf("exec\n");

        uint64 offset_in_seg = va - seg_start;
        uint64 file_offset = ph->off + offset_in_seg;
        uint64 bytes_to_read = PGSIZE;

        if(offset_in_seg < ph->filesz) {
          if(offset_in_seg + PGSIZE > ph->filesz) {
            bytes_to_read = ph->filesz - offset_in_seg;
          }

          ilock(p->ip);
          if(readi(p->ip, 0, mem, file_offset, bytes_to_read) != bytes_to_read) {
            iunlock(p->ip);
            kfree((void *)mem);
            printf("vmfault: failed to read from executable file\n");
            return 0;
          }
          iunlock(p->ip);

          printf("[pid %d] LOADEXEC va=0x%lx\n", p->pid, va);
        } else {
          printf("[pid %d] ALLOC va=0x%lx\n", p->pid, va);
        }

        int perm = PTE_U;
        if(ph->flags & 0x2) perm |= PTE_W;
        if(ph->flags & 0x1) perm |= PTE_X;
        perm |= PTE_R;

        if (mappages(p->pagetable, va, PGSIZE, mem, perm) != 0) {
          kfree((void *)mem);
          printf("vmfault: mappages failed for exec segment\n");
          return 0;
        }

        clear_page_dirty(p, va);
        p->num_resident_pages++;

        // Add page info with sequence number
        pinfo = add_page_info(p, va);
        if(pinfo) {
          // Mark dirty if this is a write access
          if(write_access) {
            mark_page_dirty(p, va);
            pinfo->is_dirty = 1;
          }
          printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, pinfo->seq);
        }

        return mem;
      }
    }
  }

  // Not a program segment - must be heap or stack
  uint64 stack_bottom = p->sz - (USERSTACK+1)*PGSIZE;
  uint64 current_sp = p->trapframe->sp;

  if(va >= stack_bottom && va < p->sz) {
    uint64 sp_page = PGROUNDDOWN(current_sp);

    if(va >= sp_page - PGSIZE && va < sp_page + PGSIZE) {
      printf("stack\n");
      printf("[pid %d] ALLOC va=0x%lx\n", p->pid, va);

      if (mappages(p->pagetable, va, PGSIZE, mem, PTE_W|PTE_U|PTE_R) != 0) {
        kfree((void *)mem);
        printf("vmfault: mappages failed for stack\n");
        return 0;
      }

      clear_page_dirty(p, va);
      p->num_resident_pages++;

      // Add page info with sequence number
      pinfo = add_page_info(p, va);
      if(pinfo) {
        // Mark dirty if this is a write access
        if(write_access) {
          mark_page_dirty(p, va);
          pinfo->is_dirty = 1;
        }
        printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, pinfo->seq);
      }

      return mem;
    } else {
      kfree((void *)mem);
      printf("vmfault: stack access at va 0x%lx not within one page of SP (0x%lx)\n", va, current_sp);
      return 0;
    }
  }

  // Must be heap
  printf("heap\n");
  printf("[pid %d] ALLOC va=0x%lx\n", p->pid, va);

  if (mappages(p->pagetable, va, PGSIZE, mem, PTE_W|PTE_U|PTE_R) != 0) {
    kfree((void *)mem);
    printf("vmfault: mappages failed for heap\n");
    return 0;
  }

  clear_page_dirty(p, va);
  p->num_resident_pages++;

  // Add page info with sequence number
  pinfo = add_page_info(p, va);
  if(pinfo) {
    // Mark dirty if this is a write access
    if(write_access) {
      mark_page_dirty(p, va);
      pinfo->is_dirty = 1;
    }
    printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, pinfo->seq);
  }

  return mem;
}

int
ismapped(pagetable_t pagetable, uint64 va)
{
  pte_t *pte = walk(pagetable, va, 0);
  if (pte == 0) {
    return 0;
  }
  if (*pte & PTE_V){
    return 1;  }  return 0;
}

// Check if a page is dirty
int
is_page_dirty(struct proc *p, uint64 va)
{
  if(!p->dirty_pages || va >= p->max_dirty_pages * PGSIZE * 64)
    return 0;

  uint64 page_index = va / PGSIZE;
  uint64 word_index = page_index / 64;
  uint64 bit_index = page_index % 64;

  return (p->dirty_pages[word_index] >> bit_index) & 1;
}

// Mark a page as dirty
void
mark_page_dirty(struct proc *p, uint64 va)
{
  // Allocate dirty bitmap if needed
  if(!p->dirty_pages) {
    // Enough for 128MB address space (32768 pages)
    p->max_dirty_pages = 32768 / 64;
    p->dirty_pages = (uint64*)kalloc();
    if(p->dirty_pages)
      memset(p->dirty_pages, 0, p->max_dirty_pages * sizeof(uint64));
    else {
      p->max_dirty_pages = 0;
      return;
    }
  }

  if(va >= p->max_dirty_pages * PGSIZE * 64)
    return;

  uint64 page_index = va / PGSIZE;
  uint64 word_index = page_index / 64;
  uint64 bit_index = page_index % 64;

  p->dirty_pages[word_index] |= (1UL << bit_index);
}

// Clear dirty bit for a page
void
clear_page_dirty(struct proc *p, uint64 va)
{
  if(!p->dirty_pages || va >= p->max_dirty_pages * PGSIZE * 64)
    return;

  uint64 page_index = va / PGSIZE;
  uint64 word_index = page_index / 64;
  uint64 bit_index = page_index % 64;

  p->dirty_pages[word_index] &= ~(1UL << bit_index);
}
