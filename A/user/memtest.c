#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "user/memstat.h"

int
main(int argc, char *argv[])
{
  struct proc_mem_stat info;

  if(memstat(&info) < 0) {
    printf("memstat failed\n");
    exit(1);
  }

  printf("Process %d memory stats:\n", info.pid);
  printf("Total pages: %d\n", info.num_pages_total);
  printf("Resident pages: %d\n", info.num_resident_pages);
  printf("Swapped pages: %d\n", info.num_swapped_pages);
  printf("Next FIFO seq: %d\n", info.next_fifo_seq);

  printf("\nFirst 10 pages:\n");
  for(int i = 0; i < 10 && i < info.num_pages_total; i++) {
    printf("Page 0x%lx: state=%d, dirty=%d, seq=%d, swap_slot=%d\n",
           info.pages[i].va, info.pages[i].state, info.pages[i].is_dirty,
           info.pages[i].seq, info.pages[i].swap_slot);
  }

  exit(0);
}
