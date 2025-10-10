// ...existing code...

int
exec(char *path, char **argv)
{
  // ...existing code...

  // Load program into memory - MODIFIED to not allocate physical pages
  sz = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, (char*)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    // Just update size without allocating physical memory
    if((sz = ph.vaddr + ph.memsz) > sz)
      sz = ph.vaddr + ph.memsz;
    // Don't call allocuvm or load the program segments
  }

  // ...existing code...

  // Allocate two pages at the next page boundary for stack - MODIFIED
  sz = PGROUNDUP(sz);
  // Just update size, don't allocate physical pages for stack
  sz += 2*PGSIZE;

  // ...existing code...

  // Push argument strings, prepare rest of stack in ustack - MODIFIED
  // Don't actually write to stack memory, just set up sp
  sp = sz;

  // Skip writing arguments to stack since pages aren't allocated yet
  // The page fault handler will allocate pages when accessed

  // ...existing code...
}
