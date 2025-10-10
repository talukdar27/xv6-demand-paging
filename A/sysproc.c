// ...existing code...

int
sys_sbrk(void)
{
  int addr;
  int n;
  struct proc *curproc = myproc();

  if(argint(0, &n) < 0)
    return -1;
  addr = curproc->sz;

  // Only update the size, don't allocate physical memory
  if(n > 0){
    // Growing the heap - just update sz
    curproc->sz += n;
  } else if(n < 0){
    // Shrinking the heap - optionally deallocate pages
    if((curproc->sz + n) < 0)
      return -1;
    curproc->sz += n;
  }

  return addr;
}
