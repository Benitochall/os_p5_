#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "mmap.h"

#define MMAP_AREA_START 0x60000000
#define MMAP_AREA_END 0x80000000

int sys_fork(void)
{
  return fork();
}

int sys_exit(void)
{
  exit();
  return 0; // not reached
}

int sys_wait(void)
{
  return wait();
}

int sys_kill(void)
{
  int pid;

  if (argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int sys_getpid(void)
{
  return myproc()->pid;
}

int sys_sbrk(void)
{
  int addr;
  int n;

  if (argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if (growproc(n) < 0)
    return -1;
  return addr;
}

int sys_sleep(void)
{
  int n;
  uint ticks0;

  if (argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while (ticks - ticks0 < n)
  {
    if (myproc()->killed)
    {
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

// Function to find an available address
uint find_available_address(int length)
{
  // TODO: at some point need to do guard pages
  struct proc *curproc = myproc();
  uint addr = MMAP_AREA_START;

  while (addr + length <= MMAP_AREA_END)
  {
    int overlap = 0;
    for (int i = 0; i < curproc->num_mappings; i++)
    {
      uint existing_start = curproc->memoryMappings[i].addr; // get the start of the first mapping 
      uint existing_end = existing_start + PGROUNDUP(curproc->memoryMappings[i].length); // get the end of the currmapping
      uint new_end = addr + length; // get the new end of the address 

      if ((existing_start < new_end && existing_end > addr)) // if the current address has a mapping and the existing end is greater than address
      // we have found a region that has already been mapped, therefore we should break and increment addr by page size
      {
        overlap = 1;
        break;
      }
    }
    if (!overlap)
    {
      return addr; // Found an available address
    }
    addr += PGSIZE;
  }
  return 0; // Failed to find an available address
}

// here is our kernal level program, this will eventually call our user level
// program that is defined in proc.c get args from user space
int sys_mmap(void)
{
  void *addr; // the requested address
  int length; // the size of memory needed //TODO: this needs to be rounded up
  int prot;   // read or write flags
  int flags;  // indicates file backed mapping
  int fd;     // file descirptors
  int offset; // the offest into the file
  struct proc *currproc = myproc();

  if (argint(0, (void *)&addr) < 0 || argint(1, &length) < 0 || argint(2, &prot) < 0 || argint(3, &flags) < 0 || argint(4, &fd) < 0 || argint(5, &offset) < 0)
  {
    cprintf("Failed 1\n");
    return -1;
  }

  // cprintf("%d\n", addr);
  // cprintf("%d\n", length);
  // cprintf("%d\n", prot);
  // cprintf("%d\n", flags);
  // cprintf("%d\n", fd);
  // cprintf("%d\n", offset);
  if (length <= 0 || (int)addr < 0x60000000 || (int)addr > 0x80000000 - PGSIZE || (int)addr % PGSIZE != 0){
    cprintf("Failed 2\n");
    return -1;
  }
    

  // At least one of MAP_SHARED or MAP_PRIVATE should be specified. Also, if MAP_ANONYMOUS is set, then fd should be -1 and offset should be 0.
  if (!((flags & MAP_SHARED) || (flags & MAP_PRIVATE)))
  {
    cprintf("Failed 3\n");
    return -1;
  }
  if ((flags & MAP_ANONYMOUS) && (fd != -1 || offset != 0))
  {
    return -1;
  }

  // If MAP_FIXED is set, then the address should be non-null and page-aligned.
  if ((flags & MAP_FIXED) && (addr == 0 || (uint)addr % PGSIZE != 0))
  {
    cprintf("Failed 4\n");
    return -1;
  }

  // If it's not an anonymous mapping, validate that the file descriptor is valid, and the offset is within the file bounds.
  if (!(flags & MAP_ANONYMOUS))
  {
    if (fd < 0 || fd >= NOFILE || myproc()->ofile[fd] == 0)
    {
      cprintf("Failed 5\n");
      return -1; // Invalid file descriptor
    }
    // if (offset < 0 || offset >= file_size(myproc()->ofile[fd]))
    // {
    //   return -1; // Invalid offset
    // }
  }
  // file mappings
  // data inside mem correspond to a file 
  // 
  // EVERYTHING BELOW THIS LINE IS MOVED TO PROC.C

  // Address allocation
  uint new_address;
  if (flags & MAP_FIXED) // map to a fixed address 
  {
    new_address = (uint)addr;
  }
  else
  {
    new_address = find_available_address(length);
    if (new_address == 0)
    {
      cprintf("Failed 6\n");
      return -1; // Failed to find an available address
    }
  }
  // now we have found the address we can go ahead and add it to the sturct

if (!(flags & MAP_ANONYMOUS)) {
  struct file *f = myproc()->ofile[fd];
  uint current_addr = new_address;
  int total_read = 0; // Total bytes read from the file

  for (int i = 0; i < length; i += PGSIZE) {
    char *mem = kalloc(); // Allocate one page frame from the kernel
    if (mem == 0) {
      // Handle error: free any previously allocated pages
      return -1; // Allocation failed
    }

    memset(mem, 0, PGSIZE);

    // Read file content into the memory
    int read_bytes = fileread(f, mem, PGSIZE);
    if (read_bytes < 0) {
      kfree(mem); // Free the allocated memory if read failed
      // Handle error: free any previously allocated pages
      return -1;
    }
    total_read += read_bytes;

    // If we read less than PGSIZE, we've hit EOF; don't try to read more.
    if (read_bytes < PGSIZE) break;

    // Map this memory to the virtual address in the process's address space
    if (mappages(myproc()->pgdir, (char *)current_addr, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
      kfree(mem); // Free the allocated memory if mapping failed
      // Handle error: free any previously allocated pages
      return -1;
    }

    current_addr += PGSIZE;
  }
}



  // Add the new mapping to the process's list of mappings
  struct mem_mapping new_mapping;

  new_mapping.addr = new_address;
  new_mapping.length = length;
  new_mapping.flags = flags;
  new_mapping.fd = fd;

  currproc->memoryMappings[currproc->num_mappings] = new_mapping; // add the new mappings to the struct
  currproc->num_mappings++;
  cprintf("%d\n", new_address);
  return new_address; // return the new address
}

// the goal of this function is unmap memory, we need to get args from the user spac e
int sys_munmap(void)
{
  return 0;
}
