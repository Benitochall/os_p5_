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
  struct proc *curproc = myproc();
  uint addr = MMAP_AREA_START;

  while (addr + length <= MMAP_AREA_END)
  {
    int overlap = 0;
    for (int i = 0; i < curproc->num_mappings; i++)
    {
      uint existing_start = curproc->memoryMappings[i].addr;
      uint existing_end = existing_start + curproc->memoryMappings[i].length;
      uint new_end = addr + length;

      if ((existing_start < new_end && existing_end > addr))
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
  int length; // the size of memory needed
  int prot;   // read or write flags
  int flags;  // indicates file backed mapping
  int fd;     // file descirptors
  int offset; // the offest into the file
  // struct proc *curproc = myproc();

  if (argint(0, (void *)&addr) < 0 || argint(1, &length) < 0 || argint(2, &prot) < 0 || argint(3, &flags) < 0 || argint(4, &fd) < 0 || argint(5, &offset) < 0)
  {
    return -1;
  }

  cprintf("%d\n", addr);
  cprintf("%d\n", length);
  cprintf("%d\n", prot);
  cprintf("%d\n", flags);
  cprintf("%d\n", fd);
  cprintf("%d\n", offset);
  if (length <= 0 || (length % PGSIZE != 0) || (int)addr < 0x60000000 || (int)addr > 0x80000000 - PGSIZE || (int)addr % PGSIZE != 0)
    return -1;

  // At least one of MAP_SHARED or MAP_PRIVATE should be specified. Also, if MAP_ANONYMOUS is set, then fd should be -1 and offset should be 0.
  if (!((flags & MAP_SHARED) || (flags & MAP_PRIVATE)))
  {
    return -1;
  }
  if ((flags & MAP_ANONYMOUS) && (fd != -1 || offset != 0))
  {
    return -1;
  }

  // If MAP_FIXED is set, then the address should be non-null and page-aligned.
  if ((flags & MAP_FIXED) && (addr == 0 || (uint)addr % PGSIZE != 0))
  {
    return -1;
  }

  // If it's not an anonymous mapping, validate that the file descriptor is valid, and the offset is within the file bounds.
  if (!(flags & MAP_ANONYMOUS))
  {
    if (fd < 0 || fd >= NOFILE || myproc()->ofile[fd] == 0)
    {
      return -1; // Invalid file descriptor
    }
    if (offset < 0 || offset >= file_size(myproc()->ofile[fd]))
    {
      return -1; // Invalid offset
    }
  }

  // Address allocation
  uint new_address;
  if (flags & MAP_FIXED)
  {
    new_address = (uint)addr;
  }
  else
  {
    new_address = find_available_address(length);
    if (new_address == 0)
    {
      return -1; // Failed to find an available address
    }
  }

  // Placeholder for allocating physical pages and mapping them to virtual addresses
  // ...

  // Placeholder for file-backed mapping logic
  // ...
//   if (!(flags & MAP_ANONYMOUS)) {
//   struct file *f = myproc()->ofile[fd];
//   char *mem = kalloc();  // Allocate one page frame from the kernel
//   if (mem == 0) {
//     return -1;  // Allocation failed
//   }

//   // Read file content into the memory
//   ilock(f->ip);
//   int n = readi(f->ip, mem, offset, PGSIZE);
//   iunlock(f->ip);

//   if (n < 0) {
//     kfree(mem);  // Free the allocated memory if read failed
//     return -1;
//   }

//   // Map this memory to the virtual address in the process's address space
//   if (mappages(myproc()->pgdir, (char *)new_address, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0) {
//     kfree(mem);  // Free the allocated memory if mapping failed
//     return -1;
//   }
// }

  // Add the new mapping to the process's list of mappings
  struct proc *curproc = myproc();
  struct mem_mapping new_mapping;

  new_mapping.addr = new_address;
  new_mapping.length = length;
  new_mapping.flags = flags;
  new_mapping.fd = fd;

  curproc->memoryMappings[curproc->num_mappings] = new_mapping;
  curproc->num_mappings++;

  // this is where we need to call mmap
  // mmap(addr, length, prot, flags, fd, offset);
  return new_address;
}

// the goal of this function is unmap memory, we need to get args from the user spac e
int sys_munmap(void)
{
  return 0;
}
