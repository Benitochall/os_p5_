#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "param.h"
#include "proc.h"
#include "mmap.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"

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

  cprintf("addr: %d\n", addr);
  cprintf("length: %d\n", length);
  cprintf("prot: %d\n", prot);
  cprintf("flags: %d\n", flags);
  cprintf("fd: %d\n", fd);
  cprintf("offset: %d\n", offset);

  if (length <=0) {
    return -1;
  }
  
  if (addr){
    if ((int)addr < (int)MMAP_AREA_START || (int)addr > (int)(MMAP_AREA_END - PGSIZE) || (int)addr % PGSIZE != 0){
      return -1; 
      
      }
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
    // struct file* f = currproc->ofile[fd];
    // struct inode *ip;
    // ip = f->ip;
    // cprintf("file size%d\n", ip->size); 
    // int new_size = 4096;
    // begin_op(); 
    //     if (new_size > ip->size) {
    //     // Calculate the number of additional blocks needed
    //     int additional_blocks = (new_size - ip->size + BSIZE - 1) / BSIZE;

    //     // Allocate additional blocks
    //     for (int i = 0; i < additional_blocks; i++) {
    //         if (balloc(ip->dev) < 0) {
    //             panic("balloc");
    //         }
    //     }

    //     // Update inode size
    //     ip->size = new_size;

    //     // Write updated inode back to disk
    //     iupdate(ip);
    //     }
    //     end_op(); 
        
    //     cprintf("New file size: %d\n", ip->size);

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

  // Check for MAP_GROWSUP flag and adjust the mapping accordingly
//   if (flags & MAP_GROWSUP) {
//   // Ensure there is at least one guard page
//   length = PGROUNDUP(length); // Round up to the nearest page size
//   new_address = find_available_address(length + PGSIZE); // Reserve space for the guard page
//   if (new_address == 0) {
//     cprintf("Failed to find available address with guard page\n");
//     return -1;
//   }
// }


  // now we have found the address we can go ahead and add it to the sturct
  struct mem_mapping new_mapping;

  new_mapping.addr = new_address;
  new_mapping.length = length;
  new_mapping.flags = flags;
  new_mapping.fd = fd;
  new_mapping.originalLength = length; 

  currproc->memoryMappings[currproc->num_mappings] = new_mapping; // add the new mappings to the struct
  currproc->num_mappings++;
  cprintf("%x\n", new_address);
  return new_address; // return the new address
}

// the goal of this function is unmap memory, we need to get args from the user spac e
int sys_munmap(void) {
  void *addr; // this is the address we need to get
  int length; // we are not doing partial unmappings 
  struct proc *curproc = myproc();
  struct file *f;
  
  // Retrieve the arguments from the system call.
  if (argint(0, (void *)&addr) < 0 || argint(1, &length) < 0) {
    return -1;
  }

  
  // Iterate over the mappings and find the mapping for the given address.
  for (int i = 0; i < curproc->num_mappings; i++) {
    // may need to walk the page directory
    struct mem_mapping *map = &curproc->memoryMappings[i];
    if ((uint)addr >= map->addr && (uint)addr + length <= map->addr + map->length) {
      // If the mapping is file-backed with the MAP_SHARED flag, write it back to the file.
      if ((map->flags & MAP_SHARED) && !(map->flags & MAP_ANONYMOUS) && map->fd >= 0) {
          cprintf("the number of mappings are %d\n", curproc->num_mappings);
          f = curproc->ofile[map->fd];
          if (f == 0)
            {
              // Handle error: Invalid file descriptor
              panic("mapping failed 1");
            }
          struct inode *ip = f->ip;
          cprintf("file size %d\n", ip->size); 
        // we need dump the file into a buffer
        uint va = map->addr; 
        uint offset = PGROUNDUP(map->addr + map->length); 
        cprintf("flags is %d\n", map->flags); 
        if (MAP_GROWSUP & map->flags){
          cprintf("we shouldnt access this\n"); 
          offset = PGROUNDUP(map->addr + map->length) -PGSIZE; 
        }
        cprintf("trying to access %x\n", va); 
        while (va < offset){
          cprintf("made it into unmap\n"); 
          pte_t *pte;

          pte = walkpgdir(myproc()->pgdir, (void *)va, 0); // gets the page table entry

          if(!pte || !(*pte & PTE_P)){
            // if the address is not found but it is in the copy uvm 
            cprintf("something wrong with pte\n"); 
            return -1; 
          }
          char *pa = P2V(PTE_ADDR(*pte));  // gets the physical address
          char buffer[PGSIZE]; 
          // Copy data from physical address 'pa' to the buffer
          memmove(buffer, pa, PGSIZE);
          
          uint offset_into_file = va - map->addr; 

          begin_op();
          ilock(ip);
          int written_bytes = writei(ip, buffer, offset_into_file, PGSIZE);

          cprintf("Made it here2\n"); 

          iunlock(ip); 
          end_op(); 

         if (written_bytes < 0) {
            cprintf(" write bytes is negative\n");
            return -1;
          }
          // now we need to increment the va
          va+=PGSIZE; 
          }
      }
    }

    for (int k = i; k < curproc->num_mappings - 1; k++) {
      curproc->memoryMappings[k] = curproc->memoryMappings[k + 1];
    }
      curproc->num_mappings--;

      break; // Exit the loop after handling the found mapping.
  }
    return 0;
}
