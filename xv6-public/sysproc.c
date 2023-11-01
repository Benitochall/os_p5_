#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
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
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

// here is our kernal level program, this will eventually call our user level
// program that is defined in proc.c get args from user space
int sys_mmap(void)
{
  void* addr; // the requested address
  int length; // the size of memory needed
  int prot; // read or write flags
  int flags; // indicates file backed mapping 
  int fd; // file descirptors 
  int offset; // the offest into the file
  // struct proc *curproc = myproc();

  if (argint(0, (void*) &addr) < 0 || argint(1, &length) < 0 || argint(2, &prot) < 0 || argint(3, &flags) < 0 || argint(4, &fd) < 0 || argint(5, &offset) < 0) {
      return -1;
  }

  cprintf("%d\n", addr);
  cprintf("%d\n", length);
  cprintf("%d\n", prot);
  cprintf("%d\n", flags);
  cprintf("%d\n", fd);
  cprintf("%d\n", offset);
  if (length <= 0 || (int) addr < 0x60000000 || (int) addr > 0x80000000 - PGSIZE || (int)addr % PGSIZE != 0)
      return -1;

  // this is where we need to call mmap
  mmap(addr, length, prot, flags, fd, offset); 
  return 0;
}

// the goal of this function is unmap memory, we need to get args from the user spac e
int sys_munmap(void)
{
  return 0;
}
