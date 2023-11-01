#include "types.h"
#include "stat.h"
#include "user.h"

int main(void) 
{
    int addr = 1610612737; // the requested address
    int length = 4096; // the size of memory needed
    int prot =0 ; // read or write flags
    int flags = 0; // indicates file backed mapping 
    int fd =0 ; // file descirptors 
    int offset = 0; // the offest into the file
    mmap((void *)addr, length ,prot, flags, fd, offset);
    exit();
} 