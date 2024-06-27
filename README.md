# xv6 Memory Mapping

This project implements memory mapping in xv6, hiding the implementation details from the user of how virtual memory is mapped to physical memory. It creates two system calls: `mmap` and `munmap`.

## mmap()

`mmap()` has two modes of operation: anonymous and file-backed. Anonymous functions like `malloc` in C, while file-backed writes to a file when `munmap` is called and the `MAP_SHARED` flag is used. 

**Method signature:** 
```c
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
```
- `addr`: The virtual address that `mmap` could/should place the mapping at depending on flags.
- `length`: The length of the mapping in bytes.
- `prot`: The protections for the memory region (e.g., `PROT_READ | PROT_WRITE`).
- `fd`: The file descriptor for file-backed mapping.
- `offset`: The offset into the file.
- `flags`: All possible flags to be used with `mmap` (see `mmap.h`).

Returns the starting virtual address of the mapping.

### Flags
- `MAP_ANONYMOUS`: Not file-backed mapping.
- `MAP_SHARED`: Changes made to the child process are visible to the parent and vice versa.
- `MAP_PRIVATE`: Each process has its own copy of the mapping, same virtual but different physical.
- `MAP_FIXED`: When this flag is set, the mapping must be placed at the specified virtual address.
- `MAP_GROWSUP`: When set, touching the page above the current mapping (the guard page) will not cause a segfault but will instead grow the mapping upward.

## munmap()

Removes `length` bytes starting from the virtual address and then, if `MAP_SHARED` was set, writes memory back to the file used. 

**Method signature:** 
```c
int munmap(void *addr, size_t length)
```

# Implementation

## proc.h

I first defined some new structs in `proc.h` and assigned each process to have some new state variables. Specifically, each process has an array of `mem_mapping` structs. These structs contain:

```c
struct mem_mapping {
  uint addr; // Starting virtual address
  int length; // Length of the mapping in bytes
  int flags;  // Flags as passed to mmap (e.g., MAP_FIXED, MAP_ANONYMOUS, etc.)
  int fd;     // File descriptor for file-backed mappings, if applicable
  int originalLength;
  int allocated; // If the memory is currently allocated
};
```

Each process also keeps track of the number of mappings it currently has. 

## System Calls in syscall.h

Created system calls `sys_mmap` and `sys_munmap`.

### sys_mmap()

Verifies the arguments to `mmap` from user space and then finds a free virtual address that is not in use. Sets up all instance variables for the `mem_mapping` struct. Returns the new address.

### sys_munmap()

Gets the address of the memory that should be unmapped along with the length. Gets the mapping table of the current process, searches for the mapping, removes the mapping from the `mapping_table`, and flushes the page to the specified file if not `MAP_ANON`.

## proc.c

### Modifying fork()

Since when `MAP_SHARED` is used the virtual address mappings of the child process must be accessible from the parent and vice versa, I copy the memory mappings from the current process's `memoryMappings` array to the child's `memoryMappings` array. When `MAP_PRIVATE` is used, things get a little more complicated as I need to share virtual mappings but hide physical mappings. I go through all address blocks allocated for a specific mapping, find the page table entry (PTE) (the physical mapping for the page), and set it to read-only. Then, I create a new virtual to physical mapping for the child process. This ensures that the same virtual address is used but different physical pages.

### Modifying exit()

I clear the memory mappings when a process exits, effectively freeing memory.

### int count_children(struct proc *parent_proc)

A helper function to count the number of child processes.

### Modifying the page_fault_handler()

There are a couple of different accesses that can cause a page fault.
- **Case 1:** The page we tried to write to has the COW flag set. In this instance, we just copy the page and change its permissions to be writable.
- **Case 2:** I implemented lazy allocation and need to allocate memory for the actual page using `kalloc()`.
  - **Case 2a:** `MAP_GROWSUP` is used. In this case, I check to see if I have the memory mapping for the specific address the program segfaulted on in my memory mappings, then add an additional mapping for the guard page above it.
  - **Case 2b:** `MAP_ANON` was not used. In this case, I write the page to a file provided.
- **Case 3:** The virtual address was not in my mappings table and should indeed return a segfault.





