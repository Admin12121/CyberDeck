/* mingw compat: minimal sys/mman.h — john's memory-map paths are gated by
 * configure (no mmap support in the mingw build), but the header include is
 * unconditional in one shared header. */
#ifndef JOHN_COMPAT_SYS_MMAN_H
#define JOHN_COMPAT_SYS_MMAN_H
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_SHARED  0x01
#define MAP_PRIVATE 0x02
#define MAP_FAILED ((void *)-1)
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
int munmap(void *addr, unsigned long len);
#endif
