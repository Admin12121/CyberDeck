/* mingw compat: minimal sys/times.h for john's status accounting. */
#ifndef JOHN_COMPAT_SYS_TIMES_H
#define JOHN_COMPAT_SYS_TIMES_H
typedef long clock_t;
#define CLOCKS_PER_SEC 1000
struct tms { long tms_utime, tms_stime, tms_cutime, tms_cstime; };
clock_t times(struct tms *);
#endif
