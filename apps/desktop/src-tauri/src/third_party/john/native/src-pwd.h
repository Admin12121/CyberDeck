/* msys build stub: the msys runtime exports getpwuid/getuid/endpwent. */
#ifndef JOHN_PWD_STUB_H
#define JOHN_PWD_STUB_H
struct passwd { char *pw_name; char *pw_passwd; unsigned long pw_uid; unsigned long pw_gid; char *pw_gecos; char *pw_dir; char *pw_shell; };
struct passwd *getpwuid(unsigned long uid);
unsigned long getuid(void);
void setpwent(void);
void endpwent(void);
#endif
