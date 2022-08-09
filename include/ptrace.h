#ifndef _PTRACE_H
#define _PTRACE_H

void ptrace_read(int pid, unsigned long addr, void *vptr, int len);
void ptrace_write(int pid, unsigned long addr, void *vptr, int len);

#endif
