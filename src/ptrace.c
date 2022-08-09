#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "ptrace.h"

/*
 * Read @len bytes from process memory 
 */
void ptrace_read(int pid, unsigned long addr, void *vptr, int len) {
  int bytesRead = 0;
  int i = 0;
  long word = 0;
  long *ptr = (long *)vptr;

  while (bytesRead < len) {
    word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
    if (word == -1) {
      fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
      exit(EXIT_FAILURE);
    }
    bytesRead += sizeof(word);
    ptr[i++] = word;
  }
}

/*
 * Write @len bytes into process memory
 */
void ptrace_write(int pid, unsigned long addr, void *vptr, int len) {
  int byteCount = 0;
  long word = 0;

  while (byteCount < len) {
    memcpy(&word, vptr + byteCount, sizeof(word));
    word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
    if (word == -1) {
      fprintf(stderr, "ptrace(PTRACE_POKETEXT) failed\n");
      exit(EXIT_FAILURE);
    }
    byteCount += sizeof(word);
  }
}
