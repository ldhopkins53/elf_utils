//
// Created by luke on 02/08/2022.
//

#include <elf.h>
#include <sys/stat.h>

#ifndef COUNTER_INJECTION_ELF_UTILS_H
#define COUNTER_INJECTION_ELF_UTILS_H

#define _PAGE_ALIGN(x) (x & ~(4096 - 1))
#define PAGE_ALIGN_UP(x) (_PAGE_ALIGN(x) + 4096)
#define PAGE_ROUND PAGE_ALIGN_UP

struct ElfHandle {
  char *elf_file;
  struct stat *file_stat;
  Elf64_Ehdr *elf_header;
  Elf64_Shdr *shdr_base;
  Elf64_Phdr *phdr_base;
  char *string_table;
};

struct ElfHandle read_elf_file(const char *filename);
void cleanup_elf_file(struct ElfHandle elf_handle);
int find_interpreter(struct ElfHandle elf_handle);
void display_sections(struct ElfHandle elf_handle);
int find_text_segment(struct ElfHandle elf_handle);
int find_data_segment(struct ElfHandle elf_handle);
int find_note_segment(struct ElfHandle elf_handle);
int find_section_index(const struct ElfHandle elf_handle,
                       const char *section_name);
void catch_attached_debugger();

#endif // COUNTER_INJECTION_ELF_UTILS_H
