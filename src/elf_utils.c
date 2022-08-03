#include <elf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <unistd.h>

#include <elf_utils.h>

/*
 * Read a file into memory for later manipulation
 */
struct ElfHandle read_elf_file(const char *filename) {
  printf("[+] Reading %s\n", filename);

  // Get file size
  struct stat *file_stat = (struct stat *)malloc(sizeof(struct stat));
  stat(filename, file_stat);
  printf("[+] File is %lu bytes\n", file_stat->st_size);

  // Open file
  FILE *fd = fopen(filename, "r+");
  if (fd == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }
  printf("[+] Opened file for reading\n");

  // Read file into memory for parsing
  char *elf_file = (char *)malloc(file_stat->st_size);
  unsigned long long num_read = fread(elf_file, file_stat->st_size, 1, fd);
  if (num_read != 1) {
    perror("fread");
    exit(EXIT_FAILURE);
  }
  fclose(fd);

  // Build output
  struct ElfHandle handle;
  handle.elf_file = elf_file;
  handle.file_stat = file_stat;
  handle.elf_header = (Elf64_Ehdr *)elf_file;
  handle.shdr_base = (Elf64_Shdr *)&elf_file[handle.elf_header->e_shoff];
  handle.phdr_base = (Elf64_Phdr *)&elf_file[handle.elf_header->e_phoff];
  handle.string_table =
      &elf_file[(handle.shdr_base + handle.elf_header->e_shstrndx)->sh_offset];
  return handle;
}

/*
 * Cleanup any dynamically allocated parts created during reading in an ELF file
 */
void cleanup_elf_file(struct ElfHandle elf_handle) {
  free(elf_handle.elf_file);
  free(elf_handle.file_stat);
}

/*
 * Find and display the program interpreter
 */
int find_interpreter(const struct ElfHandle elf_handle) {
  Elf64_Phdr *phdr = elf_handle.phdr_base;
  for (int i = 0; i < elf_handle.elf_header->e_phnum; ++i) {
    if (phdr->p_type == PT_INTERP) {
      printf("Interpreter found at program header: %u\n", i);
      printf("Interpreter is: %s\n", &elf_handle.elf_file[phdr->p_offset]);
      return i;
    }
    ++phdr;
  }
  return -1;
}

/*
 * Enumerate the file sections
 */
void display_sections(const struct ElfHandle elf_handle) {
  printf("[+] Displaying section names\n");
  if (elf_handle.elf_header->e_shnum == 0 ||
      elf_handle.elf_header->e_shoff == 0) {
    fprintf(stderr, "[-] Unable to enumerate sections since no section header "
                    "table exists\n");
    exit(EXIT_FAILURE);
  }
  Elf64_Shdr *shdr = elf_handle.shdr_base;
  for (unsigned i = 0; i < elf_handle.elf_header->e_shnum; ++i) {
    printf("\t%u --> %s\n", i, &elf_handle.string_table[(shdr++)->sh_name]);
  }
}

/*
 * Find text segment index
 */
int find_text_segment(const struct ElfHandle elf_handle) {
  Elf64_Phdr *phdr = elf_handle.phdr_base;
  for (int text_phdr_index = 0;
       text_phdr_index < elf_handle.elf_header->e_phnum; ++text_phdr_index) {
    if ((phdr->p_flags & PF_X) == PF_X) {
      printf("[+] Found text segment at index: %d\n", text_phdr_index);
      return text_phdr_index;
    }
    phdr++;
  }
  return -1;
}

/*
 * Find the data segment index
 */
int find_data_segment(const struct ElfHandle elf_handle) {
  Elf64_Phdr *phdr = elf_handle.phdr_base;
  for (int data_phdr_index = 0;
       data_phdr_index < elf_handle.elf_header->e_phnum; ++data_phdr_index) {
    if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_R) == PF_R &&
        (phdr->p_flags & PF_W) == PF_W) {
      printf("[+] Found data segment at index: %d\n", data_phdr_index);
      return data_phdr_index;
    }
    phdr++;
  }
  return -1;
}

/*
 * Find a PT_NOTE segment index
 */
int find_note_segment(const struct ElfHandle elf_handle) {
  Elf64_Phdr *phdr = elf_handle.phdr_base;
  for (int note_phdr_index = 0;
       note_phdr_index < elf_handle.elf_header->e_phnum; ++note_phdr_index) {
    if (phdr->p_type == PT_NOTE) {
      printf("[+] Found a note segment at index: %d\n", note_phdr_index);
      return note_phdr_index;
    }
    phdr++;
  }
  return -1;
}

/*
 * Find a section by name
 */
int find_section_index(const struct ElfHandle elf_handle,
                       const char *section_name) {
  if (elf_handle.elf_header->e_shnum == 0 ||
      elf_handle.elf_header->e_shoff == 0) {
    fprintf(stderr, "[-] Unable to find a section in a binary with no section "
                    "header table\n");
    return -1;
  }
  Elf64_Shdr *shdr = elf_handle.shdr_base;
  for (int i = 0; i < elf_handle.elf_header->e_shnum; ++i) {
    if (strcmp(elf_handle.string_table + shdr->sh_name, section_name) == 0) {
      printf("[+] Found section (%s) at index: %d\n", section_name, i);
      return i;
    }
  }
  return -1;
}

/*
 * Catch if a debugger is attached
 */
void catch_attached_debugger() {
  if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
    printf("[-] A debugger is attached, bailing out\n");
    kill(getpid(), SIGKILL);
    exit(0);
  }
}
