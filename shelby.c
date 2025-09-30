#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>

#define RED "\033[31m"
#define YELLOW "\033[33m"
#define DEFAULT "\033[0m"

void  check_file(char *file)
{
  struct stat file_stat;

  if (stat(file, &file_stat) < 0)
  {
    printf(RED "ERROR: " DEFAULT "No such file\n");
    exit(1);
  }

  if (!(file_stat.st_mode & S_IRUSR))
  {
    printf(RED "ERROR: " DEFAULT "File does not have read permission\n");
    exit(1);
  }
}

void  check_if_elf(Elf64_Ehdr header)
{
  /* Checking if file is elf by magic number first bytes */
  if (header.e_ident[EI_MAG0] != ELFMAG0 ||
      header.e_ident[EI_MAG1] != ELFMAG1 ||
      header.e_ident[EI_MAG2] != ELFMAG2 ||
      header.e_ident[EI_MAG3] != ELFMAG3)
  {
    printf("Not an ELF file\n");
    exit(1);
  }
}

uint64_t find_text_offset(int elf, Elf64_Ehdr elf_header)
{
  Elf64_Phdr  program_header;

  /* Jumping to Program Header Table */
  lseek(elf, elf_header.e_phoff, SEEK_SET);
  read(elf, &program_header, sizeof(Elf64_Phdr));

  /* Searching for first executable segment and jump to it*/
  while (program_header.p_type != PT_LOAD || !(program_header.p_flags & PF_X)) 
    read(elf, &program_header, sizeof(Elf64_Phdr));
  lseek(elf, program_header.p_offset, SEEK_SET);

  /* Returning the size of executable segment */
  return (program_header.p_filesz);
}

void  print_shellcode(unsigned char *text, uint64_t bytes)
{
  int           null_byte = 0;

  printf("\"");
  for (uint64_t i = 0; i < bytes; i++)
  {
    if (text[i] == 0x0)
    {
      null_byte = 1;
      printf(RED "\\x%02x" DEFAULT, text[i]);
    }
    else
      printf("\\x%02x", text[i]);
  }
  printf("\"\n");
  if (null_byte)
    printf(YELLOW "WARNING: " DEFAULT "Null byte in shellcode\n");
}

int   main(int argc, char **argv)
{
  int           elf;
  uint64_t      bytes;
  unsigned char *text;
  Elf64_Ehdr    elf_header;

  if (argc == 1)
  {
    printf(RED "ERROR: " DEFAULT "Usage: %s <executable>\n", argv[0]);
    return 1;
  }

  check_file(argv[1]);
  elf = open(argv[1], O_RDONLY);
  if (elf < 0)
  {
    printf(RED "ERROR: " DEFAULT "Cannot open %s\n", argv[1]);
    return 1;
  }

  read(elf, &elf_header, sizeof(Elf64_Ehdr));
  check_if_elf(elf_header);
  bytes = find_text_offset(elf, elf_header);

  text = malloc(bytes);
  if (!text)
  {
    printf(RED "ERROR: " DEFAULT "Memory allocation error\n");
    return 1;
  }
  
  read(elf, text, bytes);
  print_shellcode(text, bytes);
  free(text);
  close(elf);
  return 0;
}
