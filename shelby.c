#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define DEFAULT "\033[0m"

int is_32 = 0;

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

void  check_if_elf_64(Elf64_Ehdr header)
{
  if (header.e_ident[EI_MAG0] != ELFMAG0 ||
      header.e_ident[EI_MAG1] != ELFMAG1 ||
      header.e_ident[EI_MAG2] != ELFMAG2 ||
      header.e_ident[EI_MAG3] != ELFMAG3)
  {
    printf(RED "ERROR: " DEFAULT "Not an ELF file\n");
    exit(1);
  }
  if (header.e_ident[EI_CLASS] == ELFCLASS32)
  {
    printf(RED "ERROR: " DEFAULT "For x32 bit architecture us -x parameter\n");
    exit(1);
  }
}

uint64_t find_text_offset_64(int elf, Elf64_Ehdr elf_header)
{
  Elf64_Phdr  program_header;

  lseek(elf, elf_header.e_phoff, SEEK_SET);
  read(elf, &program_header, sizeof(Elf64_Phdr));
  while (program_header.p_type != PT_LOAD || !(program_header.p_flags & PF_X)) 
    read(elf, &program_header, sizeof(Elf64_Phdr));
  lseek(elf, program_header.p_offset, SEEK_SET);
  return (program_header.p_filesz);
}

void  check_if_elf_32(Elf32_Ehdr header)
{
  if (header.e_ident[EI_MAG0] != ELFMAG0 ||
      header.e_ident[EI_MAG1] != ELFMAG1 ||
      header.e_ident[EI_MAG2] != ELFMAG2 ||
      header.e_ident[EI_MAG3] != ELFMAG3)
  {
    printf(RED "ERROR: " DEFAULT "Not an ELF file\n");
    exit(1);
  }
 if (header.e_ident[EI_CLASS] == ELFCLASS64)
  {
    printf(RED "ERROR: " DEFAULT "Don't use -x if your file is x64 bit\n");
    exit(1);
  }
}

uint64_t find_text_offset_32(int elf, Elf32_Ehdr elf_header)
{
  Elf32_Phdr  program_header;

  lseek(elf, elf_header.e_phoff, SEEK_SET);
  read(elf, &program_header, sizeof(Elf32_Phdr));
  while (program_header.p_type != PT_LOAD || !(program_header.p_flags & PF_X)) 
    read(elf, &program_header, sizeof(Elf32_Phdr));
  lseek(elf, program_header.p_offset, SEEK_SET);
  return (program_header.p_filesz);
}

void  print_shellcode(unsigned char *text, uint64_t bytes)
{
  int null_byte = 0;
  int counter = 0;

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
    counter++;
  }
  printf("\"\n\n");
  if (null_byte)
    printf(YELLOW "WARNING: " DEFAULT "Null byte in shellcode\n");
  printf("Shellcode length: " GREEN "%d" DEFAULT "\n", counter);
}

void  print_help(void)
{
  printf("Usage: shelby [options] args\n\n");
  printf("Basic usage:\n    -h    show this message\n");
  printf("    -x    turn on x32 bit mode\n");
}

void  execute_for_64(char *file)
{
  int           elf;
  uint64_t      bytes;
  unsigned char *text;
  Elf64_Ehdr    elf_header;

  
  elf = open(file, O_RDONLY);
  if (elf < 0)
  {
    printf(RED "ERROR: " DEFAULT "Cannot open %s\n", file);
    exit(1);
  }

  read(elf, &elf_header, sizeof(Elf64_Ehdr));
  check_if_elf_64(elf_header);
  bytes = find_text_offset_64(elf, elf_header);

  text = malloc(bytes);
  if (!text)
  {
    printf(RED "ERROR: " DEFAULT "Memory allocation error\n");
    close(elf);
    exit(1);
  }
  
  read(elf, text, bytes);
  print_shellcode(text, bytes);
  free(text);
  close(elf);
  exit(1);
}

void  execute_for_32(char *file)
{
  int           elf;
  uint64_t      bytes;
  unsigned char *text;
  Elf32_Ehdr    elf_header;

  
  elf = open(file, O_RDONLY);
  if (elf < 0)
  {
    printf(RED "ERROR: " DEFAULT "Cannot open %s\n", file);
    exit(1);
  }

  read(elf, &elf_header, sizeof(Elf32_Ehdr));
  check_if_elf_32(elf_header);
  bytes = find_text_offset_32(elf, elf_header);

  text = malloc(bytes);
  if (!text)
  {
    printf(RED "ERROR: " DEFAULT "Memory allocation error\n");
    close(elf);
    exit(1);
  }
  
  read(elf, text, bytes);
  print_shellcode(text, bytes);
  free(text);
  close(elf);
  exit(1);
}

int   main(int argc, char **argv)
{
  int option;

  if (argc == 1)
  {
    printf(RED "ERROR: " DEFAULT "Usage:    %s <executable>\n       For more: %s -h\n", argv[0], argv[0]);
    exit(1);
  }
  while ((option = getopt(argc, argv, "hx")) != -1)
  {
    switch (option)
    {
      case 'h':
        print_help();
        exit(0);
      case 'x':
        is_32 = 1;
        break ;
      default:
        print_help();
        exit(1);
    }
  }
  check_file(argv[optind]);
  if (is_32)
    execute_for_32(argv[optind]);
  else
    execute_for_64(argv[optind]);
  return 0;
}
