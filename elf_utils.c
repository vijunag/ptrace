
#include <stdio.h> // NULL definition
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h> //off_t
#include <sys/mman.h>
#include <elf.h>

#include "elf_utils.h" //Generic macros


Elf_Phdr *elf_find_phdr_by_address(Elf_Ehdr *e, Elf_Addr addr, int idx)
{
  Elf_Phdr *p;
  int i;

  p = (Elf_Phdr *)((char *)e + e->e_phoff);
  for (i = idx; i < e->e_phnum; i++) {
    if (addr >= p[i].p_vaddr &&
        addr < p[i].p_vaddr + p[i].p_filesz)
      return (&p[i]);
  }
  return (NULL);
}

Elf_Phdr *elf_find_phdr_by_type(Elf_Ehdr *e, int type, int idx)
{
  Elf_Phdr *p;
  int i;

  p = (Elf_Phdr *)((char *)e + e->e_phoff);
  for (i = idx; i < e->e_phnum; i++) {
    if (p[i].p_type == type)
      return (&p[i]);
  }
  return (NULL);
}

Elf_Shdr *elf_find_shdr(Elf_Ehdr *e, char *name, int idx)
{
  char *shstrtab;
  Elf_Shdr *sh;
  int i;

  if (e->e_shoff == 0)
    return (NULL);
  sh = (Elf_Shdr *)((char *)e + e->e_shoff);
  shstrtab = (char *)e + sh[e->e_shstrndx].sh_offset;
  for (i = idx; i < e->e_shnum; i++) {
    if (strcmp(name, shstrtab + sh[i].sh_name) == 0)
      return (&sh[i]);
  }
  return (NULL);
}

Elf_Sym *elf_find_sym_by_address(Elf_Ehdr *e, Elf_Addr addr)
{
  Elf_Shdr *sh;
  Elf_Sym *st;
  int i;

  if ((sh = elf_find_shdr(e, ".symtab", 0)) == NULL)
    return (NULL);
  st = (Elf_Sym *)((char *)e + sh->sh_offset);
  for (i = 0; i < sh->sh_size / sizeof(*st); i++) {
    if (addr >= st[i].st_value &&
        addr < st[i].st_value + st[i].st_size)
      return (&st[i]);
  }
  return (NULL);
}

Elf_Sym *elf_find_sym_by_name(Elf_Ehdr *e, char *name)
{
  Elf_Shdr *sh;
  Elf_Sym *st;
  char *strtab;
  int i;

  if ((sh = elf_find_shdr(e, ".strtab", 0)) == NULL)
    return (NULL);
  strtab = (char *)e + sh->sh_offset;
  if ((sh = elf_find_shdr(e, ".symtab", 0)) == NULL)
    return (NULL);
  st = (Elf_Sym *)((char *)e + sh->sh_offset);
  for (i = 0; i < sh->sh_size / sizeof(*st); i++) {
    if (strcmp(name, strtab + st[i].st_name) == 0)
      return (&st[i]);
  }
  return (NULL);
}

Elf_Ehdr *elf_map_file(char *name, off_t *sz)
{
  struct stat st;
  Elf_Ehdr *e;
  char *v;
  int fd;

  if ((fd = open(name, O_RDONLY)) < 0 ||
      fstat(fd, &st) < 0)
    perror("open error");
  v = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if ((e = (Elf_Ehdr *)v) == MAP_FAILED)
    perror("mmap failure");
  if (!IS_ELF(*e))
    perror("not an elf file");
  if (sz != NULL)
    *sz = st.st_size;
  return (e);
}

void *elf_translate_core_address(Elf_Ehdr *e, Elf_Addr addr)
{
  Elf_Phdr *p;

  p = elf_find_phdr_by_address(e, addr, 0);
  if (p == NULL)
    return (NULL);
  return (char *)e + p->p_offset + (addr - p->p_vaddr);
}

int elf_search_symbol(Elf_Ehdr *ehdr,
											Elf_Addr addr, 
                      Elf_Addr *value, 
                      char **name)
{
  char *strtab;
  Elf_Shdr *sh;
  Elf_Sym *st;
  int i;

  if ((st = elf_find_sym_by_address(ehdr, addr)) != NULL &&
      (sh = elf_find_shdr(ehdr, ".strtab", 0)) != NULL) {
    strtab = (char *)ehdr + sh->sh_offset;
    *name = strtab + st->st_name;
    *value = 0 + st->st_value;
    return (1);
  }
  *name = NULL;
  *value = 0;
  return (0);
}

