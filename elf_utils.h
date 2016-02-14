
#ifndef __ELF_UTILS_H_
#define __ELF_UTILS_H_

#include <elf.h> //The base elf

#define Elf_Addr unsigned long

#ifdef __x86_64__
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym  Elf64_Sym
#define Elf_Ehdr Elf64_Ehdr
#else /*__i386__*/
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym  Elf32_Sym
#define Elf_Ehdr Elf32_Ehdr
#endif /*__x86_64__*/

#ifndef IS_ELF
#define IS_ELF(ehdr)  ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
       (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
       (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
       (ehdr).e_ident[EI_MAG3] == ELFMAG3)
#endif /*IS_ELF*/

Elf_Phdr *elf_find_phdr_by_address(Elf_Ehdr *e, Elf_Addr addr, int idx);
Elf_Phdr *elf_find_phdr_by_type(Elf_Ehdr *e, int type, int idx);
Elf_Shdr *elf_find_shdr(Elf_Ehdr *e, char *name, int idx);
Elf_Sym *elf_find_sym_by_address(Elf_Ehdr *e, Elf_Addr addr);
Elf_Sym *elf_find_sym_by_name(Elf_Ehdr *e, char *name);
Elf_Ehdr *elf_map_file(char *name, off_t *sz);
void *elf_translate_core_address(Elf_Ehdr *e, Elf_Addr addr);
int elf_search_symbol(Elf_Ehdr *ehdr, Elf_Addr addr, Elf_Addr *value, 
                      char **name);

#endif /*__ELF_UTILS_H_ */
