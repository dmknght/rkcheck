#[
  A script to detect hooked functions from ld_preload
  Original idea: https://github.com/mempodippy/detect_preload/ (No LICENSE)
]#

{.emit: """

#include <dlfcn.h>
#include <stdio.h>

void rk_check_each_symbol() {
  void *libc_handler;
  
  if (!(libc_handler = dlopen("libc.so.6", RTLD_LAZY)))
  {
    return;
  }

  char *symb_name;
  char *COMMON_FUNCTIONS[] = {"rename", "renameat", "stat", "stat64", "fstat", "fstat64", "lstat", "lstat64", "__lxstat", "__lxstat64", "__fxstat", "__fxstat64", "__xstat", "__xstat64", NULL};
  int i = 0;

  while (symb_name = COMMON_FUNCTIONS[i++])
  {
    void *symb_from_libc, *symb_from_curr;

    symb_from_libc = dlsym(libc_handler, symb_name);
    symb_from_curr = dlsym(RTLD_NEXT, symb_name);

    if (symb_from_libc != symb_from_curr)
    {
      Dl_info real_nfo, curr_nfo;

      dladdr(symb_from_libc, &real_nfo);
      dladdr(symb_from_curr, &curr_nfo);

      printf("[-] Hijacked \033[1;31m%s\033[0m: %s\n", symb_name, curr_nfo.dli_fname);
    }
  }

  dlclose(libc_handler);
}

""".}


proc rk_check_each_symbol() {.importc: "rk_check_each_symbol".}


rk_check_each_symbol()
