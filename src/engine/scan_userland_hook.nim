#[
  A script to detect hooked functions from ld_preload
  Original idea: https://github.com/mempodippy/detect_preload/ (No LICENSE)
]#

import .. / cli / print_utils
import strutils

{.emit: """

#include <dlfcn.h>
#include <stdio.h>


char *rk_hook_find_hijack_func() {
  void *libc_handler;
  
  if (!(libc_handler = dlopen("libc.so.6", RTLD_LAZY)))
  {
    return;
  }

  char *symb_name;
  char *COMMON_FUNCTIONS[] = {"rename", "renameat", "stat", "stat64", "fstat", "fstat64", "lstat", "lstat64",
   "__lxstat", "__lxstat64", "__fxstat", "__fxstat64", "__xstat", "__xstat64", "access", "unlink", "strstr" ,
   "fgets", "fopen", "fopen64", "open", "opendir", "opendir64", "readdir", "readdir64", "unlinkat", NULL};
  int i = 0;

  while (symb_name = COMMON_FUNCTIONS[i++])
  {
    void *symb_from_libc, *symb_from_curr;

    symb_from_libc = dlsym(libc_handler, symb_name);
    symb_from_curr = dlsym(RTLD_NEXT, symb_name);

    if (symb_from_libc != symb_from_curr)
    {
      Dl_info curr_nfo;
      dladdr(symb_from_curr, &curr_nfo);
      dlclose(libc_handler);
      return curr_nfo.dli_fname;
    }
  }

  dlclose(libc_handler);
}

""".}


proc rk_hook_find_hijack_func(): cstring {.importc: "rk_hook_find_hijack_func".}


proc rk_hook_scan_userland*() =
  # FIXME this module should handle multiple infections
  let
    path_hooked_lib = $rk_hook_find_hijack_func()

  if not isEmptyOrWhitespace(path_hooked_lib):
    print_file_infected("Heur:Rootkit.FuncHook", path_hooked_lib)
