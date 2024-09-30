#[
  A script to detect hooked functions from ld_preload
  Original idea: https://github.com/mempodippy/detect_preload/ (No LICENSE)
]#

import os
import std/dynlib


const
  PATH_LD_PRELOAD = "/etc/ld.so.preload"
  COMMON_FUNCTIONS = ["rename", "renameat", "stat", "stat64", "fstat", "fstat64", "lstat", "lstat64", "__lxstat", "__lxstat64", "__fxstat", "__fxstat64", "__xstat", "__xstat64"]


{.emit: """

#include <dlfcn.h>

int rk_check_each_symbol(char *symb_name) {
  void *libc_handler;
  
  if (!(libc_handler = dlopen("libc.so.6", RTLD_LAZY)))
  {
    return -1;
  }

  void *symb_from_libc, *symb_from_curr;
  int result;

  symb_from_libc = dlsym(libc_handler, symb_name);
  symb_from_curr = dlsym(RTLD_NEXT, symb_name);

  if (symb_from_libc != symb_from_curr)
  {
    result == 1; // 1 == different
  }
  else
  {
    result == 0; // Same
  }

  // Missing info

  dlclose(libc_handler);
  return result;
}

""".}


proc rk_check_each_symbol(symb_name: cstring): cint {.importc: "rk_check_each_symbol".}


# proc rk_check_each_symbol(symb_name: string) =
#   var libc_handler = loadLib("libc.so.6") # NOTICE open flag is RTLD_LAZY
#   let
#     sym_from_libc = libc_handler.symAddr(symb_name)
#   # get sym and compare
#   libc_handler.unloadLib()



proc rk_find_hook() =
  for check_func in COMMON_FUNCTIONS:
    if rk_check_each_symbol(check_func) == cint(1):
      echo "Detect hooked: ", check_func


proc main() =
  if fileExists(PATH_LD_PRELOAD):
    # DO something with this
    discard
  else:
    # Find hooked functions
    rk_find_hook()


main()
