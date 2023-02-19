import strutils

const procfs_modules = "/proc/modules"


proc mod_is_hidden_in_procfs(mod_name: string): bool =
  for line in lines(procfs_modules):
    if line.startsWith(mod_name):
      return false
  return true


proc find_hidden_module(mod_name: cstring) {.exportc.} =
  if mod_is_hidden_in_procfs($mod_name):
    echo "Hidden module ", $mod_name
