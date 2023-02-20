import os
import strutils
import posix


const procfs_modules = "/proc/modules"


proc mod_is_hidden_in_procfs(mod_name: string): bool =
  for line in lines(procfs_modules):
    if line.startsWith(mod_name):
      return false
  return true


proc pid_is_in_procfs(pid: string): bool =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir and path.endsWith(pid):
      return true
  return false


proc revealerk_find_hidden_module(mod_name: cstring) {.exportc.} =
  if mod_is_hidden_in_procfs($mod_name):
    echo "Hidden module ", $mod_name


proc revealerk_find_hidden_proc(pid: Pid, comm: cstring) {.exportc.} =
  if not pid_is_in_procfs($pid):
    echo "Hidden pid ", $pid, " name: ", comm
