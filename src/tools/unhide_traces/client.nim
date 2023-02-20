import os
import strutils
import posix


const procfs_modules = "/proc/modules"


proc rkrev_mod_is_hidden_in_procfs(mod_name: string): bool =
  for line in lines(procfs_modules):
    if line.startsWith(mod_name):
      return false
  return true


proc rkrev_pid_is_in_procfs(pid: string): bool =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir and path.endsWith(pid):
      return true
  return false


proc rkrev_find_hidden_module(mod_name: cstring) {.exportc.} =
  if rkrev_mod_is_hidden_in_procfs($mod_name):
    echo "Hidden module ", $mod_name


proc rkrev_find_hidden_proc(pid: Pid, comm: cstring) {.exportc.} =
  if not rkrev_pid_is_in_procfs($pid):
    echo "Hidden pid ", $pid, " name: ", comm
