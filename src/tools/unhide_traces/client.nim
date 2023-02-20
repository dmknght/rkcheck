import os
import strutils
import posix


const procfs_modules = "/proc/modules"


proc rkrev_show_hidden_object(pid, comm: string) =
  echo " Hidden proccess \e[91m", comm, "\e[0m pid: \e[95m", pid, "\e[0m"


proc rkrev_show_hidden_object(mod_name: string) =
  echo " Hidden module \e[91m", mod_name, "\e[0m"


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
    rkrev_show_hidden_object($mod_name)


proc rkrev_find_hidden_proc(pid: Pid, comm: cstring) {.exportc.} =
  if not rkrev_pid_is_in_procfs($pid):
    rkrev_show_hidden_object($pid, $comm)
