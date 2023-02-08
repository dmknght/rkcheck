import os
import strutils
import posix


proc pid_is_in_procfs(pid: string): bool =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir and path.endsWith(pid):
      return true
  return false


proc find_hidden_proc(list_pids: openArray[Pid]) {.exportc.} =
  for pid in list_pids:
    if not pid_is_in_procfs($pid):
      echo "Hidden pid ", pid # TODO get the actual pid from kernel
