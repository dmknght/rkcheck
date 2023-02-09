import os
import strutils
import posix


proc pid_is_in_procfs(pid: string): bool =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir and path.endsWith(pid):
      return true
  return false


proc find_hidden_proc(pid: Pid, comm: cstring) {.exportc.} =
  if not pid_is_in_procfs($pid):
    echo "Hidden pid ", $pid, " name: ", comm
