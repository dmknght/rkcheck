import os
import strutils

#[
  Fork version of https://github.com/sandflysecurity/sandfly-processdecloak/ in Nim
  License: MIT
]#
const
  MAX_PID = 4194304

type
  PidStat = object
    pid: int
    tgid: int
    ppid: int


proc map_pid(procfs: string): PidStat =
  var
    map_pid: PidStat

  for line in lines(procfs & "/status"):
    if line.startsWith("Pid:"):
      map_pid.pid = parseInt(line.split()[^1])
    elif line.startsWith("Tgid"):
      map_pid.tgid = parseInt(line.split()[^1])
    elif line.startsWith("PPid:"):
      map_pid.ppid = parseInt(line.split()[^1])
      return map_pid


proc check_hidden(procfs: string): bool =
  var pid_stat: PidStat
  pid_stat = map_pid(procfs)

  if pid_stat.pid == pid_stat.tgid and pid_stat.ppid > 0:
    for kind, path in walkDir("/proc/"):
      if kind == pcDir and path == procfs:
        # proc is listed
        return false
    return true
  else:
    return false

proc readable_pid(procfs: string): bool =
  try:
    # TODO read maps is huge. Try faster solution?
    discard readFile(procfs & "/maps")
    return true
  except:
    return false

for i in countup(1, MAX_PID):
  let
    procfs = "/proc/" & $i
  if dirExists(procfs) and readable_pid(procfs):
    if check_hidden(procfs):
      echo "Hidden process: ", i

echo "Checking hidden processes completed"
