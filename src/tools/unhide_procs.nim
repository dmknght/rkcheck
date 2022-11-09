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
    name: string


proc map_pid(procfs: string): PidStat =
  var
    map_pid: PidStat

  for line in lines(procfs & "/status"):
    if line.startsWith("Name:"):
      map_pid.name = line.split()[^1]
    elif line.startsWith("Pid:"):
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
    echo "Hidden process: ", pid_stat.pid, " name: ", pid_stat.name
    return true
  else:
    return false

var
  has_hidden_process = false

for i in countup(1, MAX_PID):
  let
    procfs = "/proc/" & $i

  if dirExists(procfs) and check_hidden(procfs):
    has_hidden_process = true

echo "Checking hidden processes completed"
if has_hidden_process:
  echo "Found hidden processes. Possibly rootkit?"
else:
  echo "No hidden processes found"
