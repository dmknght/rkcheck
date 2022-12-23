import os
import strutils
import strformat

#[
  Fork version of https://github.com/sandflysecurity/sandfly-processdecloak/ in Nim
  License: MIT
]#
const
  MAX_PID = 4194304

type
  PidStat = object
    pid: uint
    tgid: uint
    ppid: uint
    name: string
    exec: string


proc progress_bar_print(pid: int) =
  let progress = float(pid) / float(MAX_PID) * 100
  stdout.write(fmt"{progress:<2.2f}%")
  stdout.flushFile()


proc progress_bar_fush() =
  stdout.write("\e[2K\r")


proc show_process_status(pid_stat: PidStat, reason: string) =
  progress_bar_fush()
  echo "Reason: ", reason
  echo " PID: ", pid_stat.pid, " name: ", pid_stat.name
  echo " Binary: ", pid_stat.exec


proc attach_process(procfs: string, pid_stat: var PidStat): bool =
  try:
    pid_stat.exec = expandSymlink(procfs & "/exe")
  except:
    pid_stat.exec = ""

  try:
    for line in lines(procfs & "/status"):
      if line.startsWith("Name:"):
        pid_stat.name = line.split()[^1]
      elif line.startsWith("Pid:"):
        pid_stat.pid = parseUInt(line.split()[^1])
      elif line.startsWith("Tgid"):
        pid_stat.tgid = parseUInt(line.split()[^1])
      elif line.startsWith("PPid:"):
        pid_stat.ppid = parseUInt(line.split()[^1])
        return true
  except IOError:
    pid_stat.pid = parseUInt(splitPath(procfs).tail)
    return false


proc check_hidden(procfs: string): bool =
  var
    pid_stat: PidStat

  if not attach_process(procfs, pid_stat):
    show_process_status(pid_stat, "Hidden process: Prevent attaching status")
    return true

  if pid_stat.exec.endsWith("(deleted)"):
    show_process_status(pid_stat, "Fileless process: Binary was removed")
  if pid_stat.pid == pid_stat.tgid and pid_stat.ppid > 0:
    for kind, path in walkDir("/proc/"):
      if kind == pcDir and path == procfs:
        # proc is listed
        return false
    show_process_status(pid_stat, "Hidden process: Hide from ProcFS")
    return true
  else:
    return false

var
  has_hidden_process = false

for i in countup(1, MAX_PID):
  let
    procfs = "/proc/" & $i

  progress_bar_print(i)
  if dirExists(procfs) and check_hidden(procfs):
    has_hidden_process = true
  progress_bar_fush()


progress_bar_fush()
echo "Checking hidden processes completed"
if has_hidden_process:
  echo "Found hidden processes. Possibly rootkit?"
else:
  echo "No hidden processes found"
