
import .. / cores / eng_cores
import .. / scan / scan_processes
import os
import strutils
import scanner_consts


proc pscanner_new_proc_scan*(context: var ProcScanContext, pid: int) =
  context.proc_object.pid = pid
  context.proc_object.pid_path = sys_dir_proc & intToStr(pid)

  pscanner_scan_proc(context)


proc pscanner_new_procs_scan*(context: var ProcScanContext, pids: seq[int]) =
  for pid in pids:
    context.proc_object.pid = pid
    context.proc_object.pid_path = sys_dir_proc & intToStr(pid)
    pscanner_new_proc_scan(context, pid)


proc pscanner_new_all_procs_scan*(context: var ProcScanContext) =
  for kind, path in walkDir(sys_dir_proc):
    if kind == pcDir:
      try:
        let pid = parseInt(splitPath(path).tail)
        try:
          context.proc_object.binary_path = expandSymlink(context.proc_object.pid_path & "/exe")
        except:
          # Some processes causes permissino deny when do expandSymlink
          context.proc_object.binary_path = readFile(path & "/cmdline")
        context.proc_object.pid = pid
        context.proc_object.pid_path = path
        pscanner_scan_proc(context)
      except ValueError:
        # This is not a process from procfs
        discard
