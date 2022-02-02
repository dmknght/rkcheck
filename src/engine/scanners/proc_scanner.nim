
import .. / .. / libs / libyara / nim_yara
import .. / cores / eng_cores
import os
import strutils


proc cb_yr_process_scan(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    let
      data = cast[ptr ProcInfo](user_data)
      rule = cast[ptr YR_RULE](message_data)
    echo rule.ns.name, ":", rule.identifier, " ", data.binary_path, " (pid: ", data.pid, ")"
    return CALLBACK_ABORT
  else:
    # cast[ProcScanContext](user_data).virus_name = ""
    return CALLBACK_CONTINUE


proc pscanner_scan_proc(context: var ProcScanContext) =
  context.scan_object.cmdline = readFile(context.scan_object.pid_path & "/cmdline")
  try:
    context.scan_object.binary_path = expandSymlink(context.scan_object.pid_path & "/exe")
  except:
    # Fix crash when pid = 1 -> exe permission denied
    context.scan_object.binary_path = context.scan_object.cmdline
  # TODO handle parent pid, child pid, ... to do ignore scan
  # TODO sometime the actual malicious part is cmdline (python3 -c <reverse shell> for example. We scan it as well)
  discard yr_rules_scan_proc(
    context.ScanEngine.YaraEng,
    cint(context.scan_object.pid),
    0,
    cb_yr_process_scan,
    addr(context.scan_object),
    yr_scan_timeout
  )


proc pscanner_new_proc_scan*(context: var ProcScanContext, pid: int) =
  context.scan_object.pid = pid
  context.scan_object.pid_path = "/proc/" & intToStr(pid)

  pscanner_scan_proc(context)


proc pscanner_new_procs_scan*(context: var ProcScanContext, pids: seq[int]) =
  for pid in pids:
    pscanner_new_proc_scan(context, pid)


proc pscanner_new_all_procs_scan*(context: var ProcScanContext) =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir:
      try:
        let pid = parseInt(path.split("/")[^1])
        context.scan_object.pid = pid
        context.scan_object.pid_path = path
        pscanner_scan_proc(context)
      except ValueError:
        # This is not a process from procfs
        discard
