
import .. / .. / libs / libyara / nim_yara
import .. / cores / eng_cores
import os
import strutils


proc cb_yr_process_scan(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    let
      data = cast[ProcScanContext](user_data)
      bin_path = data.scan_object.cmdline.split(" ")[0] # binary should be the first. # TODO handle binary with space in name with custom name parser
    echo cast[ptr YR_RULE](message_data).ns.name, ":", cast[ptr YR_RULE](message_data).identifier, " ", bin_path, " pid: ", data.scan_object.pid
    return CALLBACK_ABORT
  else:
    # cast[ProcScanContext](user_data).virus_name = ""
    return CALLBACK_CONTINUE

# proc rscanner_scan_proc(pid: int) =


proc rscanner_scan_proc(context: var ProcScanContext) =
  context.scan_object.cmdline = readFile(context.scan_object.pid_path & "/cmdline")
  # TODO handle parent pid, child pid, ... to do ignore scan
  # TODO sometime the actual malicious part is cmdline (python3 -c <reverse shell> for example. We scan it as well)
  discard yr_rules_scan_proc(
    context.ScanEngine.YaraEng,
    cint(context.scan_object.pid),
    0,
    cb_yr_process_scan,
    addr(context),
    yr_scan_timeout
  )


proc rscanner_new_proc_scan*(engine: CoreEngine, pid: int) =
  var ScanContext: ProcScanContext
  ScanContext.ScanEngine = engine
  ScanContext.scan_object.pid = pid
  ScanContext.scan_object.pid_path = "/proc/" & intToStr(pid)
  rscanner_scan_proc(ScanContext)


proc rscanner_new_procs_scan*(engine: CoreEngine) =
  var ScanContext: ProcScanContext
  ScanContext.ScanEngine = engine
  for kind, path in walkDir("/proc/"):
    if kind == pcDir:
      try:
        let pid = parseInt(path.split("/")[^1])
        ScanContext.scan_object.pid = pid
        ScanContext.scan_object.pid_path = path
        rscanner_scan_proc(ScanContext)
      except ValueError:
        # This is not a process from procfs
        discard

