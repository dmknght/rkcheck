import .. / .. / libs / libyara / nim_yara
import .. / cores / [eng_cores, eng_cli_progress]
import strutils


proc cb_yr_process_scan_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    let
      data = cast[ptr ProcInfo](user_data)
      rule = cast[ptr YR_RULE](message_data)
    cli_progress_flush()
    echo rule.ns.name, ":", replace($rule.identifier, "_", "."), " ", data.binary_path, " (pid: ", data.pid, ")"
    return CALLBACK_ABORT
  else:
    return CALLBACK_CONTINUE


proc pscanner_scan_proc*(context: var ProcScanContext) =
  # context.scan_object.cmdline = readFile(context.scan_object.pid_path & "/cmdline")
  # TODO handle parent pid, child pid, ... to do ignore scan
  # TODO sometime the actual malicious part is cmdline (python3 -c <reverse shell> for example. We scan it as well)
  cli_progress_scan_process(context.scan_object.pid, context.scan_object.binary_path)
  discard yr_rules_scan_proc(
    context.ScanEngine.YaraEng,
    cint(context.scan_object.pid),
    0,
    cb_yr_process_scan_result,
    addr(context.scan_object),
    yr_scan_timeout
  )
  cli_progress_flush()
