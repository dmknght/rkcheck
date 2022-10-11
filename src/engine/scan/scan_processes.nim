import .. / .. / libs / libyara / nim_yara
import .. / .. / libs / libclamav / nim_clam
import .. / cores / [eng_cores, eng_cli_progress]
import strutils
import os
import scan_utils


proc cb_yr_virus_found(ctx: var ProcScanContext) =
  #[
    Print virus found message with file path
  ]#
  cli_progress_flush()
  fscanner_on_process_matched($ctx.virus_name, $ctx.proc_object.binary_path, ctx.proc_object.pid)
  cli_progress_flush()


proc cb_yr_process_scan_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanContext](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    return fscanner_on_rule_matched(ctx.scan_result, ctx.virus_name, $rule.ns.name, $rule.identifier)
  else:
    return fscanner_on_rule_not_matched(ctx.scan_result, ctx.virus_name)


proc do_analysis_proc(ctx: var ProcScanContext): cint =
  # Check if process has deleted binary. Usually used by malware
  if ctx.proc_object.binary_path.endsWith(" (deleted)"):
    return fscanner_on_process_deleted(ctx.virus_name, ctx.proc_object.binary_path, ctx.scan_result)

  # Scan cmdline file
  # FIXME: data has \x00 instead of space. Need to scan buffer
  discard yr_rules_scan_file(ctx.ScanEngine.YaraEng, cstring(ctx.proc_object.cmdline), SCAN_FLAGS_PROCESS_MEMORY, cb_yr_process_scan_result, addr(ctx), yr_scan_timeout)
  if ctx.scan_result == CL_VIRUS:
    return fscanner_on_process_cmd_matched(ctx.virus_name, ctx.scan_result)

  # Maybe scan binary to execute?
  return yr_rules_scan_proc(ctx.ScanEngine.YaraEng, cint(ctx.proc_object.pid), SCAN_FLAGS_FAST_MODE, cb_yr_process_scan_result, addr(ctx), yr_scan_timeout)


proc pscanner_scan_proc*(ctx: var ProcScanContext) =
  ctx.proc_object.cmdline = ctx.proc_object.pid_path & "/cmdline"
  if isEmptyOrWhitespace(readFile(ctx.proc_object.cmdline)):
    # Can't get either binary path nor cmdline
    return

  try:
    ctx.proc_object.binary_path = expandSymlink(ctx.proc_object.pid_path & "/exe")
  except:
    # Some processes causes permissino deny when do expandSymlink
    ctx.proc_object.binary_path = parseCmdLine(readFile(ctx.proc_object.cmdline).replace("\x00", " "))[0]
    if not ctx.proc_object.binary_path.startsWith("/"):
      # TODO check with cwd as well
      ctx.proc_object.binary_path = findExe(ctx.proc_object.binary_path)

  # TODO handle parent pid, child pid, ... to do ignore scan
  cli_progress_scan_process(ctx.proc_object.pid, ctx.proc_object.binary_path)
  discard do_analysis_proc(ctx)
  cli_progress_flush()

  if ctx.scan_result == CL_VIRUS:
    cb_yr_virus_found(ctx)
