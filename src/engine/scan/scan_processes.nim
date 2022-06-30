import .. / .. / libs / libyara / nim_yara
import .. / .. / libs / libclamav / nim_clam
import .. / cores / [eng_cores, eng_cli_progress]
import strutils
import os


proc cb_yr_virus_found(ctx: var ProcScanContext) =
  #[
    Print virus found message with file path
  ]#
  cli_progress_flush()
  if not isEmptyOrWhitespace(ctx.proc_object.binary_path):
    echo $ctx.virus_name, " ", $ctx.proc_object.binary_path, " (pid: ", ctx.proc_object.pid, ")"
  else:
    echo $ctx.virus_name, " process: ", ctx.proc_object.pid
  cli_progress_flush()


proc cb_yr_process_scan_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanContext](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    ctx.scan_result = CL_VIRUS
    # Change virus name of current scan context
    ctx.virus_name = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    return CALLBACK_ABORT
  else:
    ctx.scan_result = CL_CLEAN
    ctx.virus_name = ""
    return CALLBACK_CONTINUE


proc do_analysis_proc(ctx: var ProcScanContext) =
  let yr_scan_flags: cint = SCAN_FLAGS_PROCESS_MEMORY
  # Check if process has deleted binary. Usually used by malware
  if ctx.proc_object.binary_path.endsWith(" (deleted)"):
    ctx.virus_name = "Heur:DeletedProcess"
    ctx.scan_result = CL_VIRUS
    ctx.proc_object.binary_path.removeSuffix(" (deleted)")
    return
  # Scan cmdline file
  # FIXME: data has \x00 instead of space. Need to scan buffer
  discard yr_rules_scan_file(
    ctx.ScanEngine.YaraEng,
    cstring(ctx.proc_object.cmdline),
    yr_scan_flags,
    cb_yr_process_scan_result,
    addr(ctx),
    yr_scan_timeout
  )
  if ctx.scan_result == CL_VIRUS:
    return

  # TODO: Scan static binary if rule has only binary
  # if not isEmptyOrWhitespace(ctx.proc_object.binary_path):
  #   discard yr_rules_scan_file(
  #     ctx.ScanEngine.YaraEng,
  #     cstring(ctx.proc_object.binary_path),
  #     yr_scan_flags,
  #     cb_yr_process_scan_result,
  #     addr(ctx),
  #     yr_scan_timeout
  #   )
  #   if ctx.scan_result == CL_VIRUS:
  #     return

  discard yr_rules_scan_proc(
    ctx.ScanEngine.YaraEng,
    cint(ctx.proc_object.pid),
    0,
    cb_yr_process_scan_result,
    addr(ctx),
    yr_scan_timeout
  )


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
      ctx.proc_object.binary_path = findExe(ctx.proc_object.binary_path)

  # TODO handle parent pid, child pid, ... to do ignore scan
  cli_progress_scan_process(ctx.proc_object.pid, ctx.proc_object.binary_path)
  do_analysis_proc(ctx)
  if ctx.scan_result == CL_VIRUS:
    cb_yr_virus_found(ctx)
