import .. / .. / libs / libclamav / nim_clam
import .. / .. / libs / libyara / nim_yara
import .. / cores / [eng_cores, eng_cli_progress]
import strutils


proc fscanner_cb_yara_scan_result*(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  #[
    Handle scan result from Yara engine
  ]#

  var
    ctx = cast[ptr FileScanContext](user_data)
    rule = cast[ptr YR_RULE](message_data)

  # If target matches a rule
  if message == CALLBACK_MSG_RULE_MATCHING:
    # Change current result of scan context to virus
    ctx.scan_result = CL_VIRUS
    # Change virus name of current scan context
    ctx.virus_name = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    return CALLBACK_ABORT
  else:
    ctx.scan_result = CL_CLEAN
    ctx.virus_name = ""
    return CALLBACK_CONTINUE


proc fscanner_cb_clam_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  #[
    Print virus found message with file path
  ]#
  let
    ctx = cast[ptr FileScanContext](context)
    # Show virname for heur detection
    virus_name = if ctx.virus_name != "": ctx.virus_name else: virname
  ctx.obj_infected += 1
  echo virus_name, " ", ctx.scan_object


proc fscanner_cb_clam_scan_file*(fd: cint, `type`: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    The actual function to scan files. This function will call yara to scan file first.
    If result is CL_CLEAN, Clam will scan with its signatures
    # TODO we want to handle text files to scan .desktop files and .service files. Better to handle them before we call yr_rules_scan_fd
  ]#
  let
    ctx = cast[ptr FileScanContext](context)
    yr_scan_flags: cint = SCAN_FLAGS_FAST_MODE
  cli_progress_scan_file(ctx.scan_object)
  discard yr_rules_scan_fd(ctx.ScanEngine.YaraEng, fd, yr_scan_flags, fscanner_cb_yara_scan_result, context, yr_scan_timeout)
  ctx.obj_scanned += 1
  cli_progress_flush()
  # If result is CL_CLEAN, clamAV will use signatures of ClamAV to scan file again
  return ctx.scan_result
