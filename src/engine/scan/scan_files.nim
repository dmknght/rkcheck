import .. / .. / libs / libclamav / nim_clam
import .. / .. / libs / libyara / nim_yara
import .. / cores / [eng_cores, eng_cli_progress]
import scan_utils


proc fscanner_cb_yara_scan_result*(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  #[
    Handle scan result from Yara engine
  ]#

  var
    ctx = cast[ptr FileScanContext](user_data)
    rule = cast[ptr YR_RULE](message_data)

  # If target matches a rule
  if message == CALLBACK_MSG_RULE_MATCHING:
    return fscanner_on_rule_matched(ctx.scan_result, ctx.virus_name, $rule.ns.name, $rule.identifier)
  else:
    return fscanner_on_rule_not_matched(ctx.scan_result, ctx.virus_name)


proc fscanner_cb_clam_scan_file*(fd: cint, `type`: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    The actual function to scan files. This function will call yara to scan file first.
    If result is CL_CLEAN, Clam will scan with its signatures
    # TODO we want to handle text files to scan .desktop files and .service files. Better to handle them before we call yr_rules_scan_fd
  ]#
  let
    ctx = cast[ptr FileScanContext](context)

  cli_progress_scan_file(ctx.scan_object)
  discard yr_rules_scan_fd(ctx.ScanEngine.YaraEng, fd, SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, context, yr_scan_timeout)
  ctx.obj_scanned += 1
  cli_progress_flush()
  # If result is CL_CLEAN, clamAV will use signatures of ClamAV to scan file again
  return ctx.scan_result
