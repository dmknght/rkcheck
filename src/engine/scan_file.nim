import libyara
import libclamav
import engine_cores
import engine_utils
import .. / cli / progress_bar


proc fscanner_cb_yara_scan_result*(context: ptr YR_SCAN_CONTEXT, message: cint, message_data: pointer, user_data: pointer): cint {.cdecl.} =
  #[
    Handle scan result from Yara engine
  ]#

  var
    ctx = cast[ptr FileScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  # If target matches a rule
  if message == CALLBACK_MSG_RULE_MATCHING:
    return file_scanner_on_matched(ctx.scan_result, ctx.scan_virname, $rule.ns.name, $rule.identifier)
  else:
    return file_scanner_on_clean(ctx.scan_result, ctx.scan_virname)


proc fscanner_cb_msg_dummy*(severity: cl_msg, fullmsg: cstring, msg: cstring, context: pointer) {.cdecl.} =
  discard


proc fscanner_cb_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  #[
    Print virus found message with file path
  ]#
  let
    ctx = cast[ptr FileScanner](context)

  file_scanner_on_malware_found(virname, ctx.scan_virname, ctx.scan_object, ctx.result_infected)


proc fscanner_cb_scan_file*(fd: cint, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
  # Inner file name can be called via cli_ctx in others.h of ClamAV but it's not callable
  let
    ctx = cast[ptr FileScanner](context)

  progress_bar_scan_file(ctx.scan_object)
  ctx.result_scanned += 1

  if scan_result == CL_VIRUS:
    ctx.scan_virname = virname
    #[
      This is the post-scan step (after scan file)
      So if file is marked as virus, we should return CLEAN
      So the callback virus found wont be called multiple times
    ]#
    return CL_CLEAN
  else:
    discard yr_rules_scan_fd(ctx.yr_scanner.engine, fd, SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, context, YR_SCAN_TIMEOUT)
    return ctx.scan_result
