import libyara
import libclamav
import engine_cores
import engine_utils
import .. / cli / progress_bar


proc fscanner_cb_clam_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  #[
    Print virus found message with file path
  ]#
  let
    ctx = cast[ptr FileScanner](context)

  file_scanner_on_malware_found(virname, ctx.scan_virname, ctx.scan_object, ctx.result_infected)


proc fscanner_cb_yara_scan_result*(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  #[
    Handle scan result from Yara engine
  ]#

  var
    ctx = cast[ptr FileScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  ctx.result_scanned += 1
  # If target matches a rule
  if message == CALLBACK_MSG_RULE_MATCHING:
    return file_scanner_on_matched(ctx.scan_result, ctx.scan_virname, $rule.ns.name, $rule.identifier)
  else:
    return file_scanner_on_clean(ctx.scan_result, ctx.scan_virname)


proc fscanner_cb_clam_scan_file*(fd: cint, `type`: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    The actual function to scan files. This function will call yara to scan file first.
    If result is CL_CLEAN, Clam will scan with its signatures
    # TODO we want to handle text files to scan .desktop files and .service files. Better to handle them before we call yr_rules_scan_fd
  ]#
  let
    ctx = cast[ptr FileScanner](context)

  progress_bar_scan_file(ctx.scan_object)
  discard yr_rules_scan_fd(ctx.yr_scanner.engine, fd, SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, context, YR_SCAN_TIMEOUT)
  progress_bar_flush()

  return ctx.scan_result
