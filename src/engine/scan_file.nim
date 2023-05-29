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
    return file_scanner_on_matched(ctx.yr_scanner.scan_result, ctx.yr_scanner.scan_virname, $rule.ns.name, $rule.identifier)
  else:
    return file_scanner_on_clean(ctx.yr_scanner.scan_result, ctx.yr_scanner.scan_virname)


proc fscanner_cb_msg_dummy*(severity: cl_msg, fullmsg: cstring, msg: cstring, context: pointer) {.cdecl.} =
  discard


proc fscanner_cb_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  #[
    Print virus found message with file path
  ]#
  let
    ctx = cast[ptr FileScanner](context)

  file_scanner_on_malware_found(virname, ctx.yr_scanner.scan_virname, ctx.yr_scanner.scan_object, ctx.yr_scanner.file_infected)


# proc fscanner_cb_post_scan_file*(fd: cint, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
#   #[
#     Post-scan callback
#   ]#
#   # Inner file name can be called via cli_ctx in others.h of ClamAV but it's not callable
#   let
#     ctx = cast[ptr FileScanner](context)

#   progress_bar_scan_file(ctx.yr_scanner.scan_object)
#   ctx.yr_scanner.file_scanned += 1

#   if scan_result == CL_VIRUS:
#     ctx.yr_scanner.scan_virname = virname
#     #[
#       This is the post-scan step (after scan file)
#       So if file is marked as virus, we should return CLEAN
#       So the callback virus found wont be called multiple times
#     ]#
#     return CL_CLEAN
#   else:
#     discard yr_rules_scan_fd(ctx.yr_scanner.engine, fd, SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, context, YR_SCAN_TIMEOUT)
#     return ctx.yr_scanner.scan_result


proc fscanner_cb_pre_scan_file*(fd: cint, cl_type: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    Pre-scan callback
  ]#
  let
    ctx = cast[ptr FileScanner](context)

  progress_bar_scan_file(ctx.yr_scanner.scan_object)
  ctx.yr_scanner.file_scanned += 1

  discard yr_rules_scan_fd(ctx.yr_scanner.engine, fd, SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, context, YR_SCAN_TIMEOUT)
  return ctx.yr_scanner.scan_result


proc fscanner_cb_inc_count*(fd: cint, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    When Yara failed to init, this function is called instead of fscanner_cb_scan_file
    This function will count scanned files only
  ]#
  let
    ctx = cast[ptr FileScanner](context)

  progress_bar_scan_file(ctx.yr_scanner.scan_object)
  ctx.yr_scanner.file_scanned += 1


proc fscanner_yr_scan_file_cb(context: ptr YR_SCAN_CONTEXT, message: cint, message_data: pointer, user_data: pointer): cint {.cdecl.} =
  var
    ctx = cast[ptr YrEngine](user_data)
    rule = cast[ptr YR_RULE](message_data)
    vir_name: cstring

  if message == CALLBACK_MSG_RULE_MATCHING:
    discard file_scanner_on_matched(ctx.scan_result, ctx.scan_virname, $rule.ns.name, $rule.identifier)
    file_scanner_on_malware_found(vir_name, ctx.scan_virname, ctx.scan_object, ctx.file_infected)
    return CALLBACK_ABORT # TODO maybe do multiple rules matching?
  else:
    return file_scanner_on_clean(ctx.scan_result, ctx.scan_virname)


proc fscanner_yr_scan_file*(context: var YrEngine) =
  progress_bar_scan_file(context.scan_object)
  discard yr_rules_scan_file(context.engine, cstring(context.scan_object), SCAN_FLAGS_FAST_MODE, fscanner_yr_scan_file_cb, context.addr, YR_SCAN_TIMEOUT)
  context.file_scanned += 1
  progress_bar_flush()
