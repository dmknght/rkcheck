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
    ctx = cast[ptr FileScanCtx](user_data)

  # if message == CALLBACK_MSG_MODULE_IMPORTED:
  #   # Prototype ocde of fetching module's data (ELF). CHeck out modules_callback
  #   # https://yara.readthedocs.io/en/stable/capi.html#c.YR_MODULE_IMPORT
  #   var
  #     module = cast[ptr YR_OBJECT_STRUCTURE](message_data)

  #   if module.identifier == "elf":
  #     echo "\nImported module ELF"
  if message == CALLBACK_MSG_RULE_MATCHING:
    var
      rule = cast[ptr YR_RULE](message_data)

    return file_scanner_on_matched(ctx.scan_result, ctx.virname, $rule.ns.name, $rule.identifier)
  else:
    return file_scanner_on_clean(ctx.scan_result, ctx.virname)


proc fscanner_cb_msg_dummy*(severity: cl_msg, fullmsg: cstring, msg: cstring, context: pointer) {.cdecl.} =
  discard


proc fscanner_cb_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  #[
    Print virus found message with file path
  ]#
  let
    ctx = cast[ptr FileScanCtx](context)

  file_scanner_on_malware_found(virname, ctx.virname, ctx.scan_object, ctx.file_infected)


proc fscanner_cb_post_scan_file*(fd: cint, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    Post-scan callback
  ]#
  # Inner file name can be called via cli_ctx in others.h of ClamAV but it's not callable
  let
    ctx = cast[ptr FileScanCtx](context)

  if scan_result == CL_VIRUS:
    ctx.virname = virname
    #[
      This is the post-scan step (after scan file)
      So if file is marked as virus, we should return CLEAN
      So the callback virus found wont be called multiple times
    ]#
    return CL_CLEAN
  else:
    progress_bar_scan_file(ctx.scan_object)
    ctx.file_scanned += 1
    discard ctx.yara.engine.yr_rules_define_integer_variable("scan_block_type", 0)
    discard yr_rules_scan_fd(ctx.yara.engine, fd, SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, context, YR_SCAN_TIMEOUT)
    return ctx.scan_result


proc fscanner_cb_pre_scan_cache*(fd: cint, cl_type: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    Pre-scan callback
  ]#
  let
    ctx = cast[ptr FileScanCtx](context)

  progress_bar_scan_file(ctx.scan_object)
  ctx.file_scanned += 1

  discard ctx.yara.engine.yr_rules_define_integer_variable("scan_block_type", 0)
  discard yr_rules_scan_fd(ctx.yara.engine, fd, SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, context, YR_SCAN_TIMEOUT)
  return ctx.scan_result


proc fscanner_cb_inc_count*(fd: cint, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    When Yara failed to init, this function is called instead of fscanner_cb_scan_file
    This function will count scanned files only
  ]#
  let
    ctx = cast[ptr FileScanCtx](context)

  progress_bar_scan_file(ctx.scan_object)
  ctx.file_scanned += 1

# proc fscanner_yr_scan_file_cb(context: ptr YR_SCAN_CONTEXT, message: cint, message_data: pointer, user_data: pointer): cint {.cdecl.} =
#   var
#     ctx = cast[ptr FileScanCtx](user_data)
#     rule = cast[ptr YR_RULE](message_data)
#     vir_name: cstring

#   if message == CALLBACK_MSG_RULE_MATCHING:
#     discard file_scanner_on_matched(ctx.scan_result, ctx.virname, $rule.ns.name, $rule.identifier)
#     file_scanner_on_malware_found(vir_name, ctx.virname, ctx.scan_object, ctx.file_infected)
#     return CALLBACK_ABORT # TODO maybe do multiple rules matching?
#   else:
#     return file_scanner_on_clean(ctx.scan_result, ctx.virname)


# proc fscanner_yr_scan_file*(context: var FileScanCtx) =
#   progress_bar_scan_file(context.scan_object)
#   discard yr_rules_scan_file(context.yara.engine, cstring(context.scan_object), SCAN_FLAGS_FAST_MODE, fscanner_yr_scan_file_cb, context.addr, YR_SCAN_TIMEOUT)
#   context.file_scanned += 1
#   progress_bar_flush()
