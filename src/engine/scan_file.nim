import libyara
import libclamav
import engine_cores
import engine_utils
import strutils
import os
import .. / cli / progress_bar


proc fscanner_cb_yara_scan_result*(context: ptr YR_SCAN_CONTEXT, message: cint, message_data: pointer, user_data: pointer): cint {.cdecl.} =
  #[
    Handle scan result from Yara engine
  ]#

  var
    ctx = cast[ptr FileScanCtx](user_data)

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


proc fscanner_cb_inc_count*(fd: cint, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    When Yara failed to init, this function is called instead of fscanner_cb_scan_file
    This function will count scanned files only
  ]#
  let
    ctx = cast[ptr FileScanCtx](context)

  progress_bar_scan_file(ctx.scan_object)
  ctx.file_scanned += 1


proc fscanner_cb_file_inspection*(fd: cint, file_type: cstring, ancestors: ptr cstring, parent_file_size: uint,
  file_name: cstring; file_size: uint, file_buffer: cstring, recursion_level: uint32, layer_attributes: uint32,
  context: pointer): cl_error_t {.cdecl.} =
  #[
    Only use Yara scan when file_type is various types like PE, ELF, text, ...
    Arcoding to LibClamAV's scanners.c#L4624, there are some file types triggers scan function. There are some unknown
    file types like
    1. CL_TYPE_TEXT_ASCII
    2. CL_TYPE_TEXT_UTF16BE
    3. CL_TYPE_TEXT_UTF16LE
  ]#
  # TODO dig ClamAV's code to improve accuracy of file scanning. Idea: Do not scan compressed files
  #[
    ClamAV doesn't scan CL_TYPE_TEXT_ASCII?
  ]#
  # TODO improve ram usage. Current function is using 54mb (compare to 46mb when use pre-cache) for same files
  # TODO create a rule to combine text_ascii with the scan memory to prevent false positive

  if $file_type in [
    "CL_TYPE_TEXT_UTF8",
    "CL_TYPE_MSEXE",
    "CL_TYPE_ELF",
    "CL_TYPE_MACHO_UNIBIN",
    "CL_TYPE_BINARY_DATA",
    "CL_TYPE_HTML",
    "CL_TYPE_TEXT_ASCII"
  ]:
    let
      ctx = cast[ptr FileScanCtx](context)

    if ctx.scan_result == CL_VIRUS:
      return CL_VIRUS

    if not isEmptyOrWhitespace($file_name):
      let
        inner_file_name = splitPath($file_name).tail
      if inner_file_name != splitPath(ctx.scan_object).tail:
        ctx.scan_object = ctx.scan_object & "//" & inner_file_name

    # progress_bar_scan_file(ctx.scan_object)
    ctx.file_scanned += 1
    discard ctx.yara.engine.yr_rules_define_integer_variable("scan_block_type", 0)
    discard yr_rules_scan_fd(ctx.yara.engine, fd, SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, context, YR_SCAN_TIMEOUT)
    if ctx.scan_result == CL_VIRUS:
      # FIX multiple files marked as previous signature. However, it might raise error using multiple callbacks to detect malware
      ctx.scan_result = CL_CLEAN
      return CL_VIRUS

  return CL_CLEAN
