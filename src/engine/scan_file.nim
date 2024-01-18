import strutils
import os
import engine_cores
import bindings/[libyara, libclamav]
import .. /cli/[progress_bar, print_utils]


#[
  Print infected file for Yara
]#
proc fscanner_on_malware_found_yara(context: ptr YR_SCAN_CONTEXT, message: cint, message_data: pointer, user_data: pointer): cint {.cdecl.} =
  var
    ctx = cast[ptr FileScanCtx](user_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    let
      rule = cast[ptr YR_RULE](message_data)

    ctx.scan_result = CL_VIRUS
    ctx.virname = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    return CALLBACK_ABORT
  else:
    ctx.scan_result = CL_CLEAN
    ctx.virname = ""
    return CALLBACK_CONTINUE


#[
  Print infected file for ClamAV
]#
proc fscanner_on_malware_found_clam*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  let
    ctx = cast[ptr FileScanCtx](context)
    # Show virname for heur detection
    virus_name = if isEmptyOrWhitespace($ctx.virname): virname else: ctx.virname

  ctx.file_infected += 1
  print_file_infected($virus_name, ctx.virt_scan_object)


#[
  Disable print message for ClamAV
]#
proc fscanner_slient_message_clam*(severity: cl_msg, fullmsg: cstring, msg: cstring, context: pointer) {.cdecl.} =
  discard


#[
  When Yara engine is nil, and ClamAV is enabled,
  Clam will scan anyway.
  This function will count scanned files by ClamAV
]#
proc fscanner_cb_inc_count*(fd: cint, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
  let
    ctx = cast[ptr FileScanCtx](context)

  progress_bar_scan_file(ctx.scan_object)
  ctx.file_scanned += 1


#[
  Scan file descriptor with Yara
  When ClamAV Engine is defined, it will be called later
  # TODO use Yara scanner
]#
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

  # if $file_type in [
  #   "CL_TYPE_TEXT_UTF8",
  #   "CL_TYPE_MSEXE",
  #   "CL_TYPE_ELF",
  #   "CL_TYPE_MACHO_UNIBIN",
  #   "CL_TYPE_BINARY_DATA",
  #   "CL_TYPE_HTML",
  #   "CL_TYPE_TEXT_ASCII"
  # ]:
  let
    ctx = cast[ptr FileScanCtx](context)

  if ctx.scan_result == CL_VIRUS:
    return CL_VIRUS

  ctx.virt_scan_object = ctx.scan_object

  if not isEmptyOrWhitespace($file_name):
    let
      inner_file_name = splitPath($file_name).tail

    if inner_file_name != splitPath(ctx.scan_object).tail:
      if "//" in ctx.scan_object:
        ctx.virt_scan_object = ctx.scan_object & "/" & inner_file_name
      else:
        ctx.virt_scan_object = ctx.scan_object & "//" & inner_file_name

  progress_bar_scan_file(ctx.virt_scan_object)
  ctx.file_scanned += 1
  discard yr_rules_scan_fd(ctx.yara.rules, fd, SCAN_FLAGS_FAST_MODE, fscanner_on_malware_found_yara, context, YR_SCAN_TIMEOUT)

  if ctx.scan_result == CL_VIRUS:
    # FIX multiple files marked as previous signature. However, it might raise error using multiple callbacks to detect malware
    ctx.scan_result = CL_CLEAN
    return CL_VIRUS

  return CL_CLEAN
