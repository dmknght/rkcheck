import os
import .. / .. / libs / libclamav / nim_clam
import .. / .. / libs / libyara / nim_yara
import .. / cores / [eng_cores, eng_cli_progress]
import strutils


proc fscanner_cb_yara_scan_file*(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
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
    # Safe check to avoid crash. Don't calculate weight if rule doesn't have tag "weight"
    # if rule != nil and yr_rule_is_weight(rule) == 0:
    #   let rule_count_strs = yr_rule_count_strings(rule)
    #   if rule_count_strs != 0:
    #     # Calculate patterns weight
    #     # TODO didn't count the "not $" cases
    #     let weight = yr_scan_count_strings_m(context, rule) * 100 / rule_count_strs
    #     if weight > 55:
    #       ctx.scan_result = CL_VIRUS
    #       ctx.virus_name = cstring(weight.formatFloat(ffDecimal, 2) & "% " & $rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    #       return CALLBACK_ABORT
    # else:
    # Remove status "virus" and virus name
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
  echo virus_name, " ", ctx.scan_object


proc fscanner_cb_clam_scan*(fd: cint, `type`: cstring, context: pointer): cl_error_t {.cdecl.} =
  #[
    The actual function to scan files. This function will call yara to scan file first.
    If result is CL_CLEAN, Clam will scan with its signatures
    # TODO we want to handle text files to scan .desktop files and .service files. Better to handle them before we call yr_rules_scan_fd
  ]#
  let
    ctx = cast[ptr FileScanContext](context)
  cli_progress_scan_file(ctx.scan_object)
  discard yr_rules_scan_fd(ctx.ScanEngine.YaraEng, fd, yr_scan_flags, fscanner_cb_yara_scan_file, context, yr_scan_timeout)
  cli_progress_flush()
  # If result is CL_CLEAN, clamAV will use signatures of ClamAV to scan file again
  return ctx.scan_result


# proc rscanner_cb_clam_post_scan*(fd, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
#   let ctx = cast[ptr FileScanContext](context)
#   if scan_result == CL_CLEAN:
#     discard yr_rules_scan_fd(ctx.ScanEngine.YaraEng, fd, yr_scan_flags, rscanner_cb_yara_scan_file, context, yr_scan_timeout)
#   # If result is CL_CLEAN, clamAV will use signatures of ClamAV to scan file again
#   return ctx.scan_result


proc fscanner_scan_file(context: var FileScanContext, file_path: string) =
  var
    virname: cstring
    scanned: culong = 0

  context.scan_object = file_path
  discard cl_scanfile_callback(file_path, addr(virname), addr(scanned), context.ScanEngine.ClamAV, addr(context.ScanEngine.ClamScanOpts), addr(context))


proc fscanner_scan_dir(context: var FileScanContext, dir_path: string) =
  for file_path in walkDirRec(dir_path):
    fscanner_scan_file(context, file_path)


proc fscanner_new_file_scan*(context: var FileScanContext, file_path: string) =
  fscanner_scan_file(context, file_path)


proc fscanner_new_files_scan*(context: var FileScanContext, file_paths: seq[string]) =
  for file_path in file_paths:
    fscanner_scan_file(context, file_path)


proc fscanner_new_dir_scan*(context: var FileScanContext, dir_path: string) =
  fscanner_scan_dir(context, dir_path)


proc fscanner_new_dirs_scan*(context: var FileScanContext, dir_paths: seq[string]) =
  for dir_path in dir_paths:
    if not dir_path.startsWith("/proc/"):
      fscanner_scan_dir(context, dir_path)
    else:
      echo "Ignoring ", dir_path, ". Please try scan process instead."
