import os
import .. / .. / libs / libclamav / nim_clam
import .. / .. / libs / libyara / nim_yara
import .. / cores / eng_cores


proc rscanner_cb_yara_scan_file*(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  #[
    Handle scan result from Yara engine
  ]#
  # If target matches a rule
  if message == CALLBACK_MSG_RULE_MATCHING:
    # Change current result of scan context to virus
    cast[ptr FileScanContext](user_data).scan_result = CL_VIRUS
    # Change virus name of current scan context
    cast[ptr FileScanContext](user_data).virus_name = $cast[ptr YR_RULE](message_data).ns.name & ":" & $cast[ptr YR_RULE](message_data).identifier
    return CALLBACK_ABORT
  else:
    # Remove status "virus" and virus name
    cast[ptr FileScanContext](user_data).scan_result = CL_CLEAN
    cast[ptr FileScanContext](user_data).virus_name = ""
    return CALLBACK_CONTINUE


proc rscanner_cb_clam_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  discard
#   let
#     virus_name = if user_data.virus_name != "": user_data.virus_name else: virname
#   echo virus_name, " ", user_data.scan_object
#   #[Analysis code only. Move file to other path]#
#   # let newName = splitPath(user_data.scan_object).tail & "_detected"
#   # moveFile(user_data.scan_object, "/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/" & newName)


proc rscanner_cb_clam_scan*(fd: cint, `type`: cstring, context: pointer): cl_error_t {.cdecl.} =
  discard
  # TODO if we scan with ClamAV, better to scan yara if clam doesnt match
  # TODO we want to handle text files to scan .desktop files and .service files. Better to handle them before we call yr_rules_scan_fd
  let
    engine = cast[CoreEngine](context)
  var user_data: string
  discard yr_rules_scan_fd(engine.YaraEng, fd, yr_scan_flags, rscanner_cb_yara_scan_file, addr(user_data), yr_scan_timeout)
  # return user_data.scan_result


proc scanner_scan_file(context: var FileScanContext, file_path: string) =
  var
    virname: cstring
    scanned: culong = 0

  context.scan_object = file_path
  discard cl_scanfile(file_path, addr(virname), addr(scanned), context.ScanEngine.ClamAV, addr(context.ScanEngine.ClamScanOpts))


proc scanner_scan_dir(context: var FileScanContext, dir_path: string) =
  for file_path in walkDirRec(dir_path):
    scanner_scan_file(context, file_path)


proc rscanner_new_file_scan*(context: var FileScanContext, file_path: string) =
  scanner_scan_file(context, file_path)


proc rscanner_new_files_scan*(context: var FileScanContext, file_paths: seq[string]) =
  for file_path in file_paths:
    scanner_scan_file(context, file_path)


proc rscanner_new_dir_scan*(context: var FileScanContext, dir_path: string) =
  scanner_scan_dir(context, dir_path)


proc rscanner_new_dirs_scan*(context: var FileScanContext, dir_paths: seq[string]) =
  for dir_path in dir_paths:
    scanner_scan_dir(context, dir_path)
