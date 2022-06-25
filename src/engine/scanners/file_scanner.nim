import os
import .. / .. / libs / libclamav / nim_clam
import .. / cores / eng_cores
import strutils


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
