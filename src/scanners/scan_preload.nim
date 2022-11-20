import os
import strutils
import .. / engine / [libyara, libclamav, engine_cores, scan_file, scan_proc, scan_sysmodules]


const
  ld_preload_path = "/etc/ld.so.preload"


proc check_ld_preload_hidden(): bool =
  for kind, path in walkDir("/etc/"):
    if kind == pcFile and path == ld_preload_path:
      return false
  return true


proc scanners_scan_ld_preload(options: var ScanOptions) =
  if not fileExists(ld_preload_path):
    return

  if check_ld_preload_hidden():
    # TODO show warning here
    discard

  # TODO what if rootkit hook prevent reading this file?
  for line in lines(ld_preload_path):
    if not isEmptyOrWhitespace(line):
      options.list_files.add(line)

  # TODO create a file scan task here
  # TODO do heuristic handle if file is hidden by rootkit
  # TODO add a count variable