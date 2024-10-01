import os
import strutils
import sequtils
import .. / engine / engine_cores
import helps


proc cli_opt_find_default_ydb(list_paths: openArray[string]): string =
  for path in list_paths:
    if fileExists(path):
      return path


proc cliopts_create_default*(options: var ScanOptions) =
  options.is_clam_debug = false
  options.use_clam_db = false
  options.scan_all_procs = false
  options.scan_function_hook = false
  options.db_path_clamav = "/var/lib/clamav/"
  let
    db_path_normal = [
      "/usr/share/rkcheck/databases/signatures.ydb",
      "databases/signatures.ydb"
    ]

  options.db_path_yara = cli_opt_find_default_ydb(db_path_normal)


proc cliopts_set_db_path_clamav(options: var ScanOptions, i: var int, total_param: int) =
  if i + 1 > total_param:
    raise newException(ValueError, "Missing value for ClamAV's database path")

  let
    paramValue = paramStr(i + 1)

  if not fileExists(paramValue) and not dirExists(paramValue):
    raise newException(OSError, "Invalid ClamAV's database path " & paramValue)

  options.db_path_clamav = paramValue
  # Force program to use ClamAV Signature anyway
  options.use_clam_db = true
  i += 1


proc cliopts_set_db_path_yara(options: var ScanOptions, i: var int, total_param: int) =
  if i + 1 > total_param:
    raise newException(ValueError, "Missing value for Yara's database path")

  let
    paramValue = paramStr(i + 1)

  if not fileExists(paramValue) and not dirExists(paramValue):
    # File doesn't exist
    raise newException(OSError, "Invalid Yara's database file path " & paramValue)

  options.db_path_yara = paramValue
  i += 1


proc cliopts_set_list_files_or_dirs(list_dirs, list_files: var seq[string], i: var int, total_param: int) =
  if i + 1 > total_param:
    # Check if flag has no value behind it, raise value error
    raise newException(ValueError, "Missing values for " & paramStr(i))
  else:
    # Move offset by 1 and start getting all values
    i += 1

  while i <= total_param:
    let
      currentParam = paramStr(i)

    if currentParam.startsWith("-"):
      list_dirs = deduplicate(list_dirs)
      list_files = deduplicate(list_files)
      i -= 1
      # In the end of the loop (parent function), we increase i by 1
      # This causes missing flag by unexpected offset
      break
    else:
      try:
        if getFileInfo(currentParam, true).kind == pcFile:
          list_files.add(currentParam)
        else:
          list_dirs.add(currentParam)
      except:
        # File or Dir doesn't exist
        discard
    i += 1


proc cliopts_set_list_procs(list_procs: var seq[uint], i: var int, total_param: int): int =
  i += 1

  while i <= total_param:
    let
      currentParam = paramStr(i)

    if currentParam.startsWith("-"):
      list_procs = deduplicate(list_procs)
      i -= 1
      # In the end of the loop (parent function), we increase i by 1
      # This causes missing flag by unexpected offset
      break
    else:
      try:
        list_procs.add(parseUInt(currentParam))
      except:
        discard
    i += 1

  return len(list_procs)


proc cliopts_get_options*(options: var ScanOptions): bool =
  let
    total_params_count = paramCount()

  if total_params_count == 0:
    return show_help_banner()

  cliopts_create_default(options)
  #[
    Function param count uses argv from C and calculate: result = argv.len - 2
    We use a variable so we can decrease calculation times
  ]#
  var
    i = 0

  while i <= total_params_count:
    let
      currentParam = paramStr(i)

    if currentParam.startsWith("-"):
      case currentParam:
      of "--help":
        return show_help_banner()
      of "-h":
        return show_help_banner()
      of "-help":
        return show_help_banner()
      of "--use-clamdb":
        options.use_clam_db = true
      of "--clam-debug":
        options.is_clam_debug = true
      of "--path-clamdb":
        cliopts_set_db_path_clamav(options, i, total_params_count):
      of "--cldb": # Short alias of --path-clamdb
        cliopts_set_db_path_clamav(options, i, total_params_count):
      of "--path-yaradb":
        cliopts_set_db_path_yara(options, i, total_params_count):
      of "--yrdb": # Short alias of --path-yaradb
        cliopts_set_db_path_yara(options, i, total_params_count):
      of "--scan-files":
        cliopts_set_list_files_or_dirs(options.list_dirs, options.list_files, i, total_params_count)
      of "--scan-procs":
        if cliopts_set_list_procs(options.list_procs, i, total_params_count) == 0:
          options.scan_all_procs = true
      of "--scan-fhook":
        options.scan_function_hook = true
      else:
        raise newException(ValueError, "Invalid option " & currentParam)

    i += 1

  # If there's no valid yara path and no ClamDb is in use, raise error
  if isEmptyOrWhitespace(options.db_path_yara) and not options.use_clam_db:
    raise newException(OSError, "No database found")

  return true
