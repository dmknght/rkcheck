import os
import strutils
import sequtils
import .. / engine / engine_cores
import helps


proc cli_opt_find_default_ydb(list_paths: openArray[string]): string =
  for path in list_paths:
    if fileExists(path):
      return path

  raise newException(OSError, "Missing Yara's database")


proc cliopts_create_default*(options: var ScanOptions, scan_rootkit = false) =
  options.is_clam_debug = false
  options.use_clam_db = false
  options.scan_all_procs = false
  options.match_all = false
  options.db_path_clamav = "/var/lib/clamav/"
  let
    db_path_normal = [
      "/usr/share/rkcheck/database/signatures.ydb",
      "/database/signatures.ydb",
      "database/signatures.ydb"
    ]
    db_path_rootkit = [
      "/usr/share/rkcheck/database/rootkits.ydb",
      "/database/rootkits.ydb",
      "database/rootkits.ydb"
    ]

  # Load bytecode signatures by default. Problems: if user pass only --use-clamdb,
  # program must check multiple args to make sure the values are correct
  # ignore it for now
  # if fileExists("/var/lib/clamav/bytecode.cld"):
  #   options.db_path_clamav = "/var/lib/clamav/bytecode.cld"
  #   options.use_clam_db = true
  # else:
  #   options.db_path_clamav = "/var/lib/clamav/"
  #   options.use_clam_db = false

  if not scan_rootkit:
    options.db_path_yara = cli_opt_find_default_ydb(db_path_normal)
  else:
    options.db_path_yara = cli_opt_find_default_ydb(db_path_rootkit)


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

  if not fileExists(paramValue):
    # File doesn't exist
    raise newException(OSError, "Invalid Yara's database file path " & paramValue)

  options.db_path_yara = paramValue
  i += 1


proc cliopts_set_list_files_or_dirs(list_vars: var seq[string], i: var int, total_param: int) =
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
      list_vars = deduplicate(list_vars)
      i -= 1
      # In the end of the loop (parent function), we increase i by 1
      # This causes missing flag by unexpected offset
      break
    else:
      list_vars.add(currentParam)
    i += 1


proc cliopts_set_list_procs(list_procs: var seq[uint], i: var int, total_param: int) =
  if i + 1 > total_param:
    raise newException(ValueError, "Missing value for list processes")
  else:
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

  if len(list_procs) == 0:
    raise newException(ValueError, "Invalid pid values")


proc cliopts_get_options*(options: var ScanOptions): bool =
  cliopts_create_default(options)
  var
    i = 0
  let
    #[
      Function param count uses argv from C and calculate: result = argv.len - 2
      We use a variable so we can decrease calculation times
    ]#
    total_params_count = paramCount()

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
      of "--all-procs":
        options.scan_all_procs = true
      of "--use-clamdb":
        options.use_clam_db = true
      of "--clam-debug":
        options.is_clam_debug = true
      of "--match-all":
        options.match_all = true
      of "--path-clamdb":
        cliopts_set_db_path_clamav(options, i, total_params_count):
      of "--path-yaradb":
        cliopts_set_db_path_yara(options, i, total_params_count):
      of "--list-dirs":
        cliopts_set_list_files_or_dirs(options.list_dirs, i, total_params_count)
      of "--list-files":
        cliopts_set_list_files_or_dirs(options.list_files, i, total_params_count)
      of "--list-procs":
        cliopts_set_list_procs(options.list_procs, i, total_params_count)
      else:
        raise newException(ValueError, "Invalid option " & currentParam)

    i += 1

  return true
