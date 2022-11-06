import os
import strutils
import sequtils
import .. / engine / engine_cores


proc cliopts_create_default(options: var ScanOptions) =
  options.is_clam_debug = false
  options.use_clam_db = false
  options.scan_all_procs = false
  options.db_path_clamav = "/var/lib/clamav/"

  # Load bytecode signatures by default. Problems: if user pass only --use-clamdb,
  # program must check multiple args to make sure the values are correct
  # ignore it for now
  # if fileExists("/var/lib/clamav/bytecode.cld"):
  #   options.db_path_clamav = "/var/lib/clamav/bytecode.cld"
  #   options.use_clam_db = true
  # else:
  #   options.db_path_clamav = "/var/lib/clamav/"
  #   options.use_clam_db = false

  if fileExists("/usr/share/rkscanner/database/signatures.ydb"):
    # If the program is installed to the system
    # Signature should be absolute path
    options.db_path_yara = "/usr/share/rkscanner/database/signatures.ydb"
  else:
    # Find database that should be located with compiled binary
    let
      binaryDir = splitPath(getAppFilename()).head & "/database/signatures.ydb"
    if fileExists(binaryDir):
      options.db_path_yara = "database/signatures.ydb"
    else:
      raise newException(OSError, "Missing Yara's database")


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
    # Invalid yara path. Raise error.
    # TODO: we need to define compiled rules and text rule
    raise newException(OSError, "Invalid Yara's database file path " & paramValue)

  options.db_path_yara = paramValue
  i += 1


proc cliopts_set_list_dirs(options: var ScanOptions, i: var int, total_param: int) =
  if i + 1 > total_param:
    raise newException(ValueError, "Missing value for list dirs")
  # TODO: what if file / folder has ","?

  options.list_dirs = split(paramStr(i + 1), ",").deduplicate()
  i += 1


proc cliopts_set_list_files(options: var ScanOptions, i: var int, total_param: int) =
  if i + 1 > total_param:
    raise newException(ValueError, "Missing value for list files")
  # TODO: what if file / folder has ","?

  options.list_files = split(paramStr(i + 1), ",").deduplicate()
  i += 1


proc cliopts_set_list_procs(options: var ScanOptions, i: var int, total_param: int) =
  if i + 1 > total_param:
    raise newException(ValueError, "Missing value for list processes")

  for value in split(paramStr(i + 1), ",").deduplicate():
    try:
      let int_value = parseUInt(value)
      options.list_procs.add(int_value)
    except:
      discard

  if len(options.list_procs) == 0:
    raise newException(ValueError, "Invalid pid values")
  i += 1


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
        return false
      of "-h":
        return false
      of "-help":
        return false
      of "--all-processes":
        options.scan_all_procs = true
      of "--use-clamdb":
        options.use_clam_db = true
      of "--clam-debug":
        options.is_clam_debug = true
      of "--path-clamdb":
        cliopts_set_db_path_clamav(options, i, total_params_count):
      of "--path-yaradb":
        cliopts_set_db_path_yara(options, i, total_params_count):
      of "--list-dirs":
        cliopts_set_list_dirs(options, i, total_params_count)
      of "--list-files":
        cliopts_set_list_files(options, i, total_params_count)
      of "--list-procs":
        cliopts_set_list_procs(options, i, total_params_count)
      else:
        raise newException(ValueError, "Invalid option " & currentParam)

    i += 1

  return true
