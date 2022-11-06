import os
import strutils
import sequtils


type
  CliOptions* = object
    list_dirs*: seq[string]
    list_files*: seq[string]
    list_procs*: seq[uint]
    scan_all_procs*: bool
    is_clam_debug*: bool
    use_clam_db*: bool
    db_path_clamav*: string
    db_path_yara*: string


proc cliopts_create_default(options: var CliOptions) =
  options.is_clam_debug = false
  options.use_clam_db = false
  options.scan_all_procs = false
  options.db_path_clamav = "/var/lib/clamav/"
  # TODO walkdir to select possible paths or raise error
  options.db_path_yara = "rules/signatures.db"


proc cliopts_set_db_path_clamav(options: var CliOPtions, i: var int): bool =
  let
    paramValue = paramStr(i + 1)

  if not fileExists(paramValue) and not dirExists(paramValue):
    return false

  options.db_path_clamav = paramValue
  # Force program to use ClamAV Signature anyway
  options.use_clam_db = true
  i += 1


proc cliopts_set_db_path_yara(options: var CliOptions, i: var int): bool =
  let
    paramValue = paramStr(i + 1)

  if not fileExists(paramValue):
    # Invalid yara path. Raise error.
    # TODO: we need to define compiled rules and text rule
    return false

  options.db_path_yara = paramValue
  i += 1


proc cliopts_set_list_dirs(options: var CliOptions, i: var int) =
  # TODO: what if file / folder has ","?
  options.list_dirs = split(paramStr(i + 1), ",").deduplicate()
  i += 1


proc cliopts_set_list_files(options: var CliOptions, i: var int) =
  # TODO: what if file / folder has ","?
  options.list_files = split(paramStr(i + 1), ",").deduplicate()
  i += 1


proc cliopts_set_list_procs(options: var CliOptions, i: var int) =
  for value in split(paramStr(i + 1), ",").deduplicate():
    try:
      let int_value = parseUInt(value)
      options.list_procs.add(int_value)
    except:
      discard
  i += 1


proc cliopts_get_options*(options: var CliOptions): bool =
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
      if currentParam == "-h" or currentParam == "--help" or currentParam == "-help":
        # TODO: show help banner
        return false
      if currentParam == "--all-processes":
        options.scan_all_procs = true
      elif currentParam == "--use-clamdb":
        options.use_clam_db = true
      elif currentParam == "--clam-debug":
        options.is_clam_debug = true
      elif i + 1 > total_params_count:
        raise newException(ValueError, "Option " & currentParam & " has no value or is an invalid option")
      elif currentParam == "--path-clamdb":
        if not cliopts_set_db_path_clamav(options, i):
          raise newException(ValueError, "Invalid ClamAV's database path")
      elif currentParam == "--path-yaradb":
        if not cliopts_set_db_path_yara(options, i):
          raise newException(ValueError, "Invalid Yara's database path")
      elif currentParam == "--list-dirs":
        cliopts_set_list_dirs(options, i)
      elif currentParam == "--list-files":
        cliopts_set_list_files(options, i)
      elif currentParam == "--list-procs":
        cliopts_set_list_procs(options, i)
        if len(options.list_procs) == 0:
          raise newException(ValueError, "Invalid list processes")
      else:
        raise newException(ValueError, "Invalid option " & currentParam)
    i += 1
