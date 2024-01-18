import bitops
import strutils
import streams
import os
import bindings/[libclamav, libyara]
import ../cli/print_utils
import ../compiler/compiler_utils


type
  ScanOptions* = object
    list_dirs*: seq[string]
    list_files*: seq[string]
    list_procs*: seq[uint]
    scan_all_procs*: bool
    is_clam_debug*: bool
    use_clam_db*: bool
    scan_preload*: bool
    db_path_clamav*: string
    db_path_yara*: string

  ProcInfo* = object
    pid*: uint
    procfs*: string
    proc_name*: string
    proc_exe*: string

  ClEngine* = object
    engine*: ptr cl_engine
    options*: cl_scan_options
  YrEngine* = object
    rules*: ptr YR_RULES
    scanner*: ptr YR_SCANNER

  ScanCtx* = object of RootObj
    yara*: YrEngine
    clam*: ClEngine
    scan_object*: string
    scan_result*: cl_error_t
    virname*: cstring
  FileScanCtx* = object of ScanCtx
    file_scanned*: uint
    file_infected*: uint
  ProcScanCtx* = object of ScanCtx
    pinfo*: ProcInfo
    proc_scanned*: uint
    proc_infected*: uint


const
  YR_SCAN_TIMEOUT*: cint = 1000000
  SCANNER_MAX_PROC_COUNT* = 4194304


proc init_clamav*(clam_engine: var ClEngine, loaded_sig_count: var uint, path_clamdb: string, use_clam, clam_debug: bool): cl_error_t =
  #[
    Start ClamAV engine
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
    https://docs.clamav.net/manual/Development/libclamav.html#database-loading
  ]#
  result = cl_init(CL_INIT_DEFAULT)
  if result != CL_SUCCESS:
    return result

  echo "LibAV engine: ", cl_retver()
  clam_engine.engine = cl_engine_new()

  # ~0 (not 0) is to enable all flags.In this case, we disable flags by default
  clam_engine.options.parse = bitor(clam_engine.options.parse, 0)
  # Enable some parsers
  clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_ARCHIVE)
  clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_OLE2)
  clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_PDF)
  # clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_SWF)
  clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_HWP3)
  clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_XMLDOCS)
  clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_MAIL)
  clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_HTML)

  clam_engine.options.general = bitor(clam_engine.options.general, CL_SCAN_GENERAL_HEURISTICS)

  if use_clam:
    # Enable cache
    clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_ELF)
    clam_engine.options.parse = bitor(clam_engine.options.parse, CL_SCAN_PARSE_PE)
    # Maybe enable macho?
    # clam_engine.options.heuristic = bitor(clam_engine.options.heuristic, CL_SCAN_HEURISTIC_BROKEN)
    # clam_engine.options.heuristic = bitor(clam_engine.options.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
    # clam_engine.options.heuristic = bitor(clam_engine.options.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_DOC)
    # clam_engine.options.heuristic = bitor(clam_engine.options.heuristic, CL_SCAN_HEURISTIC_MACROS)
  else:
    # Disable cache
    clam_engine.options.parse = bitand(clam_engine.options.parse, CL_SCAN_PARSE_ELF)
    clam_engine.options.parse = bitand(clam_engine.options.parse, CL_SCAN_PARSE_PE)

  discard clam_engine.engine.cl_engine_set_num(CL_ENGINE_MAX_FILESIZE, 75 * 1024 * 1024) # Max scan size 75mb

  # Did we set debug?
  if clam_debug:
    cl_debug()

  # If database path is not empty, load ClamAV Signatures
  if use_clam:
    var
      sig_count: cuint = 0
    result = cl_load(cstring(path_clamdb), clam_engine.engine, addr(sig_count), bitor(CL_DB_STDOPT, CL_DB_BYTECODE_UNSIGNED))
    loaded_sig_count = uint(sig_count)

    if result == CL_SUCCESS:
      print_loaded_signatures(loaded_sig_count, false)

  return cl_engine_compile(clam_engine.engine)


#[
  Give ClamAV Engine's freedom
  https://docs.clamav.net/manual/Development/libclamav.html#initialization
]#
proc finit_clamav*(clam_engine: var ClEngine) =
  if clam_engine.engine != nil:
    discard cl_engine_free(clam_engine.engine)


#[
  Check if the database file of Yara is compiled or text-based
]#
proc yr_rules_is_compiled(path: string, is_compiled: var bool): bool =
  try:
    let
      f = newFileStream(path)

    if f.readStr(4) == "YARA":
      is_compiled = true
    else:
      is_compiled = false
    f.close()
    return true
  except:
    echo getCurrentExceptionMsg()
    return false


proc load_yara_rules_from_file(yara_engine: var YrEngine, db_path: string): bool =
  var
    is_compiled: bool

  if not yr_rules_is_compiled(db_path, is_compiled):
    raise newException(OSError, "Failed to read Yara's database")

  if not is_compiled:
    # Need to compile rules
    return yr_rules_compile_custom_rules(yara_engine.rules, @[db_path])
  else:
    if yr_rules_load(cstring(db_path), addr(yara_engine.rules)) != ERROR_SUCCESS:
      return false
    return true


proc load_yara_rules_from_dir(yara_engine: var YrEngine, db_path: string): bool =
  var
    list_db: seq[string]

  for kind, path in walkDir(db_path):
    if kind == pcFile:
      let
        extension = splitFile(path).ext
      if extension == ".yar" or extension == ".yara":
        list_db.add(path)

  if len(list_db) == 0:
    raise newException(ValueError, "Unable to find Yara rules in directory")
  return yr_rules_compile_custom_rules(yara_engine.rules, list_db)


#[
  Load Yara rules from a file or directory
]#
proc load_custom_yara_rules(yara_engine: var YrEngine, db_path: string): bool =
  let
    db_file_type = getFileInfo(db_path).kind # Should we follow symlink?

  if db_file_type == pcFile:
    return load_yara_rules_from_file(yara_engine, db_path)
  elif db_file_type == pcDir:
    return load_yara_rules_from_dir(yara_engine, db_path)
  else:
    # Unknown file kind?
    return false


#[
  Initilize Yara's engine
]#
proc init_yara*(yara_engine: var YrEngine, loaded_sigs: var uint, db_path: string): int =
  result = yr_initialize()

  if result != ERROR_SUCCESS:
    return result

  var
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE

  if isEmptyOrWhitespace(db_path):
    return ERROR_COULD_NOT_OPEN_FILE

  if not load_custom_yara_rules(yara_engine, db_path):
    return ERROR_COULD_NOT_OPEN_FILE

  loaded_sigs = uint(yara_engine.rules.num_rules)

  print_yara_version()
  print_loaded_signatures(loaded_sigs, true)

  discard yr_set_configuration(YR_CONFIG_STACK_SIZE, addr(stack_size))
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, addr(max_strings_per_rule))
  return result


proc finit_yara*(engine: var YrEngine) =
  if engine.rules != nil:
    discard yr_rules_destroy(engine.rules)
  discard yr_finalize()
