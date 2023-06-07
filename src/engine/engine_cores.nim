import libclamav
import libyara
import bitops
import strutils
import .. / cli / print_utils
import engine_utils
import .. / compiler / compiler_utils


type
  ScanOptions* = object
    list_dirs*: seq[string]
    list_files*: seq[string]
    list_procs*: seq[uint]
    scan_all_procs*: bool
    is_clam_debug*: bool
    use_clam_db*: bool
    match_all*: bool
    scan_preload*: bool
    db_path_clamav*: string
    db_path_yara*: string

  ProcInfo* = object
    pid*: uint
    tgid*: uint
    ppid*: uint
    cmdline*: string
    exec_name*: string
    exec_path*: string
    mapped_file*: string
  ScanInfo* = object of RootObj
    scan_object*: string
    scan_result*: cl_error_t
    virname*: cstring

  ClEngine* = object
    engine*: ptr cl_engine
    options*: cl_scan_options
    database*: string
    debug_mode*: bool
    use_clam*: bool
  YrEngine* = object
    engine*: ptr YR_RULES
    database*: string
    match_all_rules*: bool

  FileScanCtx* = object of ScanInfo
    yara*: YrEngine
    clam*: ClEngine
    file_scanned*: uint
    file_infected*: uint

  ProcScanCtx* = object of ScanInfo
    yara*: YrEngine
    # clam*: ClEngine
    pinfo*: ProcInfo
    proc_scanned*: uint
    proc_infected*: uint


const
  YR_SCAN_TIMEOUT*: cint = 1000000
  SCANNER_MAX_PROC_COUNT* = 4194304


proc init_clamav*(f_engine: var ClEngine, loaded_sig_count: var uint, use_clam: bool): cl_error_t =
  #[
    Start ClamAV engine
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
    https://docs.clamav.net/manual/Development/libclamav.html#database-loading
  ]#
  result = cl_init(CL_INIT_DEFAULT)
  if result != CL_SUCCESS:
    return result

  f_engine.engine = cl_engine_new()

  # ~0 (not 0) is to enable all flags.In this case, we disable flags by default
  f_engine.options.parse = bitor(f_engine.options.parse, 0)
  # Enable some parsers
  f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_ARCHIVE)
  f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_OLE2)
  f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_PDF)
  # f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_SWF)
  f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_HWP3)
  f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_XMLDOCS)
  f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_MAIL)
  f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_HTML)

  # Disable ELF parser if we don't use ClamAV Signatures
  if use_clam:
    f_engine.options.parse = bitor(f_engine.options.parse, CL_SCAN_PARSE_ELF)
  # f_engine.options.parse = bitand(f_engine.options.parse, CL_SCAN_PARSE_PE)

  # f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_BROKEN)
  f_engine.options.general = bitor(f_engine.options.general, CL_SCAN_GENERAL_HEURISTICS)
  # f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
  # f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_DOC)
  # f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_MACROS)

  discard f_engine.engine.cl_engine_set_num(CL_ENGINE_MAX_FILESIZE, 75 * 1024 * 1024) # Max scan size 60mb

  # Did we set debug?
  if f_engine.debug_mode:
    cl_debug()

  # If database path is not empty, load ClamAV Signatures
  if f_engine.use_clam:
    var
      sig_count: cuint = 0
    result = cl_load(cstring(f_engine.database), f_engine.engine, addr(sig_count), bitor(CL_DB_STDOPT, CL_DB_BYTECODE_UNSIGNED))
    loaded_sig_count = uint(sig_count)

    if result == CL_SUCCESS:
      print_loaded_signatures(loaded_sig_count, false)

  return cl_engine_compile(f_engine.engine)


proc finit_clamav*(f_engine: var ClEngine) =
  #[
    Give ClamAV Engine's freedom
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
  ]#
  if f_engine.engine != nil:
    discard cl_engine_free(f_engine.engine)


proc init_yara*(engine: var YrEngine, loaded_sigs: var uint): int =
  result = yr_initialize()

  if result != ERROR_SUCCESS:
    return result

  var
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE

  if isEmptyOrWhitespace(engine.database):
    return ERROR_COULD_NOT_OPEN_FILE
  # If rule is compiled, we load it
  if yr_rule_file_is_compiled(engine.database):
    result = yr_rules_load(cstring(engine.database), addr(engine.engine))
  else:
    # Need to compile rules
    yr_rules_compile_custom_rules(engine.engine, engine.database)

  if result != ERROR_SUCCESS:
    return result

  loaded_sigs = uint(engine.engine.num_rules)

  print_loaded_signatures(loaded_sigs, true)
  print_yara_version()

  discard yr_set_configuration(YR_CONFIG_STACK_SIZE, addr(stack_size))
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, addr(max_strings_per_rule))
  return result


proc finit_yara*(engine: var YrEngine) =
  if engine.engine != nil:
    discard yr_rules_destroy(engine.engine)
  discard yr_finalize()
