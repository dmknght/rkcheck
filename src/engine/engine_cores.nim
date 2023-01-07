import libclamav
import libyara
import bitops
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
  PidInfo* = object
    pid*: uint
    tgid*: uint
    ppid*: uint
    name*: string
    cmdline*: string
    binary_path*: string
    v_binary_path*: string

  ClEngine* = object of RootObj
    engine*: ptr cl_engine
    options*: cl_scan_options
    database*: string
    debug_mode*: bool
  YrEngine* = object of RootObj
    engine*: ptr YR_RULES
    database*: string
    match_all_rules*: bool
    scan_object*: string
    scan_result*: cl_error_t
    file_scanned*: uint
    file_infected*: uint
    proc_scanned*: uint
    proc_infected*: uint
    scan_virname*: cstring

  ProcScanner* = object of YrEngine
    pinfo*: PidInfo
  FileScanner* = object of ClEngine
    yr_scanner*: YrEngine
    use_clam_sigs*: bool

const
  YR_SCAN_TIMEOUT*: cint = 1000000
  SCANNER_MAX_PROC_COUNT* = 4194304


proc init_clamav*(f_engine: var FileScanner): cl_error_t =
  #[
    Start ClamAV engine
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
    https://docs.clamav.net/manual/Development/libclamav.html#database-loading
  ]#
  result = cl_init(CL_INIT_DEFAULT)
  if result != CL_SUCCESS:
    return result

  f_engine.engine = cl_engine_new()

  f_engine.options.parse = bitnot(bitor(f_engine.options.parse, 0))
  f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_BROKEN)
  f_engine.options.general = bitor(f_engine.options.general, CL_SCAN_GENERAL_HEURISTICS)
  # f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
  # f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_DOC)
  # f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_MACROS)

  discard f_engine.engine.cl_engine_set_num(CL_ENGINE_MAX_FILESIZE, 75 * 1024 * 1024) # Max scan size 60mb

  # Did we set debug?
  if f_engine.debug_mode:
    cl_debug()

  # If database path is not empty, load ClamAV Signatures
  if f_engine.use_clam_sigs:
    var sig_count: cuint = 0
    result = cl_load(cstring(f_engine.database), f_engine.engine, addr(sig_count), CL_DB_STDOPT)

    if result == CL_SUCCESS:
      print_loaded_signatures(uint(sig_count), false)

  return cl_engine_compile(f_engine.engine)


proc finit_clamav*(f_engine: var FileScanner) =
  #[
    Give ClamAV Engine's freedom
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
  ]#
  if f_engine.engine != nil:
    discard cl_engine_free(f_engine.engine)


proc init_yara*(engine: var YrEngine): int =
  result = yr_initialize()

  if result != ERROR_SUCCESS:
    return result

  var
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE

  # If rule is compiled, we load it
  if yr_rule_file_is_compiled(engine.database):
    result = yr_rules_load(cstring(engine.database), addr(engine.engine))
  else:
    # Need to compile rules
    yr_rules_compile_custom_rules(engine.engine, engine.database)

  if result != ERROR_SUCCESS:
    return result

  print_loaded_signatures(uint(engine.engine.num_rules), true)
  # print_yara_version(YR_VERSION)

  discard yr_set_configuration(YR_CONFIG_STACK_SIZE, addr(stack_size))
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, addr(max_strings_per_rule))
  return result


proc finit_yara*(engine: var YrEngine) =
  if engine.engine != nil:
    discard yr_rules_destroy(engine.engine)
  discard yr_finalize()
