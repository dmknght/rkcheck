import libclamav
import libyara
import bitops
import .. / cli / print_utils


type
  #[
    engine: Pointer of ClamAV cl_engine struct
    options: Struct of ClamAV Scanner's options
    database: Path to ClamAV signatures
    debug_mode: Enable debug in libclam
  ]#
  ScanOptions* = object
    list_dirs*: seq[string]
    list_files*: seq[string]
    list_procs*: seq[uint]
    scan_all_procs*: bool
    is_clam_debug*: bool
    use_clam_db*: bool
    db_path_clamav*: string
    db_path_yara*: string

  ClEngine* = object of RootObj
    engine*: ptr cl_engine
    options*: cl_scan_options
    database*: string
    debug_mode*: bool
  #[
    engine: Pointer to YR_RULES
    database: path to yara compiled signatures
  ]#
  YrEngine* = object of RootObj
    engine*: ptr YR_RULES
    database*: string
  #[
    The ProcScanner (Process Scanner) will use only Yara's Engine
      proc_id: The ID number of process (pid)
      proc_path: Full path of pid in procfs
      proc_binary: Executable file that started process
  ]#
  ProcScanner* = object of YrEngine
    proc_id*: uint
    proc_path*: string
    # proc_cmdline*: string
    proc_binary*: string
    scan_virname*: cstring
    sumary_scanned*: uint
    sumary_infected*: uint
  #[
    yr_scanner: YR_RULES
    scan_object: current path / name of object that engine is scanning
    scan_result: Result (Infected?) of current object
    scan_virname: Empty if not infected, else signature name
    result_scanned: Total objects were scanned
    result_infected: Total objects matched
  ]#
  FileScanner* = object of ClEngine
    yr_scanner*: YrEngine
    scan_object*: string
    scan_result*: cl_error_t
    scan_virname*: cstring
    result_scanned*: uint
    result_infected*: uint
    use_clam_sigs*: bool


const
  YR_SCAN_TIMEOUT*: cint = 1000000


proc init_clamav*(f_engine: var FileScanner): cl_error_t =
  #[
    Start ClamAV engine
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
    https://docs.clamav.net/manual/Development/libclamav.html#database-loading
  ]#
  result = cl_init(CL_INIT_DEFAULT)
  if result != CL_SUCCESS:
    return result

  # Set options to enable scanner features
  f_engine.engine = cl_engine_new()
  f_engine.options.parse = bitnot(bitor(f_engine.options.parse, 0))
  f_engine.options.general = bitor(f_engine.options.general, CL_SCAN_GENERAL_HEURISTICS)
  f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
  f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_DOC)
  f_engine.options.heuristic = bitor(f_engine.options.heuristic, CL_SCAN_HEURISTIC_MACROS)
  discard f_engine.engine.cl_engine_set_num(CL_ENGINE_MAX_FILESIZE, 75 * 1024 * 1024) # Max scan size 60mb

  # Did we set debug?
  if f_engine.debug_mode:
    cl_debug()

  # If database path is not empty, load ClamAV Signatures
  if f_engine.use_clam_sigs:
    var sig_count: cuint = 0
    result = cl_load(cstring(f_engine.database), f_engine.engine, unsafeAddr(sig_count), CL_DB_STDOPT)

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

  let
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE

  result = yr_rules_load(cstring(engine.database), unsafeAddr(engine.engine))

  if result != ERROR_SUCCESS:
    return result

  print_loaded_signatures(uint(engine.engine.num_rules), true)

  discard yr_set_configuration(YR_CONFIG_STACK_SIZE, unsafeAddr(stack_size))
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(max_strings_per_rule))
  return result


proc finit_yara*(engine: var YrEngine) =
  if engine.engine != nil:
    discard yr_rules_destroy(engine.engine)
  discard yr_finalize()
