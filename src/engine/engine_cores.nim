import libclamav
import libyara
import bitops
import .. / cli / print_utils
import engine_utils
import .. / compiler / compiler_utils


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
    match_all*: bool
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
    match_all_rules*: bool
  #[
    The ProcScanner (Process Scanner) will use only Yara's Engine
      proc_id: The ID number of process (pid)
      proc_path: Full path of pid in procfs
      proc_binary: Executable file that started process
  ]#
  ProcScanner* = object of YrEngine
    proc_id*: uint
    proc_tgid*: uint
    proc_ppid*: uint
    proc_pathfs*: string
    proc_name*: string
    proc_cmdline*: string
    proc_binary_path*: string
    virtual_binary_path*: string
    scan_virname*: string
    sumary_scanned*: uint
    sumary_infected*: uint
    # do_scan_stacks*: bool
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
  YrFileScanner* = object of YrEngine
    scan_object*: string
    scan_result*: cl_error_t
    scan_virname*: cstring
    result_scanned*: uint
    result_infected*: uint


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
  print_yara_version(YR_VERSION)

  discard yr_set_configuration(YR_CONFIG_STACK_SIZE, addr(stack_size))
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, addr(max_strings_per_rule))
  return result


proc finit_yara*(engine: var YrEngine) =
  if engine.engine != nil:
    discard yr_rules_destroy(engine.engine)
  discard yr_finalize()
