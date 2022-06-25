import bitops
import .. / .. / libs / libclamav / nim_clam
import .. / .. / libs / libyara / nim_yara
import eng_cores


proc init_clam_engine*(engine: var CoreEngine): cl_error_t =
  #[
    Start ClamAV engine
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
  ]#
  result = cl_init(CL_INIT_DEFAULT)
  if result == CL_SUCCESS:
    engine.ClamAV = cl_engine_new()
    engine.ClamScanOpts.parse = bitnot(bitor(engine.ClamScanOpts.parse, 0))
    engine.ClamScanOpts.general = bitor(engine.ClamScanOpts.general, CL_SCAN_GENERAL_HEURISTICS)
    engine.ClamScanOpts.heuristic = bitor(engine.ClamScanOpts.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
    engine.ClamScanOpts.heuristic = bitor(engine.ClamScanOpts.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_DOC)
    engine.ClamScanOpts.heuristic = bitor(engine.ClamScanOpts.heuristic, CL_SCAN_HEURISTIC_MACROS)
    discard engine.ClamAV.cl_engine_set_num(CL_ENGINE_PCRE_MAX_FILESIZE, 60 * 1024 * 1024) # Max scan size 60mb
    if engine.LibClamDebug:
      cl_debug()
  return result


proc init_yara_engine*(engine: var CoreEngine): int =
  return yr_initialize()


proc init_clam_db*(engine: var CoreEngine): cl_error_t =
  #[
    Load ClamAV database. In this case we only load bytecode signatures
    Bytecode signatures supports unpacking
    https://docs.clamav.net/manual/Development/libclamav.html#database-loading
    ]#
  var
    sig_count: cuint = 0
  # TODO skip if path is invalid
  if engine.ClamDbPath == "":
    return CL_SUCCESS
  result = cl_load(cstring(engine.ClamDbPath), engine.ClamAV, unsafeAddr(sig_count), CL_DB_STDOPT)
  if result == CL_SUCCESS:
    echo "Loaded ", sig_count, " ClamAV signatures"
  return result


proc init_yara_db*(engine: var CoreEngine): int =
  let
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE

  result = yr_rules_load(cstring(engine.YaraDbPath), unsafeAddr(engine.YaraEng))
  if result == ERROR_SUCCESS:
    echo "Loaded ", engine.YaraEng.num_rules, " Yara rules"
    discard yr_set_configuration(YR_CONFIG_STACK_SIZE, unsafeAddr(stack_size))
    discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(max_strings_per_rule))
  return result


proc finit_clam_engine*(engine: var CoreEngine) =
  #[ 
    Give ClamAV Engine's freedom
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
    ]#
  if engine.ClamAV != nil:
    discard cl_engine_free(engine.ClamAV)


proc finit_yara_engine*(engine: var CoreEngine) =
  if engine.YaraEng != nil:
    discard yr_rules_destroy(engine.YaraEng)
  discard yr_finalize()
