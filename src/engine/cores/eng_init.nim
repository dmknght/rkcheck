import bitops
import .. / .. / libs / libclamav / nim_clam
import .. / .. / libs / libyara / nim_yara
import eng_cores
import .. / scanners / file_scanner


proc rinit_clam_engine*(engine: var CoreEngine): cl_error_t =
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
    cl_engine_set_clcb_pre_scan(engine.ClamAV, rscanner_cb_clam_prescan)
    cl_engine_set_clcb_virus_found(engine.ClamAV, rscanner_cb_clam_virus_found)
    if engine.LibClamDebug:
      cl_debug()
  return result


proc rinit_yara_engine*(engine: var CoreEngine): int =
  return yr_initialize()


proc rinit_clam_db*(engine: var CoreEngine): cl_error_t =
  #[ 
    Load ClamAV database. In this case we only load bytecode signatures
    Bytecode signatures supports unpacking
    https://docs.clamav.net/manual/Development/libclamav.html#database-loading
    ]#
  var
    sig_count: cuint = 0
  result = cl_load(engine.ClamDbPath, engine.ClamAV, unsafeAddr(sig_count), CL_DB_STDOPT)
  if result == CL_SUCCESS:
    echo "Loaded ", sig_count, " ClamAV signatures"
  return result


proc rinit_yara_db*(engine: var CoreEngine): int =
  let
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE

  result = yr_rules_load(engine.YaraDbPath, unsafeAddr(engine.YaraEng))
  if result == ERROR_SUCCESS:
    echo "Loaded ", engine.YaraEng.num_rules, " Yara rules"
    discard yr_set_configuration(YR_CONFIG_STACK_SIZE, unsafeAddr(stack_size))
    discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(max_strings_per_rule))
  return result


proc rfinit_clam_engine*(engine: var CoreEngine) =
  #[ 
    Give ClamAV Engine's freedom
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
    ]#
  if engine.ClamAV != nil:
    discard cl_engine_free(engine.ClamAV)


proc rfinit_yara_engine*(engine: var CoreEngine) =
  if engine.YaraEng != nil:
    discard yr_rules_destroy(engine.YaraEng)
  discard yr_finalize()


# proc rkeng_start_clam(engine: var RkEngine): cl_error_t =
#   result = rkeng_init_clam_eng(engine)
#   if result != CL_SUCCESS:
#     echo "Failed to init ClamAV engine. Error code ", result
#     return result
#   # result = rkeng_init_clam_db(engine)
#   # if result != CL_SUCCESS:
#   #   echo "Failed to load ClamAV DB. Error code ", result
#   return result


# proc rkeng_start_yara(engine: var RkEngine): int =
#   result = rkeng_init_yara(engine)
#   if result != ERROR_SUCCESS:
#     echo "Failed to start yara engine. Error code ", result
#     return result

#   result = rkeng_init_yara_db(engine)
#   if result != ERROR_SUCCESS:
#     echo "Failed to load yara rules. Error code ", result
#     return result


# proc rkcheck_start_engine*(engine: var RkEngine): cl_error_t =
#   result = rkeng_start_clam(engine)
#   if result == CL_SUCCESS:
#     result = cl_engine_compile(engine.CL_Eng)
#     let yr_result = rkeng_start_yara(engine)
#     if yr_result != ERROR_SUCCESS:
#       result = CL_ERROR
#     else:
#       result = CL_SUCCESS
#   return result


# proc rkcheck_stop_engine*(engine: var RkEngine) =
#   rkeng_finit_clam(engine)
#   rkeng_finit_yara(engine)
