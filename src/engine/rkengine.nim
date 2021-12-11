import .. / libs / libclamav / nim_clam
import .. / libs / libyara / nim_yara
import os
import bitops
import strutils

type
  RkEngine* = object
    CL_Eng*: ptr cl_engine
    YR_Eng*: ptr YR_RULES
    cl_db_path*: string
    cl_scan_opts*: cl_scan_options
    yara_db_path*: string
    enable_clam_debug*: bool
  YR_User_Data* = object
    scan_object*: string
    scan_result*: cl_error_t
    virus_name*: cstring


var
  engine*: RkEngine
  user_data: YR_User_Data


proc cb_yr_scan(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    cast[ptr YR_User_Data](user_data).scan_result = CL_VIRUS
    cast[ptr YR_User_Data](user_data).virus_name = $cast[ptr YR_RULE](message_data).ns.name & ":" & $cast[ptr YR_RULE](message_data).identifier
    return CALLBACK_ABORT
  else:
    cast[ptr YR_User_Data](user_data).scan_result = CL_CLEAN
    cast[ptr YR_User_Data](user_data).virus_name = ""
    return CALLBACK_CONTINUE


proc cb_yr_process_scan(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    let binary_path = readFile(cast[ptr YR_User_Data](user_data).scan_object & "/cmdline")
    echo cast[ptr YR_RULE](message_data).ns.name, ":", cast[ptr YR_RULE](message_data).identifier, " ", binary_path
    return CALLBACK_ABORT
  else:
    cast[ptr YR_User_Data](user_data).virus_name = ""
    return CALLBACK_CONTINUE


proc cb_clam_virus_found(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  let
    virus_name = if user_data.virus_name != "": user_data.virus_name else: virname
  echo virus_name, " ", user_data.scan_object
  #[Analysis code only. Move file to other path]#
  # let newName = splitPath(user_data.scan_object).tail & "_detected"
  # moveFile(user_data.scan_object, "/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/" & newName)


proc cb_clam_prescan*(fd: cint, `type`: cstring, context: pointer): cl_error_t {.cdecl.} =
  let
    yr_scan_flags: cint = SCAN_FLAGS_FAST_MODE
    yr_scan_timeout: cint = 1000000
  discard yr_rules_scan_fd(engine.YR_Eng, fd, yr_scan_flags, cb_yr_scan, addr(user_data), yr_scan_timeout)
  return user_data.scan_result


proc rkeng_init_clam_eng(engine: var RkEngine): cl_error_t =
  #[ 
    Start ClamAV engine
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
  ]#
  result = cl_init(CL_INIT_DEFAULT)
  if result == CL_SUCCESS:
    engine.CL_Eng = cl_engine_new()
    engine.cl_scan_opts.parse = bitnot(bitor(engine.cl_scan_opts.parse, 0))
    engine.cl_scan_opts.general = bitor(engine.cl_scan_opts.general, CL_SCAN_GENERAL_HEURISTICS)
    engine.cl_scan_opts.heuristic = bitor(engine.cl_scan_opts.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
    engine.cl_scan_opts.heuristic = bitor(engine.cl_scan_opts.heuristic, CL_SCAN_HEURISTIC_ENCRYPTED_DOC)
    engine.cl_scan_opts.heuristic = bitor(engine.cl_scan_opts.heuristic, CL_SCAN_HEURISTIC_MACROS)
    cl_engine_set_clcb_pre_scan(engine.CL_Eng, cb_clam_prescan)
    cl_engine_set_clcb_virus_found(engine.CL_Eng, cb_clam_virus_found)
    if engine.enable_clam_debug:
      cl_debug()
  return result


proc rkeng_init_clam_db(engine: var RkEngine): cl_error_t =
  #[ 
    Load ClamAV database. In this case we only load bytecode signatures
    Bytecode signatures supports unpacking
    https://docs.clamav.net/manual/Development/libclamav.html#database-loading
    ]#
  var
    sig_count: cuint = 0
  result = cl_load(engine.cl_db_path, engine.CL_Eng, unsafeAddr(sig_count), CL_DB_STDOPT)
  if result == CL_SUCCESS:
    echo "Loaded ", sig_count, " ClamAV signatures"
  return result


proc rkeng_finit_clam(engine: var RkEngine) =
  #[ 
    Give ClamAV Engine's freedom
    https://docs.clamav.net/manual/Development/libclamav.html#initialization
    ]#
  if engine.CL_Eng != nil:
    discard cl_engine_free(engine.CL_Eng)


proc rkeng_init_yara(engine: var RkEngine): int =
  return yr_initialize()


proc rkeng_init_yara_db(engine: var RkEngine): int =
  let
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE

  result = yr_rules_load(engine.yara_db_path, unsafeAddr(engine.YR_Eng))
  if result == ERROR_SUCCESS:
    echo "Loaded ", engine.YR_Eng.num_rules, " Yara rules"
    discard yr_set_configuration(YR_CONFIG_STACK_SIZE, unsafeAddr(stack_size))
    discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(max_strings_per_rule))
  return result


proc rkeng_finit_yara(engine: var RkEngine) =
  if engine.YR_Eng != nil:
    discard yr_rules_destroy(engine.YR_Eng)
  discard yr_finalize()


proc rkeng_start_clam(engine: var RkEngine): cl_error_t =
  result = rkeng_init_clam_eng(engine)
  if result != CL_SUCCESS:
    echo "Failed to init ClamAV engine. Error code ", result
    return result
  # result = rkeng_init_clam_db(engine)
  # if result != CL_SUCCESS:
  #   echo "Failed to load ClamAV DB. Error code ", result
  return result


proc rkeng_start_yara(engine: var RkEngine): int =
  result = rkeng_init_yara(engine)
  if result != ERROR_SUCCESS:
    echo "Failed to start yara engine. Error code ", result
    return result

  result = rkeng_init_yara_db(engine)
  if result != ERROR_SUCCESS:
    echo "Failed to load yara rules. Error code ", result
    return result


proc rkcheck_start_engine*(engine: var RkEngine): cl_error_t =
  result = rkeng_start_clam(engine)
  if result == CL_SUCCESS:
    result = cl_engine_compile(engine.CL_Eng)
    let yr_result = rkeng_start_yara(engine)
    if yr_result != ERROR_SUCCESS:
      result = CL_ERROR
    else:
      result = CL_SUCCESS
  return result


proc rkcheck_stop_engine*(engine: var RkEngine) =
  rkeng_finit_clam(engine)
  rkeng_finit_yara(engine)


proc rkcheck_scan_file*(file_path: string) =
  var
    virname: cstring
    scanned: culong = 0
  user_data.scan_object = file_path
  discard cl_scanfile(file_path, addr(virname), addr(scanned), engine.CL_Eng, addr(engine.cl_scan_opts))


proc rkcheck_scan_dir*(dir_path: string) =
  for file_path in walkDirRec(dir_path):
    rkcheck_scan_file(file_path)


proc rkcheck_scan_dirs*(dir_paths: seq[string]) =
  for dir_path in dir_paths:
    rkcheck_scan_dir(dir_path)


proc rkcheck_scan_procs*() =
  let yr_scan_timeout: cint = 1000000
  for kind, path in walkDir("/proc/"):
    if kind == pcDir:
      try:
        let proc_id = parseInt(path.split("/")[^1])
        user_data.scan_object = path
        discard yr_rules_scan_proc(engine.YR_Eng, cint(proc_id), 0, cb_yr_process_scan, addr(user_data), yr_scan_timeout)
      except ValueError:
        discard
