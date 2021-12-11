import .. / libs / libclamav / nim_clam
import .. / libs / libyara / nim_yara
import cores / [eng_cores, eng_init]


proc rkeng_start_clam(engine: var CoreEngine): cl_error_t =
  result = rinit_clam_engine(engine)
  if result != CL_SUCCESS:
    echo "Failed to init ClamAV engine. Error code ", result
    return result
  # result = rkeng_init_clam_db(engine) # TODO think about custom ClamAV signatures
  # Current version doesn't have upx unpacker on Linux
  return result


proc rkeng_start_yara(engine: var CoreEngine): cl_error_t =
  let init_eng_result = rinit_yara_engine(engine)
  if init_eng_result != ERROR_SUCCESS:
    echo "Failed to start yara engine. Error code ", init_eng_result
    return CL_ERROR

  let init_db_result = rinit_yara_db(engine)
  if init_db_result != ERROR_SUCCESS:
    echo "Failed to load yara rules. Error code ", init_db_result
    return CL_ERROR
  return CL_SUCCESS


proc rkcheck_start_engine*(engine: var CoreEngine): cl_error_t =
  result = rkeng_start_clam(engine)
  if result == CL_SUCCESS:
    result = cl_engine_compile(engine.ClamAV)
  result = rkeng_start_yara(engine)
  return result


proc rkcheck_stop_engine*(engine: var CoreEngine) =
  rfinit_clam_engine(engine)
  rfinit_yara_engine(engine)
