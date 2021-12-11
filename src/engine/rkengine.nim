import .. / libs / libclamav / nim_clam
import .. / libs / libyara / nim_yara
import cores / [eng_cores, eng_init]
import scanners / [file_scanner, proc_scanner]


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


proc rkcheck_scan_proc*(engine: var CoreEngine, pid: int) =
  rscanner_new_proc_scan(engine, pid)


proc rkcheck_scan_procs*(engine: var CoreEngine) =
  rscanner_new_procs_scan(engine)


proc rkcheck_scan_files*(engine: var CoreEngine, file_list: seq[string]) =
  rscanner_new_files_scan(engine, file_list)


proc rkcheck_scan_file*(engine: var CoreEngine, file_path: string) =
  rscanner_new_file_scan(engine, file_path)


proc rkcheck_scan_dir*(engine: var CoreEngine, dir_path: string) =
  rscanner_new_dir_scan(engine, dir_path)


proc rkcheck_scan_dirs*(engine: var CoreEngine, dir_list: seq[string]) =
  rscanner_new_dirs_scan(engine, dir_list)
