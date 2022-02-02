import .. / libs / libclamav / nim_clam
import .. / libs / libyara / nim_yara
import cores / [eng_cores, eng_init]
import scanners / [file_scanner, proc_scanner]


proc rkeng_start_clam(engine: var CoreEngine): cl_error_t =
  result = init_clam_engine(engine)
  if result != CL_SUCCESS:
    echo "Failed to init ClamAV engine. Error code ", result
    return result
  result = init_clam_db(engine)
  # Current version doesn't have upx unpacker on Linux
  return result


proc rkeng_start_yara(engine: var CoreEngine): cl_error_t =
  let init_eng_result = init_yara_engine(engine)
  if init_eng_result != ERROR_SUCCESS:
    echo "Failed to start yara engine. Error code ", init_eng_result
    return CL_ERROR

  let init_db_result = init_yara_db(engine)
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
  finit_clam_engine(engine)
  finit_yara_engine(engine)


proc rkcheck_scan_proc*(engine: var CoreEngine, pid: int) =
  var
    ScanContext: ProcScanContext
  ScanContext.ScanEngine = engine
  pscanner_new_proc_scan(ScanContext, pid)
  dealloc(addr(ScanContext))


proc rkcheck_scan_procs*(engine: var CoreEngine, pids: seq[int]) =
  var
    ScanContext: ProcScanContext
  ScanContext.ScanEngine = engine
  pscanner_new_procs_scan(ScanContext, pids)
  dealloc(addr(ScanContext))


proc rkcheck_scan_all_procs*(engine: var CoreEngine) =
  var
    ScanContext: ProcScanContext
  ScanContext.ScanEngine = engine
  pscanner_new_all_procs_scan(ScanContext)
  dealloc(addr(ScanContext))


proc rkcheck_scan_files*(engine: var CoreEngine, file_list: seq[string]) =
  var
    ScanContext: FileScanContext
  # engine.ClamAV.clcb_pre_cache = rscanner_cb_clam_scan
  ScanContext.ScanEngine = engine
  fscanner_new_files_scan(ScanContext, file_list)
  dealloc(addr(ScanContext))


proc rkcheck_scan_file*(engine: var CoreEngine, file_path: string) =
  var
    ScanContext: FileScanContext
  # engine.ClamAV.clcb_pre_cache = rscanner_cb_clam_scan
  ScanContext.ScanEngine = engine
  fscanner_new_file_scan(ScanContext, file_path)
  dealloc(addr(ScanContext))


proc rkcheck_scan_dir*(engine: var CoreEngine, dir_path: string) =
  var
    ScanContext: FileScanContext
  ScanContext.ScanEngine = engine
  fscanner_new_dir_scan(ScanContext, dir_path)
  dealloc(addr(ScanContext))


proc rkcheck_scan_dirs*(engine: var CoreEngine, dir_list: seq[string]) =
  var
    ScanContext: FileScanContext
  # engine.ClamAV.clcb_pre_cache = rscanner_cb_clam_scan
  ScanContext.ScanEngine = engine
  fscanner_new_dirs_scan(ScanContext, dir_list)
  dealloc(addr(ScanContext))
