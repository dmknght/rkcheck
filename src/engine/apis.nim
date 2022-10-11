import .. / libs / libclamav / nim_clam
import .. / libs / libyara / nim_yara
import cores / [eng_cores, eng_init]
import scanners / [file_scanner, proc_scanner, scanner_consts]
import scan / scan_files
import os


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


# proc rkcheck_scan_proc*(engine: var CoreEngine, pid: int) =
#   var
#     ScanContext: ProcScanContext
#   ScanContext.ScanEngine = engine
#   pscanner_new_proc_scan(ScanContext, pid)
#   dealloc(addr(ScanContext))


proc rkcheck_scan_procs*(engine: var CoreEngine, pids: seq[uint]) =
  var
    scanContext: ProcScanContext

  scanContext.ScanEngine = engine
  pscanner_new_procs_scan(scanContext, pids)
  dealloc(addr(scanContext))


proc rkcheck_scan_all_procs*(engine: var CoreEngine) =
  var
    scanContext: ProcScanContext

  scanContext.ScanEngine = engine
  pscanner_new_all_procs_scan(scanContext)
  dealloc(addr(scanContext))


proc rkcheck_scan_files_and_dirs*(engine: var CoreEngine, file_list: openArray[string] = [], dir_list: openArray[string] = []) =
  var
    scanContext: FileScanContext

  scanContext.ScanEngine = engine
  scanContext.obj_scanned = 0
  scanContext.obj_infected = 0

  cl_engine_set_clcb_pre_cache(engine.ClamAV, fscanner_cb_clam_scan_file)
  cl_engine_set_clcb_virus_found(engine.ClamAV, fscanner_cb_clam_virus_found)

  if len(file_list) > 0:
    fscanner_new_files_scan(scanContext, @file_list)
  if len(dir_list) > 0:
    fscanner_new_dirs_scan(scanContext, @dir_list)

  echo "\nInfected: ", scanContext.obj_infected, " objects"
  echo "Scanned: ", scanContext.obj_scanned, " objects"


proc rkcheck_scan_startup_apps*(engine: var CoreEngine) =
  rkcheck_scan_files_and_dirs(engine, dir_list = [sys_dir_autostart, getHomeDir() & home_dir_autostart])
