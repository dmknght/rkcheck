import os
import .. / engine / [libyara, libclamav, engine_cores, scan_file, scan_proc]


proc create_task_file_scan(yara_engine: YrEngine, list_files, list_dirs: seq[string], clam_debug, use_clam_sigs: bool, clam_db_path: string) =
  var
    file_scanner: FileScanner
    scanned: culong
    virname: cstring

  file_scanner.yr_scanner = yara_engine
  file_scanner.result_infected = 0
  file_scanner.result_scanned = 0
  file_scanner.debug_mode = clam_debug
  file_scanner.database = clam_db_path
  file_scanner.use_clam_sigs = use_clam_sigs

  if file_scanner.init_clamav() != ERROR_SUCCESS:
    raise newException(ValueError, "Failed to init ClamAV Engine")

  #[
    ClamAV scan phases
    1. pre_cache: Access file (both inner and outer) before scan
    2. pre_scan: Before scan
    3. post_scan: after file scan complete
    4. virus_found: only when a virus is found
  ]#
  cl_engine_set_clcb_post_scan(file_scanner.engine, fscanner_cb_scan_file)
  cl_engine_set_clcb_virus_found(file_scanner.engine, fscanner_cb_virus_found)

  if len(list_dirs) != 0:
    for dir_path in list_dirs:
      for path in walkDirRec(dir_path):
        file_scanner.scan_object = path
        discard cl_scanfile_callback(cstring(path), addr(virname), addr(scanned), file_scanner.engine, addr(file_scanner.options), addr(file_scanner))

  if len(list_files) != 0:
    for path in list_files:
      file_scanner.scan_object = path
      discard cl_scanfile_callback(cstring(path), addr(virname), addr(scanned), file_scanner.engine, addr(file_scanner.options), addr(file_scanner))

  finit_clamav(file_scanner)


proc create_task_proc_scan(yara_engine: YrEngine, list_procs: seq[uint], scan_all_procs: bool) =
  var
    proc_scan_engine: ProcScanner

  proc_scan_engine.engine = yara_engine.engine

  if scan_all_procs:
    pscanner_scan_system_procs(proc_scan_engine)
  else:
    pscanner_scan_procs(proc_scan_engine, list_procs)

  finit_yara(proc_scan_engine)


proc create_scan_task*(options: ScanOptions) =

  var
    yara_engine: YrEngine

  yara_engine.database = options.db_path_yara

  if yara_engine.init_yara() != ERROR_SUCCESS:
    raise newException(ValueError, "Failed to init Yara Engine")

  if len(options.list_files) != 0 or len(options.list_dirs) != 0:
    create_task_file_scan(yara_engine, options.list_files, options.list_dirs, options.is_clam_debug, options.use_clam_db, options.db_path_clamav)

  if len(options.list_procs) != 0 or options.scan_all_procs:
    create_task_proc_scan(yara_engine, options.list_procs, options.scan_all_procs)
