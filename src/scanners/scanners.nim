import os
import .. / engine / [libyara, libclamav, engine_cores, scan_file, scan_proc]


type
  KeyboardInterrupt = object of CatchableError


proc handle_keyboard_interrupt() {.noconv.} =
  raise newException(KeyboardInterrupt, "Keyboard Interrupt")


proc create_task_file_scan(yara_engine: YrEngine, options: ScanOptions, result_count, result_infect: var uint) =
  var
    file_scanner: FileScanner
    scanned: culong
    virname: cstring

  file_scanner.yr_scanner = yara_engine
  file_scanner.result_infected = 0
  file_scanner.result_scanned = 0
  file_scanner.debug_mode = options.is_clam_debug
  file_scanner.database = options.db_path_clamav
  file_scanner.use_clam_sigs = options.use_clam_db
  file_scanner.clam_parser = options.use_clam_parser

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
  cl_set_clcb_msg(fscanner_cb_msg_dummy)

  try:
    if len(options.list_dirs) != 0:
      for dir_path in options.list_dirs:
        for path in walkDirRec(dir_path):
          file_scanner.scan_object = path
          discard cl_scanfile_callback(cstring(path), addr(virname), addr(scanned), file_scanner.engine, addr(file_scanner.options), addr(file_scanner))

    if len(options.list_files) != 0:
      for path in options.list_files:
        file_scanner.scan_object = path
        discard cl_scanfile_callback(cstring(path), addr(virname), addr(scanned), file_scanner.engine, addr(file_scanner.options), addr(file_scanner))
  except KeyboardInterrupt:
    return
  finally:
    result_count = file_scanner.result_scanned
    result_infect = file_scanner.result_infected
    finit_clamav(file_scanner)


proc create_task_proc_scan(yara_engine: YrEngine, options: ScanOptions, result_count, result_infected: var uint) =
  var
    proc_scan_engine: ProcScanner

  proc_scan_engine.sumary_scanned = 0
  proc_scan_engine.sumary_infected = 0
  proc_scan_engine.engine = yara_engine.engine

  try:
    if options.scan_all_procs:
      pscanner_scan_system_procs(proc_scan_engine)
    else:
      pscanner_scan_procs(proc_scan_engine, options.list_procs)
  except KeyboardInterrupt:
    return
  finally:
    result_count = proc_scan_engine.sumary_scanned
    result_infected = proc_scan_engine.sumary_infected
    finit_yara(proc_scan_engine)


proc create_scan_task*(options: ScanOptions, f_count, f_infect, p_count, p_infect: var uint) =
  var
    yara_engine: YrEngine

  yara_engine.database = options.db_path_yara
  setControlCHook(handle_keyboard_interrupt)

  if yara_engine.init_yara() != ERROR_SUCCESS:
    raise newException(ValueError, "Failed to init Yara Engine")

  if len(options.list_files) != 0 or len(options.list_dirs) != 0:
    create_task_file_scan(yara_engine, options, f_count, f_infect)

  if len(options.list_procs) != 0 or options.scan_all_procs:
    create_task_proc_scan(yara_engine, options, p_count, p_infect)
