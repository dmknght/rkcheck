import os
import .. / engine / [libyara, libclamav, engine_cores, scan_file, scan_proc]


type
  KeyboardInterrupt = object of CatchableError


proc handle_keyboard_interrupt() {.noconv.} =
  raise newException(KeyboardInterrupt, "Keyboard Interrupt")


proc scanners_create_task_file_scan(yara_engine: YrEngine, options: ScanOptions, result_count, result_infect: var uint) =
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


proc scanners_create_task_file_scan_yr(yara_engine: var YrEngine, options: ScanOptions, result_count, result_infect: var uint) =

  try:
    if len(options.list_dirs) != 0:
      for dir_path in options.list_dirs:
        for path in walkDirRec(dir_path):
          fscanner_yr_scan_file(yara_engine, path)

    if len(options.list_files) != 0:
      for path in options.list_files:
        fscanner_yr_scan_file(yara_engine, path)
  except KeyboardInterrupt:
    return
  finally:
    discard
    # result_count = file_scanner.result_scanned
    # result_infect = file_scanner.result_infected



proc scanners_create_task_proc_scan(yara_engine: YrEngine, options: ScanOptions, result_count, result_infected: var uint) =
  var
    proc_scanner: ProcScanner

  if options.match_all:
    proc_scanner.match_all_rules = true
  else:
    proc_scanner.match_all_rules = false

  proc_scanner.sumary_scanned = 0
  proc_scanner.sumary_infected = 0
  proc_scanner.engine = yara_engine.engine

  try:
    if options.scan_all_procs:
      pscanner_scan_system_procs(proc_scanner)
    else:
      pscanner_scan_procs(proc_scanner, options.list_procs)
  except KeyboardInterrupt:
    return
  finally:
    result_count = proc_scanner.sumary_scanned
    result_infected = proc_scanner.sumary_infected
    finit_yara(proc_scanner)


proc scanners_create_scan_task*(options: ScanOptions, f_count, f_infect, p_count, p_infect: var uint) =
  var
    yara_engine: YrEngine

  yara_engine.database = options.db_path_yara
  setControlCHook(handle_keyboard_interrupt)

  if yara_engine.init_yara() != ERROR_SUCCESS:
    raise newException(ValueError, "Failed to init Yara Engine")

  if len(options.list_files) != 0 or len(options.list_dirs) != 0:
    scanners_create_task_file_scan(yara_engine, options, f_count, f_infect)

  if len(options.list_procs) != 0 or options.scan_all_procs:
    scanners_create_task_proc_scan(yara_engine, options, p_count, p_infect)


proc scanners_create_scan_preload*(options: var ScanOptions, f_count, f_infect, p_count, p_infect: var uint) =
  var
    yara_engine: YrEngine
  const
    ld_preload_path = "/etc/ld.so.preload"

  yara_engine.database = options.db_path_yara
  setControlCHook(handle_keyboard_interrupt)

  if yara_engine.init_yara() != ERROR_SUCCESS:
    raise newException(ValueError, "Failed to init Yara Engine")

  if fileExists(ld_preload_path):
    for line in lines(ld_preload_path):
      if fileExists(line):
        options.list_files.add(line)

  if len(options.list_files) != 0 or len(options.list_dirs) != 0:
    scanners_create_task_file_scan_yr(yara_engine, options, f_count, f_infect)

  if len(options.list_procs) != 0 or options.scan_all_procs:
    scanners_create_task_proc_scan(yara_engine, options, p_count, p_infect)
