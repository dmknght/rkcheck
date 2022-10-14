import .. / engine / [libyara, libclamav, engine_cores, scan_file, scan_proc]
import os


proc create_task_file_scan(yara_engine: YrEngine, list_files, list_dirs: seq[string]) =
  var
    file_scanner: FileScanner
    scanned: culong
    virname: cstring

  file_scanner.yr_scanner = yara_engine
  file_scanner.result_infected = 0
  file_scanner.result_scanned = 0


  if file_scanner.init_clamav() != ERROR_SUCCESS:
    echo "Failed to init ClamAV Engine" # TODO use cli module here
    return

  # TODO research and set callback for better workflow
  cl_engine_set_clcb_pre_cache(file_scanner.engine, fscanner_cb_scan_file)
  cl_engine_set_clcb_virus_found(file_scanner.engine, fscanner_cb_virus_found)

  if len(list_dirs) != 0:
    for dir_path in list_dirs:
      for path in walkDirRec(dir_path):
        discard cl_scanfile_callback(cstring(path), addr(virname), addr(scanned), file_scanner.engine, addr(file_scanner.options), addr(file_scanner))

  if len(list_files) != 0:
    for path in list_files:
      discard cl_scanfile_callback(cstring(path), addr(virname), addr(scanned), file_scanner.engine, addr(file_scanner.options), addr(file_scanner))

  finit_clamav(file_scanner)


proc create_task_proc_scan(yara_engine: YrEngine, list_procs: seq[string], scan_all_procs: bool) =
  var
    proc_scan_engine: ProcScanner
  proc_scan_engine.engine = yara_engine.engine
  if scan_all_procs:
    discard # TODO do proc walk here
  else:
    discard # TODO scan list procs here

  finit_yara(proc_scan_engine)


proc create_scan_task*(list_files, list_dirs, list_procs: seq[string] = @[], scan_all_procs = false) =
  # TODO must deduplicate input before call
  # TODO must define database path
  var
    yara_engine: YrEngine

  yara_engine.database = "database/signatures.ydb"

  if yara_engine.init_yara() != ERROR_SUCCESS:
    echo "Failed to init yara" # TODO use cli module here
    return

  if len(list_files) != 0 or len(list_dirs) != 0:
    create_task_file_scan(yara_engine, list_files, list_dirs)

  if len(list_procs) != 0 or scan_all_procs:
    create_task_proc_scan(yara_engine, list_procs, scan_all_procs)
