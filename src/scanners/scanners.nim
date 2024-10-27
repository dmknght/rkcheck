import os
import .. / engine / [engine_cores, scan_file, scan_proc, scan_userland_hook]
import ../ engine / bindings / [libyara, libclamav]
import ../ cli / print_utils


type
  KeyboardInterrupt = object of CatchableError


proc handle_keyboard_interrupt() {.noconv.} =
  raise newException(KeyboardInterrupt, "Keyboard Interrupt")


proc scanners_cl_scan_files*(scan_ctx: var ScanCtx, list_path_objects: seq[string], result_count, result_infect: var uint) =
  #[
    Job: walkDir and call scan
  ]#
  var
    file_scanner = FileScanCtx(
      yara: scan_ctx.yara,
      clam: scan_ctx.clam,
      scan_object: scan_ctx.scan_object,
      scan_result: scan_ctx.scan_result,
      virname: scan_ctx.virname,
      file_scanned: 0,
      file_infected: 0
    )
    scanned: culong
    virname: cstring

  file_scanner.clam.options = scan_ctx.clam.options
  cl_engine_set_clcb_virus_found(file_scanner.clam.engine, fscanner_on_malware_found_clam)

  try:
    for each_scan_object in list_path_objects:
      case getFileInfo(each_scan_object).kind
      of pcDir:
        for path in walkDirRec(each_scan_object):
          fscanner_scan_file(file_scanner, path, virname, scanned)
      of pcLinkToDir:
        for path in walkDirRec(each_scan_object):
          fscanner_scan_file(file_scanner, path, virname, scanned)
      else:
        fscanner_scan_file(file_scanner, each_scan_object, virname, scanned)
  except KeyboardInterrupt:
    return
  finally:
    result_count = file_scanner.file_scanned
    result_infect = file_scanner.file_infected


proc scanners_yr_scan_procs(scan_ctx: var ScanCtx, list_procs: seq[uint], all_procs: bool, result_count, result_infected: var uint) =
  var
    proc_scanner = ProcScanCtx(
      yara: scan_ctx.yara,
      clam: scan_ctx.clam,
      scan_object: scan_ctx.scan_object,
      scan_result: scan_ctx.scan_result,
      virname: scan_ctx.virname,
      proc_scanned: 0,
      proc_infected: 0
    )

  proc_scanner.clam.options = scan_ctx.clam.options
  cl_engine_set_clcb_virus_found(proc_scanner.clam.engine, pscanner_on_virus_found_clam)

  try:
    if all_procs:
      pscanner_scan_processes(proc_scanner)
    else:
      pscanner_scan_processes(proc_scanner, list_procs)
  except KeyboardInterrupt:
    return
  finally:
    result_count = proc_scanner.proc_scanned
    result_infected = proc_scanner.proc_infected


proc scanners_init_engine(ctx: var ScanCtx, options: ScanOptions) =
  #[
    Init Yara and ClamAV
  ]#
  var
    loaded_yara_sigs: uint = 0
    loaded_clam_sigs: uint = 0

  discard ctx.yara.init_yara(loaded_yara_sigs, options.db_path_yara)

  if ctx.clam.init_clamav(loaded_clam_sigs, options.db_path_clamav, options.use_clam_db, options.is_clam_debug) != ERROR_SUCCESS:
    raise newException(ValueError, "Failed to init ClamAV Engine")

  #[
    ClamAV scan phases
    1. pre_cache: Access file (both inner and outer) before scan. Use less RAM
      question: Call this function scans archived files (inner) too?
    2. pre_scan: Before scan
    3. post_scan: after file scan complete
    4. virus_found: only when a virus is found
  ]#
  # Only use Yara's scan engine if the init process completed
  if ctx.yara.rules != nil:
    cl_engine_set_clcb_file_inspection(ctx.clam.engine, fscanner_cb_file_inspection)
  elif loaded_clam_sigs == 0:
    raise newException(ValueError, "No valid signatures found")
  else:
    cl_engine_set_clcb_post_scan(ctx.clam.engine, fscanner_cb_inc_count)

  cl_set_clcb_msg(fscanner_slient_message_clam)


proc scanners_finish_scan(ctx: var ScanCtx, f_count, f_infect, p_count, p_infect: uint) =
  finit_yara(ctx.yara)
  finit_clamav(ctx.clam)
  print_sumary(f_count, f_infect, p_count, p_infect)


proc scanners_start_scan*(options: var ScanOptions) =
  #[
    Create a scan task
    Jobs:
      1. init ClamAV and Yara
      2. Call scan task
      3. finit ClamAV and Yara
  ]#

  var
    scan_engine: ScanCtx
    f_count, f_infect, p_count, p_infect: uint

  setControlCHook(handle_keyboard_interrupt)
  scanners_init_engine(scan_engine, options)

  if options.scan_function_hook:
    rk_hook_scan_userland()

  if len(options.list_path_objects) > 0:
    scanners_cl_scan_files(scan_engine, options.list_path_objects, f_count, f_infect)

  if len(options.list_procs) > 0 or options.scan_all_procs:
    scanners_yr_scan_procs(scan_engine, options.list_procs, options.scan_all_procs, p_count, p_infect)

  scanners_finish_scan(scan_engine, f_count, f_infect, p_count, p_infect)
