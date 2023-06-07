import os
import sequtils
import .. / engine / [libyara, libclamav, engine_cores, scan_file, scan_proc]
import .. / cli / print_utils


type
  KeyboardInterrupt = object of CatchableError


proc handle_keyboard_interrupt() {.noconv.} =
  raise newException(KeyboardInterrupt, "Keyboard Interrupt")


proc scanners_pre_scan_file(scanner: var FileScanner, virname: var cstring, scanned: var culong) =
  #[
    Use Yara's file map to read file in a safe way
    Then we compare data to check file header
    If the file header is ELF, we scan the file directly without calling the ClamAV file handler
    Expecting this will be faster
  ]#

  var
    map_file: YR_MAPPED_FILE
    elf_magic = "\x7F\x45\x4C\x46"
    is_elf_file: bool
    # TODO move elf_magic to const
    # TODO handle other file types like PE, MACH

  if yr_filemap_map(cstring(scanner.yr_scanner.scan_object), addr(map_file)) == ERROR_SUCCESS:
    # Check if the file is ELF file
    # FIXME the file is empty
    if map_file.size > 4 and cmpMem(map_file.data, addr(elf_magic[0]), 4) == 0:
      is_elf_file = true
    # Not ELF file, scan with ClamAV
    else:
      is_elf_file = false
    yr_filemap_unmap(addr(map_file))

  if is_elf_file:
    fscanner_yr_scan_file(scanner.yr_scanner)
  else:
    discard cl_scanfile_callback(cstring(scanner.yr_scanner.scan_object), addr(virname), addr(scanned), scanner.engine, addr(scanner.options), addr(scanner))


proc scanners_set_clamav_values(scanner: var FileScanner, yara_engine: YrEngine, options: ScanOptions) =
  scanner.yr_scanner = yara_engine
  scanner.yr_scanner.file_infected = 0
  scanner.yr_scanner.file_scanned = 0
  scanner.debug_mode = options.is_clam_debug
  scanner.database = options.db_path_clamav
  scanner.use_clam_sigs = options.use_clam_db

  var
    loaded_sig_count: uint

  if scanner.init_clamav(loaded_sig_count, scanner.use_clam_sigs) != ERROR_SUCCESS:
    raise newException(ValueError, "Failed to init ClamAV Engine")

  #[
    ClamAV scan phases
    1. pre_cache: Access file (both inner and outer) before scan
    2. pre_scan: Before scan
    3. post_scan: after file scan complete
    4. virus_found: only when a virus is found
  ]#
  # Only use Yara's scan engine if the init process completed
  if yara_engine.engine != nil:
    cl_engine_set_clcb_pre_cache(scanner.engine, fscanner_cb_pre_scan_cache)
  elif loaded_sig_count == 0:
    raise newException(ValueError, "No valid signatures.")
  else:
    cl_engine_set_clcb_post_scan(scanner.engine, fscanner_cb_inc_count)

  # if yara_engine.engine != nil:
  #   cl_engine_set_clcb_post_scan(scanner.engine, fscanner_cb_post_scan_file)
  # elif loaded_sig_count == 0:
  #   raise newException(ValueError, "No valid signatures.")
  # else:
  #   cl_engine_set_clcb_post_scan(scanner.engine, fscanner_cb_inc_count)

  cl_engine_set_clcb_virus_found(scanner.engine, fscanner_cb_virus_found)
  cl_set_clcb_msg(fscanner_cb_msg_dummy)


proc scanners_cl_scan_files*(yara_engine: var YrEngine, options: ScanOptions, result_count, result_infect: var uint) =
  var
    file_scanner: FileScanner
    scanned: culong
    virname: cstring

  scanners_set_clamav_values(file_scanner, yara_engine, options)

  try:
    if len(options.list_dirs) != 0:
      for dir_path in options.list_dirs:
        for path in walkDirRec(dir_path):
          file_scanner.yr_scanner.scan_object = path
          scanners_pre_scan_file(file_scanner, virname, scanned)

    if len(options.list_files) != 0:
      for path in options.list_files:
        file_scanner.yr_scanner.scan_object = path
        scanners_pre_scan_file(file_scanner, virname, scanned)
  except KeyboardInterrupt:
    return
  finally:
    result_count = file_scanner.yr_scanner.file_scanned
    result_infect = file_scanner.yr_scanner.file_infected
    finit_clamav(file_scanner)


proc scanners_yr_scan_files*(yara_engine: var YrEngine, options: ScanOptions, result_count, result_infect: var uint) =
  try:
    if len(options.list_dirs) != 0:
      for dir_path in options.list_dirs:
        for path in walkDirRec(dir_path):
          yara_engine.scan_object = path
          fscanner_yr_scan_file(yara_engine)

    if len(options.list_files) != 0:
      for path in options.list_files:
        yara_engine.scan_object = path
        fscanner_yr_scan_file(yara_engine)
  except KeyboardInterrupt:
    return
  finally:
    result_count = yara_engine.file_scanned
    result_infect = yara_engine.file_infected


proc scanners_set_proc_scan_values(scanner: var ProcScanner, options: ScanOptions, engine: ptr YR_RULES) =
  if options.match_all:
    scanner.match_all_rules = true
  else:
    scanner.match_all_rules = false

  scanner.proc_scanned = 0
  scanner.proc_infected = 0
  scanner.engine = engine


proc scanners_yr_scan_procs(yara_engine: YrEngine, options: ScanOptions, result_count, result_infected: var uint) =
  var
    proc_scanner: ProcScanner

  scanners_set_proc_scan_values(proc_scanner, options, yara_engine.engine)

  try:
    if options.scan_all_procs:
      pscanner_scan_procs(proc_scanner)
    else:
      pscanner_scan_procs(proc_scanner, options.list_procs)
  except KeyboardInterrupt:
    return
  finally:
    result_count = proc_scanner.proc_scanned
    result_infected = proc_scanner.proc_infected


proc scanners_create_scan_task*(options: var ScanOptions, scanner_cb_scan_files: proc (engine: var YrEngine, options: ScanOptions, f_count: var uint, f_infect: var uint)) =
  const
    ld_preload_path = "/etc/ld.so.preload"
  var
    yara_engine: YrEngine
    loaded_yara_sigs: uint = 0
    f_count, f_infect, p_count, p_infect: uint

  yara_engine.database = options.db_path_yara
  setControlCHook(handle_keyboard_interrupt)

  discard yara_engine.init_yara(loaded_yara_sigs)

  if options.scan_preload and fileExists(ld_preload_path):
    for line in lines(ld_preload_path):
      if fileExists(line):
        options.list_files.add(line)

  options.list_files = deduplicate(options.list_files)

  if len(options.list_files) != 0 or len(options.list_dirs) != 0:
    scanner_cb_scan_files(yara_engine, options, f_count, f_infect)

  if loaded_yara_sigs > 0 and (len(options.list_procs) != 0 or options.scan_all_procs):
    scanners_yr_scan_procs(yara_engine, options, p_count, p_infect)

  finit_yara(yara_engine)

  print_sumary(f_count, f_infect, p_count, p_infect)
