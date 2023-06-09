import os
# import sequtils
import .. / engine / [libyara, libclamav, engine_cores, scan_file, scan_proc]
import .. / cli / print_utils


type
  KeyboardInterrupt = object of CatchableError


proc handle_keyboard_interrupt() {.noconv.} =
  raise newException(KeyboardInterrupt, "Keyboard Interrupt")


proc scanners_pre_scan_file(scanner: var FileScanCtx, virname: var cstring, scanned: var culong) =
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

  if yr_filemap_map(cstring(scanner.scan_object), addr(map_file)) == ERROR_SUCCESS:
    #[
      The YR_MAPPED_FILE has `file` as a file descriptor value
      However, using yr_rules_scan_fd is slower than accessing file (2.79 when scan fd vs 2.10 when scan file)
    ]#
    # Check if the file is ELF file
    # The ELF header is 52 or 64 bytes long for 32-bit and 64-bit binaries
    if map_file.size > 52 and cmpMem(map_file.data, addr(elf_magic[0]), 4) == 0:
      # TODO check condition. for example: not elf file and size < 52
      is_elf_file = true
    # Not ELF file, scan with ClamAV
    else:
      is_elf_file = false
    yr_filemap_unmap(addr(map_file))

  if is_elf_file:
    fscanner_yr_scan_file(scanner)
  else:
    discard cl_scanfile_callback(cstring(scanner.scan_object), addr(virname), addr(scanned), scanner.clam.engine, addr(scanner.clam.options), addr(scanner))


proc scanners_cl_scan_files*(scan_ctx: var ScanCtx, list_files, list_dirs: seq[string], result_count, result_infect: var uint) =
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

  try:
    if len(list_dirs) != 0:
      for dir_path in list_dirs:
        for path in walkDirRec(dir_path):
          file_scanner.scan_object = path
          scanners_pre_scan_file(file_scanner, virname, scanned)

    if len(list_files) != 0:
      for path in list_files:
        file_scanner.scan_object = path
        scanners_pre_scan_file(file_scanner, virname, scanned)
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

  try:
    if all_procs:
      pscanner_scan_procs(proc_scanner)
    else:
      pscanner_scan_procs(proc_scanner, list_procs)
  except KeyboardInterrupt:
    return
  finally:
    result_count = proc_scanner.proc_scanned
    result_infected = proc_scanner.proc_infected


# proc scanners_iterate_preload() =
#   const
#     ld_preload_path = "/etc/ld.so.preload"

#   if options.scan_preload and fileExists(ld_preload_path):
#     for line in lines(ld_preload_path):
#       if fileExists(line):
#         options.list_files.add(line)

#   options.list_files = deduplicate(options.list_files)


proc scanners_init_engine(ctx: var ScanCtx, options: ScanOptions) =
  #[
    Init Yara and ClamAV
  ]#
  var
    loaded_yara_sigs: uint = 0
    loaded_clam_sigs: uint = 0

  ctx.yara.database = options.db_path_yara
  discard ctx.yara.init_yara(loaded_yara_sigs)

  ctx.clam.debug_mode = options.is_clam_debug
  ctx.clam.database = options.db_path_clamav
  ctx.clam.use_clam = options.use_clam_db

  if ctx.clam.init_clamav(loaded_clam_sigs, ctx.clam.use_clam) != ERROR_SUCCESS:
    raise newException(ValueError, "Failed to init ClamAV Engine")

  #[
    ClamAV scan phases
    1. pre_cache: Access file (both inner and outer) before scan
    2. pre_scan: Before scan
    3. post_scan: after file scan complete
    4. virus_found: only when a virus is found
  ]#
  # Only use Yara's scan engine if the init process completed
  if ctx.yara.engine != nil:
    cl_engine_set_clcb_pre_cache(ctx.clam.engine, fscanner_cb_pre_scan_cache)
  elif loaded_clam_sigs == 0:
    raise newException(ValueError, "No valid signatures.")
  else:
    cl_engine_set_clcb_post_scan(ctx.clam.engine, fscanner_cb_inc_count)

  cl_engine_set_clcb_virus_found(ctx.clam.engine, fscanner_cb_virus_found)
  cl_set_clcb_msg(fscanner_cb_msg_dummy)


proc scanners_finit_engine(ctx: var ScanCtx, f_count, f_infect, p_count, p_infect: uint) =
  finit_yara(ctx.yara)
  finit_clamav(ctx.clam)
  print_sumary(f_count, f_infect, p_count, p_infect)


proc scanners_create_scan_task*(options: var ScanOptions) =
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

  if len(options.list_files) != 0 or len(options.list_dirs) != 0:
    scanners_cl_scan_files(scan_engine, options.list_files, options.list_dirs, f_count, f_infect)

  if len(options.list_procs) != 0 or options.scan_all_procs:
    scanners_yr_scan_procs(scan_engine, options.list_procs, options.scan_all_procs, p_count, p_infect)

  scanners_finit_engine(scan_engine, f_count, f_infect, p_count, p_infect)
