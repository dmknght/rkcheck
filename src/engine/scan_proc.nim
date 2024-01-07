import strutils
import os
import strformat
import engine_cores
import bindings/[libyara, libclamav]
import ../cli/[progress_bar, print_utils]

#[
  Scan Linux's memory with ClamAV and Yara engine.
  1. Attach the process: Map all information from procfs
  2. Scan with Yara and ClamAV
  Memory blocks of Linux process, could be:
    A. Memory blocks mapped from a binary file
    B. Heap, Stack, ...
  The B. usually contains the data of a child process. Scanner should skip it to avoid false positive
]#

{.emit: """
  typedef struct _YR_PROC_ITERATOR_CTX
  {
    const uint8_t* buffer;
    size_t buffer_size;
    YR_MEMORY_BLOCK current_block;
    void* proc_info;
  } YR_PROC_ITERATOR_CTX;

  typedef struct _YR_PROC_INFO
  {
    int pid;
    int mem_fd;
    int pagemap_fd;
    FILE* maps;
    uint64_t map_offset;
    uint64_t next_block_end;
    int page_size;
    char map_path[PATH_MAX];
    uint64_t map_dmaj;
    uint64_t map_dmin;
    uint64_t map_ino;
  } YR_PROC_INFO;
  """.}

type
  MemBlockInfo {.bycopy, importc: "struct _YR_PROC_INFO".} = object
    pid: cint
    mem_fd: cint
    pagemap_fd: cint
    maps: ptr FILE
    map_offset: uint64
    next_block_end: uint64
    page_size: cint
    map_path: cstring
    map_dmaj: uint64
    map_dmin: uint64
    map_ino: uint64


#[
  Callback function for ClamAV
  Print information of infected process when malware is found
]#
proc pscanner_on_virus_found_clam*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  let
    ctx = cast[ptr ProcScanCtx](context)

  if ctx.scan_result == CL_CLEAN:
    ctx.scan_result = CL_VIRUS
    ctx.proc_infected += 1
    print_process_infected(ctx.pinfo.pid, $virname, ctx.scan_object, ctx.pinfo.proc_exe, ctx.pinfo.proc_name)
    ctx.virname = ""


#[
  Callback function for Yara scanner
  Print information of infected process when malware is found
]#
proc pscanner_on_virus_found_yara(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanCtx](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    ctx.virname = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    ctx.proc_infected += 1
    ctx.scan_result = CL_VIRUS
    print_process_infected(ctx.pinfo.pid, $ctx.virname, ctx.scan_object, ctx.pinfo.proc_exe, ctx.pinfo.proc_name)
    ctx.virname = ""
    return CALLBACK_ABORT
  else:
    ctx.virname = ""
    ctx.scan_result = CL_CLEAN
    return CALLBACK_CONTINUE


#[
  Get process's handler information
  /proc/<pid>/fd/<int>
]#
proc pscanner_get_fd_path(procfs: string, fd_id: int): string =
  let
    handler_path = fmt"{procfs}fd/{fd_id}"

  try:
    if symlinkExists(handler_path):
      return expandSymlink(handler_path)
    return ""
  except:
    return ""


#[
  Gather process's information
  Pass value to Yara's scanner using define variable
  This function also scans the cmdline
]#
proc pscanner_scan_heuristic(ctx: var ProcScanCtx) =
  let
    fd_stdin = pscanner_get_fd_path(ctx.pinfo.procfs, 0)
    fd_stdout = pscanner_get_fd_path(ctx.pinfo.procfs, 1)
    fd_stderr = pscanner_get_fd_path(ctx.pinfo.procfs, 2)
  var
    cmdline = readFile(fmt"{ctx.pinfo.procfs}cmdline")

  # Prevent out of bound error when cmdline is completely empty
  if isEmptyOrWhitespace(cmdline):
    cmdline = " "

  let
    proc_exe_exists = if fileExists(ctx.scan_object): cint(1) else: cint(0)

  discard yr_scanner_define_boolean_variable(ctx.yara.scanner, cstring("proc_exe_exists"), proc_exe_exists)
  discard yr_scanner_define_string_variable(ctx.yara.scanner, cstring("fd_stdin"), cstring(fd_stdin))
  discard yr_scanner_define_string_variable(ctx.yara.scanner, cstring("fd_stdout"), cstring(fd_stdout))
  discard yr_scanner_define_string_variable(ctx.yara.scanner, cstring("fd_stderr"), cstring(fd_stderr))
  discard yr_scanner_define_string_variable(ctx.yara.scanner, cstring("proc_exe"), cstring(ctx.pinfo.proc_exe))
  discard yr_scanner_define_string_variable(ctx.yara.scanner, cstring("proc_name"), cstring(ctx.pinfo.proc_name))
  discard yr_scanner_scan_mem(ctx.yara.scanner, cast[ptr uint8](cmdline[0].unsafeAddr), uint(len(cmdline)))


#[
  Scan current memory block with Yara and ClamAV. Return false if malware is found
]#
proc pscanner_scan_mem_block(ctx: var ProcScanCtx, mem_block, scan_block: ptr YR_MEMORY_BLOCK, base_size: uint): bool =
  if ctx.yara.scanner != nil:
    discard yr_scanner_scan_mem(ctx.yara.scanner, mem_block[].fetch_data(scan_block), base_size)

  if ctx.scan_result == CL_VIRUS:
    return false

  var
    cl_map_file = cl_fmap_open_memory(mem_block[].fetch_data(scan_block), base_size)
  discard cl_scanmap_callback(cl_map_file, cstring(ctx.scan_object), addr(ctx.virname), addr(ctx.memblock_scanned), ctx.clam.engine, ctx.clam.options.addr, ctx.addr)
  cl_fmap_close(cl_map_file)

  if ctx.scan_result == CL_VIRUS:
    return false
  return true


#[
  Iterate over all memory blocks, call scan_mem_block
  Instead of scan single blocks, this function merge blocks that belongs to a binary
  then call scan the whole big block
  If the current block doesn't belong to any file (heap, stack, ...), scan it
]#
proc pscanner_scan_memory(ctx: var ProcScanCtx) =
  if ctx.scan_result == CL_VIRUS:
    return

  var
    mem_blocks: YR_MEMORY_BLOCK_ITERATOR

  if yr_process_open_iterator(cint(ctx.pinfo.pid), mem_blocks.addr) == ERROR_SUCCESS:
    if mem_blocks.first(mem_blocks.addr) == nil:
      return

    var
      mem_block: ptr YR_MEMORY_BLOCK = mem_blocks.first(mem_blocks.addr)
      scan_block: YR_MEMORY_BLOCK

    scan_block.base = mem_block.base
    scan_block.size = mem_block.size
    scan_block.context = mem_block.context

    while mem_block != nil:
      var
        context = cast[ptr YR_PROC_ITERATOR_CTX](mem_block.context)
        proc_info = cast[ptr MemBlockInfo](context.proc_info)
      if isEmptyOrWhitespace($proc_info.map_path):
        if not pscanner_scan_mem_block(ctx, mem_block, scan_block.addr, scan_block.size):
          break
        scan_block.base = mem_block.base
        scan_block.size = mem_block.size
        scan_block.context = mem_block.context
        ctx.scan_object = ctx.pinfo.proc_exe
      else:
        scan_block.size += mem_block.size
        ctx.scan_object = $proc_info.map_path
      mem_block = mem_blocks.next(mem_blocks.addr)

    discard yr_process_close_iterator(mem_blocks.addr)
  else:
    # Failed to Iterate memory blocks. Let Yara handles it?
    discard yr_scanner_scan_proc(ctx.yara.scanner, cint(ctx.pinfo.pid))


#[
  Create a new YR_SCANNER object
  Set callback function
  Set scan flags
]#
proc pscanner_create_yr_scanner(ctx: var ProcScanCtx) =
  discard yr_scanner_create(ctx.yara.rules, ctx.yara.scanner.addr)
  ctx.yara.scanner.yr_scanner_set_callback(pscanner_on_virus_found_yara, addr(ctx))
  ctx.yara.scanner.yr_scanner_set_timeout(YR_SCAN_TIMEOUT)
  ctx.yara.scanner.yr_scanner_set_flags(SCAN_FLAGS_FAST_MODE)


proc pscanner_get_pid_info(ctx: var ProcScanCtx): bool =
  ctx.pinfo.procfs = fmt"/proc/{ctx.pinfo.pid}/"
  if not dirExists(ctx.pinfo.procfs):
    return false
  ctx.pinfo.proc_name = readFile(fmt"{ctx.pinfo.procfs}comm")
  ctx.pinfo.proc_name.removeSuffix('\n')
  try:
    ctx.pinfo.proc_exe = expandSymlink(fmt"{ctx.pinfo.procfs}exe")
  except:
    ctx.pinfo.proc_exe = ""

  ctx.scan_object = ctx.pinfo.proc_exe
  ctx.scan_object.removeSuffix(" (deleted)")
  return true


proc pscanner_process_pid(ctx: var ProcScanCtx) =
  if not pscanner_get_pid_info(ctx):
    return

  progress_bar_scan_proc(ctx.pinfo.pid, ctx.scan_object)
  if ctx.yara.rules != nil:
    pscanner_create_yr_scanner(ctx)
    pscanner_scan_heuristic(ctx)
  pscanner_scan_memory(ctx)
  ctx.proc_scanned += 1

  if ctx.yara.scanner != nil:
    yr_scanner_destroy(ctx.yara.scanner)


#[
  Walkthrough the list of pid
]#
proc pscanner_scan_processes*(ctx: var ProcScanCtx, list_procs: seq[uint]) =
  for pid in list_procs:
    ctx.pinfo.pid = pid
    pscanner_process_pid(ctx)


#[
  Use procfs to get all pid in the system
]#
proc pscanner_scan_processes*(ctx: var ProcScanCtx) =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir:
      try:
        let pid = parseUint(splitPath(path).tail)
        ctx.pinfo.pid = pid
        pscanner_process_pid(ctx)
      except ValueError:
        discard
