import libyara
import libclamav
import engine_cores
import .. / cli / [progress_bar, print_utils]
import strutils
import os
import strformat

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
  ProcChunkInfo* {.bycopy, importc: "struct _YR_PROC_INFO".} = object
    pid*: cint
    mem_fd*: cint
    pagemap_fd*: cint
    maps*: ptr FILE
    map_offset*: uint64
    next_block_end*: uint64
    page_size*: cint
    map_path*: cstring
    map_dmaj*: uint64
    map_dmin*: uint64
    map_ino*: uint64


proc pscanner_on_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  # TODO improve this function
  let
    ctx = cast[ptr ProcScanCtx](context)

  ctx.scan_result = CL_VIRUS
  ctx.proc_infected += 1
  print_process_infected(ctx.pinfo.pid, $virname, ctx.pinfo.proc_exe, ctx.pinfo.mapped_file, ctx.pinfo.proc_name)


proc pscanner_cb_scan_proc_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanCtx](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    # If iterator failed to map memblocks, the mapped_file is empty
    if isEmptyOrWhitespace(ctx.pinfo.mapped_file):
      ctx.pinfo.mapped_file = ctx.pinfo.proc_exe

    ctx.virname = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    ctx.proc_infected += 1
    ctx.scan_result = CL_VIRUS
    print_process_infected(ctx.pinfo.pid, $ctx.virname, ctx.scan_object, ctx.pinfo.mapped_file, ctx.pinfo.proc_name)
    ctx.pinfo.mapped_file = ""
    return CALLBACK_ABORT
  else:
    ctx.virname = ""
    ctx.scan_result = CL_CLEAN
    return CALLBACK_CONTINUE


proc pscanner_get_fd_path(procfs: string, fd_id: int): string =
  let
    handler_path = fmt"{procfs}fd/{fd_id}"

  try:
    if symlinkExists(handler_path):
      return expandSymlink(handler_path)
    return ""
  except:
    return ""


proc pscanner_scan_block(ctx: var ProcScanCtx, mem_block, scan_block: ptr YR_MEMORY_BLOCK, base_size: uint): bool =
  discard yr_rules_scan_mem(ctx.yara.engine, mem_block[].fetch_data(scan_block), base_size, SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)
  # Keep scanning if user sets match_all_rules
  # TODO skip if cl_engine is Nil?
  if ctx.scan_result == CL_CLEAN or ctx.yara.match_all_rules:
    ctx.scan_result = CL_CLEAN
    var
      cl_map_file = cl_fmap_open_memory(mem_block[].fetch_data(scan_block), base_size)

    discard cl_scanmap_callback(cl_map_file, cstring(ctx.pinfo.proc_exe), addr(ctx.virname), addr(ctx.memblock_scanned), ctx.clam.engine, ctx.clam.options.addr, ctx.addr)
    cl_fmap_close(cl_map_file)

  # Stop scan if virus matches
  if not ctx.yara.match_all_rules and ctx.scan_result == CL_VIRUS:
    return false
  return true


proc pscanner_heur_proc(ctx: var ProcScanCtx, pid_stat: var ProcInfo) =
  # https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/
  # TODO test multiple cases to see if the value of variable cause false positive (variable life time)
  let proc_exe_exists = if fileExists(ctx.scan_object): cint(1) else: cint(0)

  discard yr_rules_define_boolean_variable(ctx.yara.engine, cstring("proc_exec_exists"), proc_exe_exists)
  discard yr_rules_define_string_variable(ctx.yara.engine, cstring("fd_stdin"), cstring(ctx.pinfo.fd_stdin))
  discard yr_rules_define_string_variable(ctx.yara.engine, cstring("fd_stdout"), cstring(ctx.pinfo.fd_stdout))
  discard yr_rules_define_string_variable(ctx.yara.engine, cstring("fd_stderr"), cstring(ctx.pinfo.fd_stderr))
  discard yr_rules_define_string_variable(ctx.yara.engine, cstring("proc_exe"), cstring(ctx.pinfo.proc_exe))
  discard yr_rules_define_string_variable(ctx.yara.engine, cstring("proc_name"), cstring(ctx.pinfo.proc_name))
  discard yr_rules_scan_mem(ctx.yara.engine, cast[ptr uint8](ctx.pinfo.cmdline[0].unsafeAddr), uint(len(ctx.pinfo.cmdline)), SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)


proc pscanner_cb_scan_proc(ctx: var ProcScanCtx): cint =
  var
    mem_blocks: YR_MEMORY_BLOCK_ITERATOR
    mem_block: ptr YR_MEMORY_BLOCK

  if yr_process_open_iterator(cint(ctx.pinfo.pid), mem_blocks.addr) == ERROR_SUCCESS:
    var
      scan_block: YR_MEMORY_BLOCK

    mem_block = mem_blocks.first(mem_blocks.addr)
    scan_block.base = mem_block.base
    scan_block.size = mem_block.size
    scan_block.context = mem_block.context

    while mem_block != nil:
      var
        context = cast[ptr YR_PROC_ITERATOR_CTX](mem_block.context)
        proc_info = cast[ptr ProcChunkInfo](context.proc_info)
      if isEmptyOrWhitespace($proc_info.map_path):
        if not pscanner_scan_block(ctx, mem_block, scan_block.addr, scan_block.size):
          break
        scan_block.base = mem_block.base
        scan_block.size = mem_block.size
        scan_block.context = mem_block.context
        ctx.pinfo.mapped_file = ctx.pinfo.proc_exe
      else:
        scan_block.size += mem_block.size
        ctx.pinfo.mapped_file = $proc_info.map_path
      mem_block = mem_blocks.next(mem_blocks.addr)

    discard yr_process_close_iterator(mem_blocks.addr)
  else:
    # Failed to Iterate memory blocks. Let Yara handles it?
    discard yr_rules_scan_proc(ctx.yara.engine, cint(ctx.pinfo.pid), SCAN_FLAGS_PROCESS_MEMORY, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)


#[
  Get process's information
]#
proc pscanner_process_pid(ctx: var ProcScanCtx, pid: uint) =
  # TODO optimize here for less useless variables or reuse values from Yara instead
  ctx.pinfo.procfs = fmt"/proc/{pid}/"
  if not dirExists(ctx.pinfo.procfs):
    return

  ctx.virname = ""
  ctx.pinfo.pid = pid
  ctx.pinfo.proc_name = readFile(fmt"{ctx.pinfo.procfs}comm")
  ctx.pinfo.proc_name.removeSuffix('\n')
  ctx.pinfo.cmdline = readFile(fmt"{ctx.pinfo.procfs}cmdline")
  ctx.pinfo.fd_stdin = pscanner_get_fd_path(ctx.pinfo.procfs, 0)
  ctx.pinfo.fd_stdout = pscanner_get_fd_path(ctx.pinfo.procfs, 1)
  ctx.pinfo.fd_stderr = pscanner_get_fd_path(ctx.pinfo.procfs, 2)
  ctx.pinfo.mapped_file = ""

  # Prevent out of bound error when cmdline is completely empty
  if isEmptyOrWhitespace(ctx.pinfo.cmdline):
    ctx.pinfo.cmdline = " "

  try:
    ctx.pinfo.proc_exe = expandSymlink(fmt"{ctx.pinfo.procfs}exe")
    # TODO check if path exists here
  except:
    ctx.pinfo.proc_exe = ""

  ctx.scan_object = ctx.pinfo.proc_exe
  ctx.scan_object.removeSuffix(" (deleted)")

  progress_bar_scan_proc(ctx.pinfo.pid, ctx.scan_object)
  pscanner_heur_proc(ctx, ctx.pinfo)
  if ctx.scan_result == CL_CLEAN:
    discard pscanner_cb_scan_proc(ctx)
  ctx.proc_scanned += 1


#[
  Walkthrough the list of pid
]#
proc pscanner_scan_procs*(ctx: var ProcScanCtx, list_procs: seq[uint]) =
  for pid in list_procs:
    pscanner_process_pid(ctx, pid)


#[
  Use procfs to get all pid in the system
]#
proc pscanner_scan_procs*(ctx: var ProcScanCtx) =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir:
      try:
        let pid = parseUint(splitPath(path).tail)
        pscanner_process_pid(ctx, pid)
      except ValueError:
        discard
