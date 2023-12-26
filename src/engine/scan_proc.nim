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


type
  ProcChunk = object
    binary_path: string
    chunk_start: uint64
    chunk_end: uint64


proc pscanner_on_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
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
    print_process_infected(ctx.pinfo.pid, $ctx.virname, ctx.pinfo.proc_exe, ctx.pinfo.mapped_file, ctx.pinfo.proc_name)
    return CALLBACK_ABORT
  else:
    ctx.virname = ""
    ctx.scan_result = CL_CLEAN
    return CALLBACK_CONTINUE


proc pscanner_mapped_addr_to_file_name(procfs: string, mem_start, mem_end: uint64, proc_id: uint): string =
  #[
    The procFS has symlink at /proc/<pid>/map_files/<map block here>
    This function crafts the memory chunk based on offset and size to map the file
  ]#
  var
    offset_start = toHex(mem_start).toLowerAscii()
    offset_end = toHex(mem_end).toLowerAscii()

  offset_start.removePrefix('0')
  offset_end.removePrefix('0')
  return fmt"{procfs}map_files/{offset_start}-{offset_end}"


proc pscanner_get_mapped_bin(pinfo: var ProcInfo, procfs: string, mem_info: var ProcChunk) =
  # TODO Yara engine has code to parse and map memory blocks (which has file name too). Is it better to rewrite it in Nim?
  # Get the name of binary mapped to memory
  if isEmptyOrWhitespace(mem_info.binary_path):
    let
      path_to_check = pscanner_mapped_addr_to_file_name(procfs, mem_info.chunk_start, mem_info.chunk_end, pinfo.pid)

    try:
      if symlinkExists(path_to_check):
        mem_info.binary_path = expandSymlink(path_to_check)
        pinfo.mapped_file = mem_info.binary_path
      else:
        mem_info.binary_path = ""
    except:
      pinfo.mapped_file = pinfo.proc_exe
      mem_info.binary_path = ""


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
  # TODO handle cmdline and socket fd
  # TODO check file exists (pinfo.exec_path) and pass it to yara rule
  discard yr_rules_define_string_variable(ctx.yara.engine, cstring("proc_exe"), cstring(ctx.pinfo.proc_exe))
  discard yr_rules_define_string_variable(ctx.yara.engine, cstring("proc_name"), cstring(ctx.pinfo.proc_name))
  discard yr_rules_scan_mem(ctx.yara.engine, cast[ptr uint8](ctx.pinfo.cmdline[0].unsafeAddr), uint(len(ctx.pinfo.cmdline)), SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)


proc pscanner_cb_scan_proc*(ctx: var ProcScanCtx): cint =
  #[
    Simulate Linux's scan proc by accessing YR_MEMORY_BLOCK_ITERATOR
    Keep expanding memory block if it mapped from the same file
    Then call yr_rules_scan_mem to scan each memory block
    # TODO: handle if either Yara or ClamAV failed to init
  ]#
  var
    mem_blocks: YR_MEMORY_BLOCK_ITERATOR
    mem_block: ptr YR_MEMORY_BLOCK
    scan_block: YR_MEMORY_BLOCK

  if yr_process_open_iterator(cint(ctx.pinfo.pid), mem_blocks.addr) == ERROR_SUCCESS:
    var
      binary_path: string

    mem_block = mem_blocks.first(mem_blocks.addr)
    scan_block.base = mem_block.base
    scan_block.size = mem_block.size
    scan_block.context = mem_block.context

    while mem_block != nil:
      var
        mem_info = ProcChunk(
          chunk_start: mem_block[].base,
          chunk_end: mem_block[].base + mem_block[].size
        )
      #[
        In /proc/<pid>/maps, if mem blocks belong to a same file, the end of previous block is the start of next block
      ]#
      pscanner_get_mapped_bin(ctx.pinfo, ctx.scan_object, mem_info)

      if isEmptyOrWhitespace(binary_path) or isEmptyOrWhitespace(mem_info.binary_path):
        # FIXME pipewire scan hangs (heap stuff). Spoiler alert: IT'S FUCKING SLOW
        if not pscanner_scan_block(ctx, mem_block, scan_block.addr, scan_block.size):
          break
        # Assign scan block to current block
        scan_block.base = mem_block.base
        scan_block.size = mem_block.size
        scan_block.context = mem_block.context
        binary_path = mem_info.binary_path
      else:
        scan_block.size += mem_block.size

      mem_block = mem_blocks.next(mem_blocks.addr)
    discard yr_process_close_iterator(mem_blocks.addr)
  else:
    # Failed to Iterate memory blocks. Let Yara handles it?
    discard yr_rules_scan_proc(ctx.yara.engine, cint(ctx.pinfo.pid), SCAN_FLAGS_PROCESS_MEMORY, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)


proc pscanner_process_pid(ctx: var ProcScanCtx, pid: uint) =
  # TODO optimize here for less useless variables
  ctx.pinfo.procfs = fmt"/proc/{pid}/"
  ctx.virname = ""
  ctx.pinfo.pid = pid
  ctx.scan_object = ctx.pinfo.procfs
  ctx.pinfo.proc_name = readFile(fmt"{ctx.pinfo.procfs}comm")
  ctx.pinfo.proc_name.removeSuffix('\n')
  ctx.pinfo.cmdline = readFile(fmt"{ctx.pinfo.procfs}cmdline").replace("\x00", " ")

  # Prevent out of bound error when cmdline is completely empty
  if isEmptyOrWhitespace(ctx.pinfo.cmdline):
    ctx.pinfo.cmdline = " "

  try:
    ctx.pinfo.proc_exe = expandSymlink(fmt"{ctx.pinfo.procfs}exe")
    # TODO check if path exists here
  except:
    ctx.pinfo.proc_exe = ""

  progress_bar_scan_proc(ctx.pinfo.pid, ctx.pinfo.proc_exe)
  pscanner_heur_proc(ctx, ctx.pinfo)
  if ctx.scan_result == CL_CLEAN:
    discard pscanner_cb_scan_proc(ctx)
  ctx.proc_scanned += 1


proc pscanner_scan_procs*(ctx: var ProcScanCtx, list_procs: seq[uint]) =
  for pid in list_procs:
    pscanner_process_pid(ctx, pid)


proc pscanner_scan_procs*(ctx: var ProcScanCtx) =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir:
      try:
        let pid = parseUint(splitPath(path).tail)
        pscanner_process_pid(ctx, pid)
      except ValueError:
        discard
