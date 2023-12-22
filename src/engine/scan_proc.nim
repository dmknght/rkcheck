import libyara
import libclamav
import engine_cores
import engine_utils
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
  ProcChunk* = object
    binary_path*: string
    chunk_start*: uint64
    chunk_end*: uint64


proc pscanner_on_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  let
    ctx = cast[ptr ProcScanCtx](context)

  ctx.scan_result = CL_VIRUS
  ctx.proc_infected += 1
  print_process_infected(ctx.pinfo.pid, $virname, ctx.pinfo.exec_path, ctx.pinfo.mapped_file, ctx.pinfo.exec_name)


proc pscanner_cb_scan_proc_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanCtx](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    # If iterator failed to map memblocks, the mapped_file is empty
    if isEmptyOrWhitespace(ctx.pinfo.mapped_file):
      ctx.pinfo.mapped_file = ctx.pinfo.exec_path

    ctx.virname = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    ctx.proc_infected += 1
    ctx.scan_result = CL_VIRUS
    print_process_infected(ctx.pinfo.pid, $ctx.virname, ctx.pinfo.exec_path, ctx.pinfo.mapped_file, ctx.pinfo.exec_name)
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
      pinfo.mapped_file = pinfo.exec_path
      mem_info.binary_path = ""


proc pscanner_scan_block(ctx: var ProcScanCtx, mem_block, scan_block: ptr YR_MEMORY_BLOCK, base_size: uint): bool =
  discard yr_rules_scan_mem(ctx.yara.engine, mem_block[].fetch_data(scan_block), base_size, SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)
  # Keep scanning if user sets match_all_rules
  # TODO skip if cl_engine is Nil?
  if ctx.scan_result == CL_CLEAN or ctx.yara.match_all_rules:
    ctx.scan_result = CL_CLEAN
    var
      cl_map_file = cl_fmap_open_memory(mem_block[].fetch_data(scan_block), base_size)

    discard cl_scanmap_callback(cl_map_file, cstring(ctx.pinfo.exec_path), addr(ctx.virname), addr(ctx.memblock_scanned), ctx.clam.engine, ctx.clam.options.addr, ctx.addr)
    cl_fmap_close(cl_map_file)

  # Stop scan if virus matches
  if not ctx.yara.match_all_rules and ctx.scan_result == CL_VIRUS:
    return false
  return true


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
        if not isEmptyOrWhitespace(binary_path):
          # FIXME check the max scan size. Scan processes like vmware, firefox, ... will break the system
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


proc pscanner_heur_proc(pid_stat: var ProcInfo) =
  # https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/
  if pid_stat.exec_path.startsWith("[") and pid_stat.exec_path.endsWith("]"):
    proc_scanner_on_proccess_masquerading(pid_stat.pid, pid_stat.exec_path, pid_stat.exec_name)
  elif pid_stat.exec_path.endsWith("(deleted)"):
    proc_scanner_on_binary_deleted(pid_stat.pid, pid_stat.exec_path, pid_stat.exec_name)


proc pscanner_attach_process(procfs: string, pid_stat: var ProcInfo): bool =
  try:
    pid_stat.exec_path = expandSymlink(fmt"{procfs}exe")
  except:
    pid_stat.exec_path = ""

  # TODO 
  # try:
  #   pid_stat.cmdline = readFile(fmt"{procfs}cmdline").replace("\x00", " ")
  # except:
  #   pid_stat.cmdline = ""

  try:
    for line in lines(fmt"{procfs}status"):
      if line.startsWith("Name:"):
        pid_stat.exec_name = line.split()[^1]
      elif line.startsWith("Pid:"):
        pid_stat.pid = parseUInt(line.split()[^1])
        return true
  except IOError:
    return false


proc pscanner_process_pid(ctx: var ProcScanCtx, pid: uint) =
  # TODO optimize here for less useless variables
  ctx.pinfo.procfs = fmt"/proc/{pid}/"
  ctx.virname = ""
  ctx.pinfo.pid = pid
  ctx.scan_object = ctx.pinfo.procfs

  #[
    If the process is hidden by LKM / eBPF rootkits, dir stat can be hijacked
    Check status file exists is a temp way to do "double check"
    TODO find a better way to handle this, otherwise scanner can't scan hidden
    proccesses
  ]#
  # TODO optimize the heuristic scan
  if not dirExists(ctx.pinfo.procfs) and not fileExists(fmt"{ctx.pinfo.procfs}status"):
    return

  if not pscanner_attach_process(ctx.pinfo.procfs, ctx.pinfo):
    print_process_infected(ctx.pinfo.pid, "Heur:InvalidProc.StatusDenied", ctx.pinfo.exec_path, fmt"{ctx.pinfo.procfs}status", ctx.pinfo.exec_name)
  else:
    pscanner_heur_proc(ctx.pinfo)

  progress_bar_scan_proc(ctx.pinfo.pid, ctx.pinfo.exec_path)
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
