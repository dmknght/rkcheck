import libyara
import libclamav
import engine_cores
import engine_utils
import .. / cli / [progress_bar, print_utils]
import strutils
import os


#[
  Scan Linux's memory with ClamAV and Yara engine.
  1. Attach the process: Map all information from procfs
  2. Scan with Yara and ClamAV
]#


proc pscanner_on_virus_found*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  let
    ctx = cast[ptr ProcScanCtx](context)

  ctx.scan_result = CL_VIRUS
  print_process_infected(ctx.pinfo.pid, $virname, ctx.pinfo.exec_path, ctx.pinfo.mapped_file, ctx.pinfo.exec_name)


proc pscanner_cb_scan_proc_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanCtx](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    ctx.virname = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    ctx.proc_infected += 1
    ctx.scan_result = CL_VIRUS
    print_process_infected(ctx.pinfo.pid, $ctx.virname, ctx.pinfo.exec_path, ctx.pinfo.mapped_file, ctx.pinfo.exec_name)
    return CALLBACK_ABORT
  else:
    ctx.virname = ""
    ctx.scan_result = CL_CLEAN
    return CALLBACK_CONTINUE


proc pscanner_cb_scan_cmdline_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanCtx](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    rule.ns.name = cstring("Cmdline")
    ctx.scan_result = CL_VIRUS
    print_process_infected(ctx.pinfo.pid, $ctx.virname, ctx.pinfo.exec_path, ctx.scan_object & "exe", ctx.pinfo.exec_name)
    return CALLBACK_ABORT
  else:
    ctx.virname = ""
    ctx.scan_result = CL_CLEAN
    return CALLBACK_CONTINUE


proc pscanner_mapped_addr_to_file_name(procfs: string, base_offset, base_size: uint64, proc_id: uint): string =
  #[
    The procFS has symlink at /proc/<pid>/map_files/<map block here>
    This function crafts the memory chunk based on offset and size to map the file
  ]#
  var
    offset_start = toHex(base_offset).toLowerAscii()
    offset_end = toHex(base_offset + base_size).toLowerAscii()

  offset_start.removePrefix('0')
  offset_end.removePrefix('0')
  return procfs & "map_files/" & offset_start & "-" & offset_end


proc pscanner_get_mapped_bin(pinfo: var ProcInfo, procfs: string, base_offset, base_size: uint64) =
  # Calculate mapped binary
  let
    mapped_binary = pscanner_mapped_addr_to_file_name(procfs, base_offset, base_size, pinfo.pid)

  try:
    #[
      The current memory block sometime failed to go to craft the actual file
    ]#
    if symlinkExists(mapped_binary):
      pinfo.mapped_file = expandSymlink(mapped_binary)
    else:
      pinfo.mapped_file = ""
  except:
    # Failed to map. File not found or requires permission
    pinfo.mapped_file = pinfo.exec_path


proc pscanner_scan_cmdline(ctx: var ProcScanCtx) =
  # Scan cmdline so we can detect reverse shell or malicious exec
  if not isEmptyOrWhitespace(ctx.pinfo.cmdline):
    discard yr_rules_scan_mem(ctx.yara.engine, cast[ptr uint8](ctx.pinfo.cmdline[0].unsafeAddr), uint(len(ctx.pinfo.cmdline)), SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_cmdline_result, addr(ctx), YR_SCAN_TIMEOUT)


proc pscanner_yara_scan_mem(ctx: var ProcScanCtx, memblock: ptr YR_MEMORY_BLOCK, base_size: uint) =
  discard yr_rules_scan_mem(ctx.yara.engine, mem_block[].fetch_data(mem_block), base_size, SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)


proc pscanner_clam_scan_mem(ctx: var ProcScanCtx, memblock: ptr YR_MEMORY_BLOCK, base_size: uint) =
  # Scan mem block with ClamAV
  var
    virname: cstring
    scanned: culong

  var cl_map_file = cl_fmap_open_memory(mem_block[].fetch_data(mem_block), base_size)
  discard cl_scanmap_callback(cl_map_file, cstring(ctx.scan_object), virname.addr, scanned.addr, ctx.clam.engine, ctx.clam.options.addr, ctx.addr)
  cl_fmap_close(cl_map_file)


proc pscanner_cb_scan_proc*(ctx: var ProcScanCtx): cint =
  #[
    Simulate Linux's scan proc by accessing YR_MEMORY_BLOCK_ITERATOR
    Then call yr_rules_scan_mem to scan each memory block
  ]#
  var
    mem_blocks: YR_MEMORY_BLOCK_ITERATOR
    mem_block: ptr YR_MEMORY_BLOCK

  if yr_process_open_iterator(cint(ctx.pinfo.pid), mem_blocks.addr) == ERROR_SUCCESS:
    mem_block = mem_blocks.first(mem_blocks.addr)
    while mem_block != nil:
      let
        base_offset = mem_block[].base
        base_size = mem_block[].size

      pscanner_get_mapped_bin(ctx.pinfo, ctx.scan_object, base_offset, base_size)

      # If file failed to get the actual file, we should skip the block
      if isEmptyOrWhitespace(ctx.pinfo.mapped_file):
        mem_block = mem_blocks.next(mem_blocks.addr)
        continue

      pscanner_yara_scan_mem(ctx, mem_block, base_size)
      # Keep scanning if use match_all_rules
      if ctx.scan_result == CL_CLEAN or ctx.yara.match_all_rules:
        pscanner_clam_scan_mem(ctx, mem_block, base_size)
      if ctx.scan_result == CL_CLEAN or ctx.yara.match_all_rules:
        pscanner_scan_cmdline(ctx)

      # Stop scan if virus matches
      if not ctx.yara.match_all_rules and ctx.scan_result == CL_VIRUS:
        break
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
    pid_stat.exec_path = expandSymlink(procfs & "exe")
  except:
    pid_stat.exec_path = ""

  try:
    pid_stat.cmdline = readFile(procfs & "cmdline").replace("\x00", " ")
  except:
    pid_stat.cmdline = ""

  try:
    for line in lines(procfs & "status"):
      if line.startsWith("Name:"):
        pid_stat.exec_name = line.split()[^1]
      elif line.startsWith("Pid:"):
        pid_stat.pid = parseUInt(line.split()[^1])
      elif line.startsWith("Tgid"):
        pid_stat.tgid = parseUInt(line.split()[^1])
      elif line.startsWith("PPid:"):
        pid_stat.ppid = parseUInt(line.split()[^1])
        return true
  except IOError:
    return false


proc pscanner_process_pid(ctx: var ProcScanCtx, pid: uint) =
  let
    procfs_path = "/proc/" & $pid & "/"

  ctx.virname = ""
  ctx.pinfo.pid = pid
  ctx.scan_object = procfs_path

  #[
    If the process is hidden by LKM / eBPF rootkits, dir stat can be hijacked
    Check status file exists is a temp way to do "double check"
    TODO find a better way to handle this, otherwise scanner can't scan hidden
    proccesses
  ]#
  if not dirExists(procfs_path) and not fileExists(procfs_path & "status"):
    return

  if not pscanner_attach_process(procfs_path, ctx.pinfo):
    print_process_infected(ctx.pinfo.pid, "Heur:InvalidProc.StatusDenied", ctx.pinfo.exec_path, ctx.scan_object & "status", ctx.pinfo.exec_name)
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
