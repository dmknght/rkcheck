import libyara
import engine_cores
import engine_utils
import .. / cli / [progress_bar, print_utils]
import strutils
import os


proc pscanner_cb_scan_proc_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    ctx.scan_virname = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    ctx.proc_infected += 1
    print_process_infected(ctx.pinfo.pid, $ctx.scan_virname, ctx.pinfo.binary_path, ctx.pinfo.v_binary_path, ctx.pinfo.name)
    return CALLBACK_ABORT
  else:
    ctx.scan_virname = ""
    return CALLBACK_CONTINUE


proc pscanner_cb_scan_cmdline_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    rule.ns.name = cstring("SusCmdline")
    print_process_infected(ctx.pinfo.pid, $ctx.scan_virname, ctx.pinfo.binary_path, ctx.scan_object & "/exe", ctx.pinfo.name)
    return CALLBACK_ABORT
  else:
    ctx.scan_virname = ""
    return CALLBACK_CONTINUE


proc pscanner_get_mapped_mem(base_offset, base_size: uint64, proc_id: uint): string =
  var
    offset_start = toHex(base_offset).toLowerAscii()
    offset_end = toHex(base_offset + base_size).toLowerAscii()

  offset_start.removePrefix('0')
  offset_end.removePrefix('0')
  return "/proc/" & $proc_id & "/map_files/" & offset_start & "-" & offset_end


proc pscanner_get_mapped_bin(pinfo: var PidInfo, base_offset, base_size: uint64) =
  # Calculate mapped binary
  let
    mapped_binary = pscanner_get_mapped_mem(base_offset, base_size, pinfo.pid)

  try:
    pinfo.v_binary_path = expandSymlink(mapped_binary)
  except:
    # Failed to map. File not found or requires permission
    pinfo.v_binary_path = pinfo.binary_path


proc pscanner_cb_scan_proc*(ctx: var ProcScanner): cint =
  # Scan cmdline so we can detect reverse shell or malicious exec
  if not isEmptyOrWhitespace(ctx.pinfo.cmdline):
    discard yr_rules_scan_mem(ctx.engine, cast[ptr uint8](ctx.pinfo.cmdline[0].unsafeAddr), uint(len(ctx.pinfo.cmdline)), SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_cmdline_result, addr(ctx), YR_SCAN_TIMEOUT)

  # Malware found by scan cmdline
  if not isEmptyOrWhitespace($ctx.scan_virname):
    return 0

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

      pscanner_get_mapped_bin(ctx.pinfo, base_offset, base_size)
      discard yr_rules_scan_mem(ctx.engine, mem_block[].fetch_data(mem_block), base_size, SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)
      # Stop scan if virus matches
      if not ctx.match_all_rules and not isEmptyOrWhitespace($ctx.scan_virname):
        break
      mem_block = mem_blocks.next(mem_blocks.addr)
    discard yr_process_close_iterator(mem_blocks.addr)


proc pscanner_heur_proc(pid_stat: var PidInfo) =
  # https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/
  if pid_stat.binary_path.startsWith("[") and pid_stat.binary_path.endsWith("]"):
    proc_scanner_on_proccess_masquerading(pid_stat.pid, pid_stat.binary_path, pid_stat.name)
  elif pid_stat.binary_path.endsWith("(deleted)"):
    proc_scanner_on_binary_deleted(pid_stat.pid, pid_stat.binary_path, pid_stat.name)


proc pscanner_attach_process(procfs: string, pid_stat: var PidInfo): bool =
  try:
    pid_stat.binary_path = expandSymlink(procfs & "/exe")
  except:
    pid_stat.binary_path = ""

  try:
    pid_stat.cmdline = readFile(procfs & "/cmdline").replace("\x00", " ")
  except:
    pid_stat.cmdline = ""

  try:
    for line in lines(procfs & "/status"):
      if line.startsWith("Name:"):
        pid_stat.name = line.split()[^1]
      elif line.startsWith("Pid:"):
        pid_stat.pid = parseUInt(line.split()[^1])
      elif line.startsWith("Tgid"):
        pid_stat.tgid = parseUInt(line.split()[^1])
      elif line.startsWith("PPid:"):
        pid_stat.ppid = parseUInt(line.split()[^1])
        return true
  except IOError:
    return false


proc pscanner_process_pid(ctx: var ProcScanner, pid: uint) =
  let
    procfs_path = "/proc/" & $pid & "/"

  ctx.scan_virname = ""
  ctx.pinfo.pid = pid
  ctx.scan_object = procfs_path

  #[
    If the process is hidden by LKM / eBPF rootkits, dir stat can be hijacked
    Check status file exists is a temp way to do "double check"
    TODO find a better way to handle this, otherwise scanner can't scan hidden
    proccesses
  ]#
  if not dirExists(procfs_path) and not fileExists(procfs_path & "/status"):
    return

  if not pscanner_attach_process(procfs_path, ctx.pinfo):
    # TODO print more info?
    # TODO what if process failed to map?
    print_process_hidden(ctx.pinfo.pid, "Heur:ProcCloak.StatusDenied")
  else:
    pscanner_heur_proc(ctx.pinfo)

  progress_bar_scan_proc(ctx.pinfo.pid, ctx.pinfo.binary_path)
  discard pscanner_cb_scan_proc(ctx)
  ctx.proc_scanned += 1


proc pscanner_scan_procs*(ctx: var ProcScanner, list_procs: seq[uint]) =
  for pid in list_procs:
    pscanner_process_pid(ctx, pid)


proc pscanner_scan_procs*(ctx: var ProcScanner) =
  for i in (1 .. SCANNER_MAX_PROC_COUNT):
    pscanner_process_pid(ctx, uint(i))
