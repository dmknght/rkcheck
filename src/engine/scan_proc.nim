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
    ctx.scan_virname = $rule.ns.name & ":" & replace($rule.identifier, "_", ".")
    ctx.sumary_infected += 1
    print_process_infected(ctx.pinfo.pid, ctx.scan_virname, ctx.pinfo.binary_path, ctx.pinfo.v_binary_path, ctx.pinfo.name)
    return CALLBACK_ABORT
  else:
    ctx.scan_virname = ""
    return CALLBACK_CONTINUE


# proc pscanner_cb_scan_cmdline_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
#   let
#     ctx = cast[ptr ProcScanner](user_data)
#     rule = cast[ptr YR_RULE](message_data)

#   if message == CALLBACK_MSG_RULE_MATCHING:
#     rule.ns.name = cstring("SusCmdline")
#     return pscanner_on_process_match(ctx, rule)
#   else:
#     ctx.scan_virname = ""
#     return CALLBACK_CONTINUE


proc pscanner_get_mapped_bin(base_offset, base_size: uint64, proc_id: uint): string =
  var
    offset_start = toHex(base_offset).toLowerAscii()
    offset_end = toHex(base_offset + base_size).toLowerAscii()

  offset_start.removePrefix('0')
  offset_end.removePrefix('0')
  return "/proc/" & $proc_id & "/map_files/" & offset_start & "-" & offset_end


proc pscanner_cb_scan_proc*(ctx: var ProcScanner): cint =
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
      # Calculate mapped binary
      let
        base_offset = mem_block[].base
        base_size = mem_block[].size
        mapped_binary = pscanner_get_mapped_bin(base_offset, base_size, ctx.pinfo.pid)

      try:
        ctx.pinfo.v_binary_path = expandSymlink(mapped_binary)
      except:
        # Failed to map. File not found or requires permission
        ctx.pinfo.v_binary_path = ctx.pinfo.binary_path
      discard yr_rules_scan_mem(ctx.engine, mem_block[].fetch_data(mem_block), base_size, SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_proc_result, addr(ctx.pinfo), YR_SCAN_TIMEOUT)
      # Stop scan if virus matches
      if not ctx.match_all_rules and not isEmptyOrWhitespace(ctx.scan_virname):
        break
      mem_block = mem_blocks.next(mem_blocks.addr)
    discard yr_process_close_iterator(mem_blocks.addr)

  # Scan cmdline so we can detect reverse shell
  # if ctx.scan_virname == "" and ctx.proc_cmdline != "":
  #   discard yr_rules_scan_mem(ctx.engine, cast[ptr uint8](ctx.proc_cmdline[0].unsafeAddr), uint(len(ctx.proc_cmdline)), SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_cmdline_result, addr(ctx), YR_SCAN_TIMEOUT)

  # TODO: scan process's stacks and execfile. Maybe need different ruleset?
  # https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/


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
    pid_stat.pid = parseUInt(splitPath(procfs).tail)
    return false


proc pscanner_process_pid(ctx: var ProcScanner, pid: uint) =
  let
    procfs_path = "/proc/" & $pid & "/"

  ctx.scan_virname = ""

  if not pscanner_attach_process(procfs_path, ctx.pinfo):
    # TODO print more info?
    # TODO what if process failed to map?
    print_process_hidden(ctx.pinfo.pid, "Heur:ProcCloak.StatusDenied")
  else:
    pscanner_heur_proc(ctx.pinfo)

  progress_bar_scan_proc(ctx.pinfo.pid, ctx.pinfo.binary_path)
  discard pscanner_cb_scan_proc(ctx)
  ctx.sumary_scanned += 1


proc pscanner_scan_procs*(ctx: var ProcScanner, list_procs: seq[uint]) =
  for pid in list_procs:
    pscanner_process_pid(ctx, pid)


proc pscanner_scan_system_procs*(ctx: var ProcScanner) =
  for i in countup(1, SCANNER_MAX_PROC_COUNT):
    pscanner_process_pid(ctx, uint(i))
