import libyara
import engine_cores
import engine_utils
import .. / cli / [progress_bar, print_utils]
import strutils
import os
import posix


proc pscanner_cb_scan_proc_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    ctx.scan_virname = $rule.ns.name & ":" & replace($rule.identifier, "_", ".")
    ctx.sumary_infected += 1
    print_process_infected(ctx.scan_virname, ctx.virtual_binary_path, ctx.proc_id)
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


proc pscanner_cb_scan_proc*(ctx: var ProcScanner): cint =
  #[
    Simulate Linux's scan proc by accessing YR_MEMORY_BLOCK_ITERATOR
    Then call yr_rules_scan_mem to scan each memory block
  ]#
  var
    mem_blocks: YR_MEMORY_BLOCK_ITERATOR
    mem_block: ptr YR_MEMORY_BLOCK
    offset_start, offset_end, mapped_binary: string

  if yr_process_open_iterator(cint(ctx.proc_id), mem_blocks.addr) == ERROR_SUCCESS:
    mem_block = mem_blocks.first(mem_blocks.addr)
    while mem_block != nil:
      # Calculate mapped binary
      offset_start = toHex(mem_block[].base).toLowerAscii()
      offset_start.removePrefix('0')
      offset_end = toHex(mem_block[].base + mem_block[].size).toLowerAscii()
      offset_end.removePrefix('0')
      mapped_binary = "/proc/" & $ctx.proc_id & "/map_files/" & offset_start & "-" & offset_end

      if fileExists(mapped_binary):
        try:
          ctx.virtual_binary_path = expandSymlink(mapped_binary)
        except:
          # Failed to map. Need root permission? Do not crash
          ctx.virtual_binary_path = ctx.proc_binary_path
      else:
        # Process's memory range
        ctx.virtual_binary_path = ctx.proc_binary_path

      discard yr_rules_define_integer_variable(ctx.engine, "vmem_start", int64(mem_block[].base))
      discard yr_rules_scan_mem(ctx.engine, mem_block[].fetch_data(mem_block), mem_block[].size, SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)
      # Stop scan if virus matches
      if not isEmptyOrWhitespace(ctx.scan_virname):
        break
      mem_block = mem_blocks.next(mem_blocks.addr)
    discard yr_process_close_iterator(mem_blocks.addr)

  # Scan cmdline so we can detect reverse shell
  # if ctx.scan_virname == "" and ctx.proc_cmdline != "":
  #   discard yr_rules_scan_mem(ctx.engine, cast[ptr uint8](ctx.proc_cmdline[0].unsafeAddr), uint(len(ctx.proc_cmdline)), SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_cmdline_result, addr(ctx), YR_SCAN_TIMEOUT)

  # TODO: scan process's stacks and execfile. Maybe need different ruleset?


proc pscanner_is_hidden_proc(ctx: ProcScanner) =
  if ctx.proc_id == ctx.proc_tgid and ctx.proc_ppid > 0:
    for kind, path in walkDir("/proc/"):
      if kind == pcDir and path & "/" == ctx.proc_pathfs:
        return
    print_process_hidden(ctx.proc_id, ctx.proc_name)


proc pscanner_attach_process(ctx: var ProcScanner, check_hidden: bool) =
  try:
    ctx.proc_binary_path = expandSymlink(ctx.proc_pathfs & "exe")
    # https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/
    let
      binary_name = ctx.proc_binary_path.splitPath().tail

    if binary_name.startsWith("[") and binary_name.endsWith("]"):
      proc_scanner_on_proccess_masquerading(ctx.proc_id, ctx.proc_binary_path)
    elif binary_name.endsWith("(deleted)"):
      proc_scanner_on_binary_deleted(ctx.proc_binary_path, ctx.proc_id)
  except OSError:
    # If process is a kernel thread or so, it's not posisble to expand /proc/<id>/exe (permission denied)
    # however, we can get process name from status
    let
      f = open(ctx.proc_pathfs & "status")
    ctx.proc_binary_path = f.readLine().split()[^1]
    f.close()

  ctx.proc_cmdline = readFile(ctx.proc_pathfs & "cmdline").replace("\x00", " ")

  if check_hidden:
    for line in lines(ctx.proc_pathfs & "status"):
      if line.startsWith("Name:"):
        ctx.proc_name = line.split()[^1]
      elif line.startsWith("Tgid"):
        ctx.proc_tgid = parseUInt(line.split()[^1])
      elif line.startsWith("PPid:"):
        ctx.proc_ppid = parseUInt(line.split()[^1])
        break


proc pscanner_process_pid(ctx: var ProcScanner, pid: uint) =
  let
    procfs_path = "/proc/" & $pid & "/"

  if not dirExists(procfs_path):
    return

  ctx.proc_pathfs = procfs_path
  ctx.proc_id = pid
  ctx.scan_virname = ""
  #[
    Some rootkits prevents normal process to read process's status
    However, dirExists (function stat) still shows true
    Use lstat instead of try catch to improve performance
    NOTICE: other processes can't access so the scanner can't be used
  ]#
  progress_bar_scan_proc(ctx.proc_id, ctx.proc_binary_path)

  var
    stat: Stat
  let
    procfs_path_status = ctx.proc_pathfs & "status"

  if lstat(cstring(procfs_path_status), stat) == -1 and fileExists(procfs_path_status):
    print_process_hidden(ctx.proc_id, "Heur:ProcCloak.StatusDenied")
    return

  pscanner_attach_process(ctx, ctx.do_check_hidden_procs)

  if ctx.do_check_hidden_procs:
    # Brute force procfs. Slow. Requires a different flag
    pscanner_is_hidden_proc(ctx)

  discard pscanner_cb_scan_proc(ctx)
  ctx.sumary_scanned += 1


proc pscanner_scan_procs*(ctx: var ProcScanner, list_procs: seq[uint]) =
  for pid in list_procs:
    pscanner_process_pid(ctx, pid)


proc pscanner_scan_system_procs*(ctx: var ProcScanner) =
  for i in countup(1, SCANNER_MAX_PROC_COUNT):
    pscanner_process_pid(ctx, uint(i))
