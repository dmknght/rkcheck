import libyara
import engine_cores
import engine_utils
import .. / cli / [progress_bar, print_utils]
import strutils
import os


proc pscanner_on_process_match(ctx: ptr ProcScanner, rule: ptr YR_RULE): cint =
  #[
    Print virus found message with file path
  ]#
  proc_scanner_on_scan_matched($rule.ns.name, $rule.identifier, ctx.proc_binary_path, ctx.proc_id)
  ctx.sumary_infected += 1

  return CALLBACK_ABORT


proc pscanner_on_proc_deleted_binary(virname: var cstring, binary_path: var string, pid: uint, infected: var uint): cint =
  #[
    Detect fileless malware attack
    https://www.sandflysecurity.com/blog/detecting-linux-memfd-create-fileless-malware-with-command-line-forensics/
    https://www.sandflysecurity.com/blog/basic-linux-malware-process-forensics-for-incident-responders/
  ]#
  if binary_path.startsWith("/memfd"):
    proc_scanner_on_memfd_deleted(virname, binary_path, pid)
  else:
    proc_scanner_on_binary_deleted(virname, binary_path, pid)

  infected += 1
  return CALLBACK_ABORT


proc pscanner_cb_scan_proc_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    rule.ns.name = cstring("SusCmdline")
    return pscanner_on_process_match(ctx, rule)
  else:
    ctx.scan_virname = ""
    return CALLBACK_CONTINUE


proc pscanner_cb_scan_cmdline_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    return pscanner_on_process_match(ctx, rule)
  else:
    ctx.scan_virname = ""
    return CALLBACK_CONTINUE


proc pscanner_cb_scan_proc*(ctx: var ProcScanner): cint =
  if ctx.proc_binary_path.endsWith(" (deleted)"):
    return pscanner_on_proc_deleted_binary(ctx.scan_virname, ctx.proc_binary_path, ctx.proc_id, ctx.sumary_infected)
  discard yr_rules_scan_proc(ctx.engine, cint(ctx.proc_id), SCAN_FLAGS_PROCESS_MEMORY, pscanner_cb_scan_proc_result, addr(ctx), YR_SCAN_TIMEOUT)

  # Scan cmdline so we can detect reverse shell
  # if ctx.scan_virname == "" and ctx.proc_cmdline != "":
  #   discard yr_rules_scan_mem(ctx.engine, cast[ptr uint8](ctx.proc_cmdline[0].unsafeAddr), uint(len(ctx.proc_cmdline)), SCAN_FLAGS_FAST_MODE, pscanner_cb_scan_cmdline_result, addr(ctx), YR_SCAN_TIMEOUT)

  # TODO: scan process's stacks and execfile. Maybe need different ruleset?
  # TODO: implement entropy scan https://www.sandflysecurity.com/blog/sandfly-linux-file-entropy-scanner-updated/


proc pscanner_is_hidden_proc(ctx: ProcScanner) =
  if ctx.proc_id == ctx.proc_tgid and ctx.proc_ppid > 0:
    for kind, path in walkDir("/proc/"):
      if kind == pcDir and path & "/" == ctx.proc_pathfs:
        return
    print_process_hidden(ctx.proc_id, ctx.proc_name)


proc pscanner_map_proc_info(ctx: var ProcScanner) =
  try:
    ctx.proc_binary_path = expandSymlink(ctx.proc_pathfs & "exe")
  except:
    # Do not crash if map has error. For example: Permission Denied when read /proc/1/exe
    ctx.proc_binary_path = ""

  try:
    ctx.proc_cmdline = readFile(ctx.proc_pathfs & "cmdline").replace("\x00", " ")
  except:
    ctx.proc_cmdline = ""

  for line in lines(ctx.proc_pathfs & "status"):
    if line.startsWith("Name:"):
      ctx.proc_name = line.split()[^1]
    elif line.startsWith("Tgid"):
      ctx.proc_tgid = parseUInt(line.split()[^1])
    elif line.startsWith("PPid:"):
      ctx.proc_ppid = parseUInt(line.split()[^1])
      break


proc pscanner_process_pid(ctx: var ProcScanner, pid: uint) =
  # TODO handle parent pid, child pid, ... to do ignore scan
  let
    procfs_path = "/proc/" & $pid & "/"

  if not dirExists(procfs_path):
    return

  ctx.proc_pathfs = procfs_path
  ctx.proc_id = pid
  pscanner_map_proc_info(ctx)

  if ctx.do_check_hidden_procs:
    # Brute force procfs. Slow. Requires a different flag
    pscanner_is_hidden_proc(ctx)

  progress_bar_scan_proc(ctx.proc_id, ctx.proc_binary_path)
  discard pscanner_cb_scan_proc(ctx)
  ctx.sumary_scanned += 1


proc pscanner_scan_procs*(ctx: var ProcScanner, list_procs: seq[uint]) =
  for pid in list_procs:
    pscanner_process_pid(ctx, pid)


proc pscanner_scan_system_procs*(ctx: var ProcScanner) =
  for i in countup(1, SCANNER_MAX_PROC_COUNT):
    pscanner_process_pid(ctx, uint(i))
