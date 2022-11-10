import libyara
import engine_cores
import engine_utils
import .. / cli / progress_bar
import strutils
import os


proc pscanner_on_process_match(ctx: ptr ProcScanner, rule: ptr YR_RULE): cint =
  #[
    Print virus found message with file path
  ]#
  proc_scanner_on_scan_matched($rule.ns.name, $rule.identifier, ctx.proc_binary, ctx.proc_id)
  ctx.sumary_infected += 1

  return CALLBACK_ABORT


proc pscanner_on_proc_deleted_binary(virname: var cstring, binary_path: var string, pid: uint, infected: var uint): cint =
  #[
    Detect fileless malware attack
    https://www.sandflysecurity.com/blog/detecting-linux-memfd-create-fileless-malware-with-command-line-forensics/
    https://www.sandflysecurity.com/blog/basic-linux-malware-process-forensics-for-incident-responders/
  ]#
  if binary_path.startsWith("/memfd"):
    proc_scanner_on_memfd_deleted(virname, binary_path)
  else:
    proc_scanner_on_binary_deleted(virname, binary_path)
  proc_scanner_on_scan_heur($virname, binary_path, pid)
  infected += 1
  return CALLBACK_ABORT


proc pscanner_cb_proc_result(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  let
    ctx = cast[ptr ProcScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    return pscanner_on_process_match(ctx, rule)
  else:
    return CALLBACK_CONTINUE


proc pscanner_cb_scan_proc*(ctx: var ProcScanner): cint =
  if ctx.proc_binary.endsWith(" (deleted)"):
    return pscanner_on_proc_deleted_binary(ctx.scan_virname, ctx.proc_binary, ctx.proc_id, ctx.sumary_infected)
  # TODO scan cmdline
  return yr_rules_scan_proc(ctx.engine, cint(ctx.proc_id), SCAN_FLAGS_PROCESS_MEMORY, pscanner_cb_proc_result, addr(ctx), YR_SCAN_TIMEOUT)

  # Scan cmdline file
  # NOTICE: all spaces in here are replaced by "\x00". Need to notice the rules
  # NOTICE: yara scan file failed to scan cmdline for some reason
  # discard yr_rules_scan_file(ctx.ScanEngine.YaraEng, cstring(ctx.proc_object.cmdline), SCAN_FLAGS_FAST_MODE, cb_yr_process_scan_result, addr(ctx), yr_scan_timeout)
  # if ctx.scan_result == CL_VIRUS:
  #   return fscanner_on_process_cmd_matched(ctx.virus_name, ctx.scan_result)

  # Maybe scan binary to execute?


proc pscanner_process_pid*(ctx: var ProcScanner, pid: uint) =
  # TODO map cmdline and scan parseCmdLine(readFile(ctx.proc_object.cmdline).replace("\x00", " "))[0]
  # TODO maybe do findExe for proc_binary
  # TODO handle parent pid, child pid, ... to do ignore scan
  try:
    ctx.proc_binary = expandSymlink(ctx.proc_path & "exe")
    progress_bar_scan_proc(ctx.proc_id, ctx.proc_binary)
    ctx.sumary_scanned += 1
    discard pscanner_cb_scan_proc(ctx)
  except:
    # Do not scan if has error. For example: Permission Denied when read /proc/1/exe
    discard


proc pscanner_scan_procs*(ctx: var ProcScanner, list_procs: seq[uint]) =
  for pid in list_procs:
    let
      procfs_path = "/proc/" & $pid & "/"
    if dirExists(procfs_path):
      ctx.proc_id = pid
      ctx.proc_path = procfs_path
      pscanner_process_pid(ctx, pid)


proc pscanner_scan_system_procs*(ctx: var ProcScanner) =
  for kind, path in walkDir("/proc/"):
    if kind == pcDir:
      try:
        let
          pid = parseUInt(splitPath(path).tail)

        ctx.proc_path = path & "/"
        ctx.proc_id = pid
        pscanner_process_pid(ctx, pid)
      except ValueError:
        discard
