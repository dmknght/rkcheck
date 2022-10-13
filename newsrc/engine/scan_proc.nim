import libyara
import engine_cores
import engine_utils
import .. / cli / progress_bar
import strutils


proc pscanner_on_process_match(ctx: ptr ProcScanner, rule: ptr YR_RULE): cint =
  #[
    Print virus found message with file path
  ]#
  progress_bar_flush()
  proc_scanner_on_scan_matched($rule.ns.name, $rule.identifier, ctx.proc_binary, ctx.proc_id)
  progress_bar_flush()
  return CALLBACK_ABORT


proc pscanner_on_proc_deleted_binary(virname: var cstring, binary_path: var string, pid: uint): cint =
  proc_scanner_on_binary_deleted(virname, binary_path)
  proc_scanner_on_scan_heur($virname, binary_path, pid)
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
    return pscanner_on_proc_deleted_binary(ctx.scan_virname, ctx.proc_binary, ctx.proc_id)
  # TODO scan cmdline
  return yr_rules_scan_proc(ctx.engine, cint(ctx.proc_id), SCAN_FLAGS_PROCESS_MEMORY, pscanner_cb_proc_result, addr(ctx), YR_SCAN_TIMEOUT)

  # Scan cmdline file
  # NOTICE: all spaces in here are replaced by "\x00". Need to notice the rules
  # NOTICE: yara scan file failed to scan cmdline for some reason
  # discard yr_rules_scan_file(ctx.ScanEngine.YaraEng, cstring(ctx.proc_object.cmdline), SCAN_FLAGS_FAST_MODE, cb_yr_process_scan_result, addr(ctx), yr_scan_timeout)
  # if ctx.scan_result == CL_VIRUS:
  #   return fscanner_on_process_cmd_matched(ctx.virus_name, ctx.scan_result)

  # Maybe scan binary to execute?
