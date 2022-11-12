import libyara
import engine_cores
import .. / cli / print_utils


proc fscanner_cb_yara_scan_result*(context: ptr YR_SCAN_CONTEXT, message: cint, message_data: pointer, user_data: pointer): cint {.cdecl.} =
  #[
    Handle scan result from Yara engine
  ]#

  var
    ctx = cast[ptr KernModuScanner](user_data)
    rule = cast[ptr YR_RULE](message_data)

  # If target matches a rule
  if message == CALLBACK_MSG_RULE_MATCHING:
    print_found_rootkit_modules($rule.ns.name, $rule.identifier)
    ctx.infected += 1
  return CALLBACK_CONTINUE


proc kscanner_scan_start_scan*(ctx: var KernModuScanner) =
  let data = readFile("/sys/kernel/tracing/available_filter_functions")
  discard yr_rules_scan_mem(ctx.engine, cast[ptr uint8](data[0].unsafeAddr), uint(len(data)), SCAN_FLAGS_FAST_MODE, fscanner_cb_yara_scan_result, addr(ctx), YR_SCAN_TIMEOUT)
