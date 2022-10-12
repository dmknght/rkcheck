import libclamav
import libyara
import strutils


proc file_scanner_on_matched*(scan_result: var cl_error_t, virus_name: var cstring, rule_name_space, rule_identifier: string): cint =
  scan_result = CL_VIRUS
  virus_name = cstring($rule_name_space & ":" & replace($rule_identifier, "_", "."))
  return CALLBACK_ABORT


proc file_scanner_on_clean*(scan_result: var cl_error_t, virus_name: var cstring): cint =
  scan_result = CL_CLEAN
  virus_name = ""
  return CALLBACK_CONTINUE


proc proc_scanner_on_file_deleted*(virus_name: var cstring, binary_path: var string, scan_result: var cl_error_t): cint =
  virus_name = "Heur:DeletedProcess"
  scan_result = CL_VIRUS
  binary_path.removeSuffix(" (deleted)")
  return 0


proc proc_scanner_on_cmd_matched*(virus_name: var cstring, scan_result: var cl_error_t): cint =
  virus_name = cstring("Heur:MalCmdExe." & $virus_name)
  scan_result = CL_VIRUS
  return 0


proc file_scanner_on_malware_found*(virname, vir_detected: cstring, scan_object: string, infected: var uint) =
  #[
    Print virus found message with file path
    TODO move this to cli and use sort of clamav debug
  ]#
  let
    # Show virname for heur detection
    virus_name = if vir_detected != "": vir_detected else: virname

  infected += 1
  echo virus_name, " ", scan_object


# proc fscanner_on_process_matched*(virus_name, binary_path: string, pid: uint) =
#   if not isEmptyOrWhitespace(binary_path):
#     echo virus_name, " ", binary_path, " (pid: ", pid, ")"
#   else:
#     echo virus_name, " process: ", pid
