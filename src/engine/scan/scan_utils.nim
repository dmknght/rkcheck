import .. / .. / libs / libclamav / nim_clam
import .. / .. / libs / libyara / nim_yara
# import .. / cores / [eng_cores, eng_cli_progress]
import strutils


proc fscanner_on_rule_matched*(scan_result: var cl_error_t, virus_name: var cstring, rule_name_space, rule_identifier: string): cint =
  scan_result = CL_VIRUS
  virus_name = cstring($rule_name_space & ":" & replace($rule_identifier, "_", "."))
  return CALLBACK_ABORT


proc fscanner_on_rule_not_matched*(scan_result: var cl_error_t, virus_name: var cstring): cint =
  scan_result = CL_CLEAN
  virus_name = ""
  return CALLBACK_CONTINUE


proc fscanner_on_process_matched*(virus_name, binary_path: string, pid: uint) =
  if not isEmptyOrWhitespace(binary_path):
    echo virus_name, " ", binary_path, " (pid: ", pid, ")"
  else:
    echo virus_name, " process: ", pid


proc fscanner_on_process_deleted*(virus_name: var cstring, binary_path: var string, scan_result: var cl_error_t): cint =
  virus_name = "Heur:DeletedProcess"
  scan_result = CL_VIRUS
  binary_path.removeSuffix(" (deleted)")
  return 0


proc fscanner_on_process_cmd_matched*(virus_name: var cstring, scan_result: var cl_error_t): cint =
  virus_name = cstring("Heur:MalCmdExe." & $virus_name)
  scan_result = CL_VIRUS
  return 0
