import libclamav
import libyara
import strutils
import .. / cli / print_utils
import streams


proc file_scanner_on_matched*(scan_result: var cl_error_t, virus_name: var cstring, rule_name_space, rule_identifier: string): cint =
  scan_result = CL_VIRUS
  virus_name = cstring($rule_name_space & ":" & replace($rule_identifier, "_", "."))
  return CALLBACK_ABORT


proc file_scanner_on_clean*(scan_result: var cl_error_t, virus_name: var cstring): cint =
  scan_result = CL_CLEAN
  virus_name = ""
  return CALLBACK_CONTINUE


proc file_scanner_on_malware_found*(virname, vir_detected: cstring, scan_object: string, infected: var uint) =
  #[
    Print virus found message with file path
  ]#
  let
    # Show virname for heur detection
    virus_name = if isEmptyOrWhitespace($vir_detected): virname else: vir_detected

  infected += 1
  print_file_infected($virus_name, $scan_object)


proc proc_scanner_on_binary_deleted*(virus_name: var cstring, binary_path: var string) =
  virus_name = "Heur:Fileless.DeletedBin"
  binary_path.removeSuffix(" (deleted)")


proc proc_scanner_on_memfd_deleted*(virus_name: var cstring, binary_path: var string) =
  virus_name = "Heur:Fileless.DeletedMemfd"
  binary_path = ""


proc proc_scanner_on_cmd_matched*(virus_name: var cstring, scan_result: var cl_error_t): cint =
  virus_name = cstring("Heur:MalCmdExe." & $virus_name)
  scan_result = CL_VIRUS
  return 0


proc proc_scanner_on_scan_matched*(rule_ns, rule_id, binary_path: string, pid: uint) =
  let
    virus_name = cstring(rule_ns & ":" & replace(rule_id, "_", "."))

  print_process_infected($virus_name, binary_path, pid)


proc proc_scanner_on_scan_heur*(virus_name, binary_path: string, pid: uint) =
  print_process_infected(virus_name, binary_path, pid)


proc yr_rule_file_is_compiled*(path: string): bool =
  let f = newFileStream(path)
  if f.readStr(4) == "YARA":
    result = true
  else:
    result = false
  f.close()
