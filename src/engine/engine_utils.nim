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


proc proc_scanner_on_binary_deleted*(pid: uint, binary_path, proc_name: var string) =
  if binary_path.startsWith("/memfd"):
    print_process_infected(pid, "Heur:Fileless.DeletedMemfd", binary_path.split()[0], "", proc_name)
  else:
    binary_path.removeSuffix(" (deleted)")
    print_process_infected(pid, "Heur:Fileless.DeletedBin", binary_path, "", proc_name)


proc proc_scanner_on_proccess_masquerading*(pid: uint, binary_path, proc_name: string) =
  let virus_name = "Heur:ProcCloak.Masquerading"
  print_process_infected(pid, virus_name, binary_path, "", proc_name)


proc proc_scanner_on_cmd_matched*(virus_name: var cstring, scan_result: var cl_error_t): cint =
  virus_name = cstring("SusCmd:" & $virus_name)
  scan_result = CL_VIRUS
  return 0


proc yr_rule_file_is_compiled*(path: string): bool =
  let f = newFileStream(path)
  if f.readStr(4) == "YARA":
    result = true
  else:
    result = false
  f.close()
