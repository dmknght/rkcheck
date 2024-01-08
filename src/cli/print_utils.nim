import strutils
import progress_bar

{.emit:
  """
  #include <yara.h>

  char* yr_get_version() {
      return YR_VERSION;
  }
  """
  .}


proc yr_get_version(): cstring {.importc.}


proc print_file_infected*(virname, scan_obj: string) =
  #[
    If the Yara is post scan (scan after ClamAV)
    and ClamAV marked file as infected, the progress bar
    is messed up. Call flush again to clear that
  ]#
  progress_bar_flush()
  echo "\e[91m", virname, "\e[0m ", scan_obj


proc print_process_infected*(pid: uint, virname, scan_object, exec_path, name: string) =
  progress_bar_flush()
  echo "\e[91m", virname, "\e[0m Pid: \e[95m", pid, "\e[0m "
  echo " Name: ", name

  if not isEmptyOrWhitespace(exec_path):
    echo " Exec: \e[40m", exec_path, "\e[0m"
  else:
    echo " Exec: \e[93mUnknown\e[0m"

  echo " Infected: \e[91m", scan_object, "\e[0m"


proc print_loaded_signatures*(num_loaded: uint, is_yara: bool) =
  if is_yara:
    echo "Loaded ", num_loaded, " Yara rules"
  else:
    echo "Loaded ", num_loaded, " ClamAV signatures"


proc print_yara_version*() =
  echo "Yara Engine: ", $yr_get_version()


# proc print_found_rootkit_modules*(namespace, id: string) =
#   echo "\e[91mKernLoaded@", namespace, ":", id.replace("_", "."), "\e[0m"


proc print_sumary*(scanned_files, infected_files, scanned_procs, infected_procs: uint) =
  progress_bar_flush()
  echo "\n===SCAN COMPLETED==="
  if scanned_files > 0:
    echo "Scanned objects: ", scanned_files
    echo "Infected objects: ", infected_files
  if scanned_procs > 0:
    echo "Scanned processes: ", scanned_procs
    echo "Infected processes: ", infected_procs
