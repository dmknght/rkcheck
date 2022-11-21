import strutils
import progress_bar


proc print_file_infected*(virname, scan_obj: string) =
  #[
    If the Yara is post scan (scan after ClamAV)
    and ClamAV marked file as infected, the progress bar
    is messed up. Call flush again to clear that
  ]#
  progress_bar_flush()
  echo "[\e[91m!\e[0m] \e[101m", virname, "\e[0m ", scan_obj


proc print_process_infected*(pid: uint, virname, run_path, map_path, name: string) =
  progress_bar_flush()
  echo "[\e[91m!\e[0m] \e[105m", virname, "\e[0m Pid: \e[95m", pid, "\e[0m "
  echo " Name: ", name

  if not isEmptyOrWhitespace(map_path):
    echo " Exec: ", run_path
  else:
    echo " Exec: \e[91mUnknown\e[0m"

  if not isEmptyOrWhitespace(map_path):
    echo " Mapped: " & map_path


proc print_process_hidden*(pid: uint, name: string) =
  progress_bar_flush()
  echo "Heur:ProcCloak.ProcfsIv\e[0m Pid: \e[95m", pid, "\e[0m Name: ", name


proc print_loaded_signatures*(num_loaded: uint, is_yara: bool) =
  if is_yara:
    echo "Loaded ", num_loaded, " Yara rules"
  else:
    echo "Loaded ", num_loaded, " ClamAV signatures"


proc print_yara_version*(version: string) =
  echo "Yara Engine: ", version


proc print_found_rootkit_modules*(namespace, id: string) =
  echo "\e[91mKernLoaded@", namespace, ":", id.replace("_", "."), "\e[0m"


proc print_sumary*(scanned_files, infected_files, scanned_procs, infected_procs: uint) =
  progress_bar_flush()
  echo "\n===SCAN COMPLETED==="
  if scanned_files > 0:
    echo "Scanned objects: ", scanned_files
    echo "Infected objects: ", infected_files
  if scanned_procs > 0:
    echo "Scanned processes: ", scanned_procs
    echo "Infected processes: ", infected_procs
