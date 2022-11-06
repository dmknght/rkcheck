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


proc print_process_infected*(virname, path: string, pid: uint) =
  if not isEmptyOrWhitespace(path):
    echo "[\e[91m!\e[0m] \e[105m", virname, "\e[0m pid: \e[95m", pid, "\e[0m ", path
  else:
    echo "[\e[91m!\e[0m] \e[105m", virname, "\e[0m pid: \e[95m", pid, "\e[0m"


proc print_loaded_signatures*(num_loaded: uint, is_yara: bool) =
  if is_yara:
    echo "Loaded ", num_loaded, " Yara rules"
  else:
    echo "Loaded ", num_loaded, " ClamAV signatures"
