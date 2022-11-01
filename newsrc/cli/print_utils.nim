import strutils


proc print_file_infected*(virname, scan_obj: string) =
  echo "[\e[91m!\e[0m] \e[101m", virname, "\e[0m ", scan_obj


proc print_process_infected*(virname, path: string, pid: uint) =
  if not isEmptyOrWhitespace(path):
    echo "[!] \e[105m", virname, "\e[0m \e[106mpid: ", pid, "\e[0m ", path
  else:
    echo "[!] \e[105m", virname, "\e[0m \e[106mpid: ", pid, "\e[0m"
