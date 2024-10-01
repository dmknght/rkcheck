

proc show_help_banner*(): bool =
  echo "\nEngine options:"
  echo " --use-clamdb                  Use ClamAV's default sigs (/var/lib/clamav/)"
  echo " --clam-debug                  Enable libclam debug mode"
  echo " --path-clamdb  <file or dir>  Set custom ClamAV's signatures"
  echo " --path-yaradb  <file or dir>  Set custom Yara's rules"
  echo "\nScan options:"
  echo " --scan-files  <file1 file2>  Scan files and dirs"
  echo " --scan-procs                 Scan all running processes"
  echo " --scan-procs  <pid1 pid2>    Scan processes by given PIDs"
  echo " --scan-fhook                 Scan function hooking by userland rootkit"
  return false
