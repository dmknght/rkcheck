

proc show_help_banner*(): bool =
  echo "\nEngine options:"
  echo " --use-clamdb                  Use ClamAV's default sigs (/var/lib/clamav/)"
  echo " --clam-debug                  Enable libclam debug mode"
  echo " --path-clamdb  <file or dir>  Set custom ClamAV's signatures"
  echo " --path-yaradb  <file>         Set custom Yara's rules"
  echo "\nScan options:"
  echo " --scan-files  <file1 file2>  Scan files and dirs"
  echo " --scan-procs  <pid1 pid2>    Scan processes. Skip if --all-procs is used"
  echo " --scan-mem                   Scan all running proccesses"
  # echo " --match-all                  Match all rules (process scan only)"
  return false
