

proc show_help_banner*(): bool =
  echo "\nEngine options:"
  echo " --use-clamdb                  Use default ClamAV's signatures at /var/lib/clamav/"
  echo " --clam-debug                  Enable libclam debug mode"
  echo " --path-clamdb  <file or dir>  Set custom ClamAV's signatures"
  echo " --path-yaradb  <file>         Set custom Yara's rules"
  echo "\nScan options:"
  echo "  --check-hidden-proc          Do procfs walkDir to check if processes are hidden"
  echo "  --all-processes              Scan all running proccesses"
  echo "  --list-dirs   <dir1 dir2>    Scan directories"
  echo "  --list-files  <file1 file2>  Scan files"
  echo "  --list-procs  <pid1 pid2>    Scan processes. Skip if --all-processes is used"
  return false
