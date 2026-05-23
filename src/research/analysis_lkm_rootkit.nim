import os
import strutils
import posix


proc fileno(f: File): cint {.importc, header: "<stdio.h>".}


iterator read_single_lines(log_path: string): string =
  let f = open(log_path, fmRead)
  defer: f.close()

  # "Convert" File object to read in O_NONBLOCK mode, which allows reading file without hanging
  # This is the suggestion of ClaudeAI.
  let fd: cint = fileno(f)
  let flags = fcntl(fd, F_GETFL, 0.cint)
  discard fcntl(fd, F_SETFL, flags or O_NONBLOCK)

  var
    ret_str: string
    # Buf must be newString(1), otherwise it causes crash because of readBuffer copies
    # Data to pointer directly.
    buf = newString(1)

  while true:
    try:

      if f.readBuffer(addr(buf[0]), 1) <= 0:
        # Hopefully this will break loop because the program could hang from reading channel
        break

      if buf == "\n":
        yield ret_str
        ret_str = ""
      else:
        ret_str &= buf

    except IOError:
      # After reading everything, program raises IOError. We catch here to suppress error
      break


proc analysis_syslog() =
  # Read syslog to find suspicious information about kernel module.
  # Instead of static log file, this tool tries to read from kmsg "channel"
  # which should work globally with other distro.
  let log_path = "/dev/kmsg"

  if access(log_path, R_OK) != 0:
    echo "[x] Error can't read from file ", log_path

  else:
    for line in read_single_lines(log_path):
      if "module verification failed" in line: # There are more keywords but let make it simple first
        let suspicious_module = line.split(":")[0].split(";")[1]
        echo "Found suspicious module ", suspicious_module # I should manage list of modules instead
        # Counter point: what if the kernel sees the module as a valid one? This logic won't work


analysis_syslog()
