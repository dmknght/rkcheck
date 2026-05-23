import strutils
import posix


var
  kernel_name: Utsname

# If return != 0 -> # Error! Maybe handle this by reading /proc/sys/kernel/osrelease?
discard uname(kernel_name)
let kernel_path = "/lib/modules/" & $cast[cstring](addr(kernel_name.release[0]))


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


proc is_in_kernel_symbols(module_name: string): bool =
  # Cmp with many symbols and aliases in kernel
  # Possibly a little bottleneck because of how the function works.
  # However, if it works, it works. This is the only method so far
  # False postive (?) dm_mirror

  # Check /lib/modules/$(uname -r)/modules.order
  for line in lines(kernel_path & "/modules.order"):
    if line.endsWith("/" & module_name & ".ko"):
      return true

  # Check /lib/modules/$(uname -r)/modules.alias
  for line in lines(kernel_path & "/modules.alias"):
    if line.endsWith(" " & module_name):
      return true

  # Check /lib/modules/$(uname -r)/modules.symbols
  for line in lines(kernel_path & "/modules.symbols"):
    if line.endsWith(":" & module_name) or line.endsWith(" " & module_name):
      return true

  # Check in /proc/modules
  for line in lines("/proc/modules"):
    if line.startsWith(module_name & " "):
      return true

  return false


proc find_module_loc(sus_modules: seq[string]) =
  #[
    Find in /lib/modules/$(uname -r)/modules.dep
    FIXME: looks like this one contains relative path only
  ]#
  echo "[*] Finding locations of suspicious modules"

  for line in lines(kernel_path & "/modules.dep"):
    for sus_name in sus_modules:
      if line.contains("/" & sus_name & ".ko"):
        echo line


proc read_kernel_tracing_funcs(sus_modules: var seq[string]) =
  #[
    Read and get functions from /sys/kernel/tracing/available_filter_functions
    During my research, threat actors usually "foget" about this one
    It could be highly cost to hide value from this data so it might be a
    trustable source to analysis later
    Todo: count module and count function?
  ]#
  echo "[*] Finding suspicious modules from kernel tracing"

  let path = "/sys/kernel/tracing/available_filter_functions"

  if access(cstring(path), R_OK) != 0:
    echo "[x] Failed to read from kernel FS"

  var
    fast_skip = ""
    fast_show = ""

  for line in lines(path):
    if not line.endsWith "]":
      # Could be kernel's function? Like the line has no module.
      # Do skip instead
      continue

    if fast_skip != "" and line.endsWith(fast_skip & "]"):
      continue
    elif fast_show != "" and line.endsWith(fast_show & "]"):
      echo line
    else:
      # Clean up fast skip. But is it correct if i put it here?
      fast_skip = ""
      fast_show = ""
      # Analysis module in sus
      var module_name = line.split(" ")[1]
      module_name.removePrefix('[')
      module_name.removeSuffix(']')

      if not is_in_kernel_symbols(module_name):
        fast_show = module_name
        echo line
        if module_name notin sus_modules:
          sus_modules.add(module_name)
      else:
        fast_skip = module_name

proc analysis_syslog(): seq[string] =
  # Read syslog to find suspicious information about kernel module.
  # Instead of static log file, this tool tries to read from kmsg "channel"
  # which should work globally with other distro.
  # Template code. Should be changed later with more case to cover
  echo "[*] Finding suspicious modules from syslog"

  let log_path = "/dev/kmsg"

  if access(cstring(log_path), R_OK) != 0:
    echo "[x] Error can't read from file ", log_path

  else:
    for line in read_single_lines(log_path):
      if "module verification failed" in line: # There are more keywords but let make it simple first
        let suspicious_module = line.split(":")[0].split(";")[1]
        result.add(suspicious_module)
        echo "Found suspicious module ", suspicious_module # I should manage list of modules instead
        # Counter point: what if the kernel sees the module as a valid one? This logic won't work


var sus_modules = analysis_syslog()
read_kernel_tracing_funcs(sus_modules)
find_module_loc(sus_modules)
