import posix
import cli / [cli_opts, print_utils]
import engine / engine_cores
import scanners / scanners
import os


if not dirExists("/sys/"):
  raise newException(OSError, "Sysfs is not mounted")

const
  kernel_modules = "/sys/kernel/tracing/available_filter_functions"
var
  options: ScanOptions
  f_infect: uint

options.cliopts_create_default(true)
options.list_files = @[kernel_modules]
# TODO scan /etc/ld.so.preload https://compilepeace.medium.com/memory-malware-part-0x2-writing-userland-rootkits-via-ld-preload-30121c8343d5
# https://www.sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/
if getuid() != 0:
  echo "Scan Kernel rootkit requires Root permission. Ignoring"
else:
  scanners_create_scan_rootkit_task(options, f_infect)
# TODO show sumary that has kernel modules and ld-preload modules
# print_sumary(f_count, f_infect, p_count, p_infect)