import posix
import cli / [cli_opts, print_utils]
import engine / engine_cores
import scanners / scanners
import os


if getuid() != 0:
  echo "Requires root permission"
elif not dirExists("/sys/"):
  raise newException(OSError, "Sysfs is not mounted")
else:
  const
    kernel_modules = "/sys/kernel/tracing/available_filter_functions"
  var
    options: ScanOptions
    f_infect: uint

  options.cliopts_create_default(true)
  options.list_files = @[kernel_modules]
  # TODO scan /etc/ld.so.preload
  # https://www.sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/
  create_scan_rootkit_task(options, f_infect)
  # TODO show sumary that has kernel modules and ld-preload modules
  # print_sumary(f_count, f_infect, p_count, p_infect)