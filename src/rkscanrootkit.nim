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
    # FIXME: LibClamAV debug: cl_scandesc_callback: File too small (0 bytes), ignoring
    kernel_modules = "/sys/kernel/tracing/available_filter_functions"
  var
    options: ScanOptions
    f_infect: uint

  options.cliopts_create_default(true)
  options.list_files = @[kernel_modules]
  # TODO match all rules
  create_scan_rootkit_task(options, f_infect)
  # TODO show sumary
  # print_sumary(f_count, f_infect, p_count, p_infect)