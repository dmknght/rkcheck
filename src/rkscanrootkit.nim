import posix
import cli / [cli_opts, print_utils]
import engine / engine_cores
import scanners / scanners



if getuid() != 0:
  echo "Requires root permission"
else:
  const
    kernel_modules = "/sys/kernel/tracing/available_filter_functions"
  var
    options: ScanOptions
    f_count, f_infect, p_count, p_infect: uint

  options.cliopts_create_default(true)
  options.list_files = @[kernel_modules]
  # TODO match all rules
  create_scan_task(options, f_count, f_infect, p_count, p_infect)
  # TODO show sumary
  # print_sumary(f_count, f_infect, p_count, p_infect)