import cli / [cli_opts, print_utils]
import engine / engine_cores
import scanners / scanners


var options: ScanOptions

if cliopts_get_options(options):
  var
    f_count, f_infect, p_count, p_infect: uint
  scanners_create_scan_task(options, scanners_cl_scan_files, f_count, f_infect, p_count, p_infect)
  print_sumary(f_count, f_infect, p_count, p_infect)
