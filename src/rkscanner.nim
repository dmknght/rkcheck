import cli / cli_opts
import engine / engine_cores
import scanners / scanners


var options: ScanOptions

if cliopts_get_options(options):
  create_scan_task(options)
