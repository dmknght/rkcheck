import engine / rkengine
import libs / libclamav / nim_clam


proc main() =
  engine.cl_db_path = "/var/lib/clamav/bytecode.cld"
  engine.yara_db_path = "/home/dmknght/ParrotProjects/rkcheck/database/signatures.ydb"
  engine.enable_clam_debug = false

  if rkcheck_start_engine(engine) == CL_SUCCESS:
    rkcheck_scan_file("/tmp/hello.zip")
  rkcheck_stop_engine(engine)

main()
