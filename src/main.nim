import engine / rkengine
import libs / libclamav / nim_clam
import bitops


proc main() =
  var
    virname: cstring
    scanned: culong = 0
    options: cl_scan_options
  
  engine.cl_db_path = "/var/lib/clamav/bytecode.cld"
  engine.yara_db_path = "/home/dmknght/ParrotProjects/rkcheck/database/signatures.ydb"
  engine.enable_clam_debug = false
  options.parse = bitnot(bitor(options.parse, 0))

  if start_engine(engine) == CL_SUCCESS:
    discard cl_scanfile("/tmp/hello1.zip", addr(virname), addr(scanned), engine.CL_Eng, addr(options))
    # discard cl_scan_file("/tmp/mal.exe", addr(virname), addr(scanned), engine.CL_Eng, addr(options))

  stop_engine(engine)

main()