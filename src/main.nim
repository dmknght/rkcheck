import engine / rkengine
import libs / libclamav / nim_clam
# import libs / libyara / nim_yara


proc main() =
  var
    virname: cstring
    scanned: culong = 0
    options: cl_scan_options
  
  engine.cl_db_path = "/var/lib/clamav/bytecode.cld"
  engine.yara_db_path = "/home/dmknght/ParrotProjects/rkcheck/database/signatures.ydb"
  engine.enable_clam_debug = false

  if start_engine(engine) == CL_SUCCESS:
    discard cl_scanfile("/tmp/hello1.zip", addr(virname), addr(scanned), engine.CL_Eng, addr(options))

  stop_engine(engine)
  # echo "Scanned ", scanned, " files"

main()