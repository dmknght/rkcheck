import engine / rkengine
import libs / libclamav / nim_clam
import interfaces / server
import net


proc main() =
  engine.cl_db_path = "/var/lib/clamav/bytecode.cld"
  engine.yara_db_path = "/home/dmknght/ParrotProjects/rkcheck/database/signatures.ydb"
  engine.enable_clam_debug = false

  if rkcheck_start_engine(engine) == CL_SUCCESS:
    try:
      let svrStatus = createServer()
      if svrStatus == SUCCESS:
        var
          client: Socket
          address: string
        setControlCHook(interruptServer)
        while true:
          sockServer.acceptAddr(client, address)
          let client_request = client.recv(1024, -1)
          rkcheck_scan_dir(client_request) # TODO show completed
    except:
      discard
    finally:
      closeServer()

  rkcheck_stop_engine(engine)

main()
