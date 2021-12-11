import engine / rkengine
import engine / cores / eng_cores
import libs / libclamav / nim_clam


proc main() =
  var engine: CoreEngine
  engine.ClamDbPath = "/var/lib/clamav/bytecode.cld"
  engine.YaraDbPath = "/home/dmknght/ParrotProjects/rkcheck/database/signatures.ydb"
  engine.LibClamDebug = false

  if rkcheck_start_engine(engine) == CL_SUCCESS:
    try:
      discard
      # rkcheck_scan_dir("/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/")
      # rkcheck_scan_dir("/tmp/magics_yara/")
      # rkcheck_scan_procs()
    # try:
    #   let svrStatus = createServer()
    #   if svrStatus == SUCCESS:
    #     var
    #       client: Socket
    #       address: string
    #     setControlCHook(interruptServer)
    #     while true:
    #       sockServer.acceptAddr(client, address)
    #       # let client_request = client.recv(1024, -1)
    #       # echo client_request
    #       # rkcheck_scan_dir(client_request) # TODO show completed
    #       # discard client.send(addr(engine), sizeof(engine))
    #       client.send("banner")
    except:
      discard
    # finally:
    #   closeServer()

  rkcheck_stop_engine(engine)

main()
