import engine / cores / eng_cores
import libs / libclamav / nim_clam
import engine / apis


proc main() =
  var engine: CoreEngine
  # engine.ClamDbPath = "/var/lib/clamav/"
  # engine.ClamDbPath = "database/"
  engine.YaraDbPath = "/home/dmknght/ParrotProjects/rkcheck/database/signatures.ydb"
  engine.LibClamDebug = false

  if rkcheck_start_engine(engine) == CL_SUCCESS:
    try:
      # rkcheck_scan_procs(engine)
      # rkcheck_scan_files_and_dirs(engine, dir_list=["/usr/bin/"])
      # rkcheck_scan_procs(engine, @[1179, 793435])
      rkcheck_scan_all_procs(engine)
      # rkcheck_scan_file(engine, "/mnt/maintain/VirusCollection/vxheavens-2010-05-18/viruses-2010-05-18/Rootkit.Linux.Agent.30.Chfn")
      # rkcheck_scan_proc(engine, 3798464)
      # rkcheck_scan_dir(engine, "/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/")
      # rkcheck_scan_dir(engine, "/home/dmknght/Desktop/MalwareLab/Linux-Malware-Samples")
      # rkcheck_scan_dir(engine, "/mnt/maintain/VirusCollection/vxheavens-2010-05-18/viruses-2010-05-18/")
      # rkcheck_scan_dir(engine, "/opt/")
      # rkcheck_scan_all_procs(engine)
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
