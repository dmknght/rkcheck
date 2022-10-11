import .. / .. / libs / libclamav / nim_clam
import .. / .. / libs / libyara / nim_yara

type
  CoreEngine* = object
    ClamAV*: ptr cl_engine
    YaraEng*: ptr YR_RULES
    ClamScanOpts*: cl_scan_options
    LibClamDebug*: bool
    ClamDbPath*: string
    YaraDbPath*: string
  ProcInfo* = object
    pid*: uint
    pid_path*: string
    cmdline*: string
    binary_path*: string
  FileScanContext* = object of RootObj
    ScanEngine*: CoreEngine
    scan_object*: string
    scan_result*: cl_error_t
    virus_name*: cstring
    obj_scanned*: uint
    obj_infected*: uint
    # TOOD parent, child pid, more
  ProcScanContext* = object of FileScanContext
    proc_object*: ProcInfo
    # TODO there are parent processess, child processes has the same memory value. We try to ignore them during scan

const
  yr_scan_timeout*: cint = 1000000
