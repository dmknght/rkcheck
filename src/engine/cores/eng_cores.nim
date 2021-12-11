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
  FileScanContext* = object
    scan_object*: string
    scan_result*: cl_error_t
    virus_name*: cstring
  ProcInfo* = object
    pid*: cint
    pid_path*: string
    cmd_line*: string
    # TOOD parent, child pid, more
  ProcScanContext* = object
    scan_object*: ProcInfo
    scan_result*: cl_error_t # TODO think about this
    virus_name*: string

const
  yr_scan_flags*: cint = SCAN_FLAGS_FAST_MODE
  yr_scan_timeout*: cint = 1000000
