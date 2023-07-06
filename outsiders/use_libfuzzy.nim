# With the help of
# https://github.com/srozb/nim-libfuzzy/blob/master/src/libfuzzy/ssdeep.nim GPL-2

import os
{.pragma: impFuzzy, header: "fuzzy.h".} # libfuzzy-dev must be installed
{.passL: "-lfuzzy".}

const
  SPAMSUM_LENGTH* = 64
  FUZZY_MAX_RESULT* = (2 * SPAMSUM_LENGTH + 20)
  FUZZY_FLAG_ELIMSEQ* = 0x1
  FUZZY_FLAG_NOTRUNC* = 0x2

proc fuzzy_hash_buf*(buf: ptr uint8, buf_len: uint32, res: cstring): cint {.importc, cdecl.}
proc fuzzy_hash_file*(hFile: File, res: cstring): cint {.importc, cdecl.}
proc fuzzy_hash_filename*(filename: cstring, res: cstring): cint {.importc, cdecl.}
proc fuzzy_hash_stream*(hFile: File, res: cstring): cint {.importc, cdecl.}
proc fuzzy_compare*(sig1: cstring, sig2: cstring): cint {.importc, cdecl.}


proc main() =
  let
    # testHash = "98304:niKpipomRO262tcubr7zue3EgX5fJo4gRV7CBw5M4b9:nx2hHRo4dBu"
    # datasetDir = "/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/"
    datasetDir = "/home/dmknght/Desktop/MalwareLab/msf/"

  var
    fileHash = newString(FUZZY_MAX_RESULT)
    testHash = newString(FUZZY_MAX_RESULT)


  if fuzzy_hash_filename(cstring("/home/dmknght/Desktop/MalwareLab/msf/meter1"), cstring(testHash)) != 0:
    echo "Failed to calculate hash to test"
    return

  for kind, path in walkDir(datasetDir):
    if kind == pcFile:
      if fuzzy_hash_filename(cstring(path), cstring(fileHash)) == 0:
        let score = fuzzy_compare(cstring(testHash), cstring(fileHash))
        if score >= 75:
          echo "Score: ", score, " ", path

main()
