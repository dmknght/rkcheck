import libyara / nimyara
import os
import segfaults

type
  CALLBACK_ARGS = object
    file_path*: string
    current_count*: int


proc callback_scan(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    let rule = cast[ptr YR_RULE](message_data)
    cast[ptr CALLBACK_ARGS](user_data).current_count += 1
    echo "Detected:\n  ", rule.identifier, "\n  ", cast[ptr CALLBACK_ARGS](user_data).file_path
  return CALLBACK_CONTINUE



proc scanFile(scanner: ptr YR_SCANNER, compiler: ptr YR_COMPILER, fileName: string, user_data: ptr CALLBACK_ARGS, file_count, dir_count, err_count: var int) =
  if not fileExists(fileName):
    return
  else:
    user_data.file_path = fileName
    file_count += 1
    discard yr_compiler_define_string_variable(compiler, "filename", fileName)
    let scan_result = yr_scanner_scan_file(scanner, fileName)
    if scan_result != ERROR_SUCCESS:
      err_count += 1


proc scanDir(scanner: ptr YR_SCANNER, compiler: ptr YR_COMPILER, dirName: string, user_data: ptr CallbackArgs, file_count, dir_count, err_count: var int) =
  if not dirExists(dirName):
    return
  else:
    dir_count += 1
    for path in walkDirRec(dirName):
      scanFile(scanner, compiler, path, user_data, file_count, dir_count, err_count)


proc scanDirs(scanner: ptr YR_SCANNER, compiler: ptr YR_COMPILER, dirNames: seq[string], user_data: ptr CallbackArgs, file_count, dir_count, err_count: var int) =
  for dir in dirNames:
    scanDir(scanner, compiler, dir, user_data, file_count, dir_count, err_count)


proc handle_scan(scanner: ptr YR_SCANNER, compiler: ptr YR_COMPILER, fileOrDirName: string, user_data: ptr CallbackArgs, file_count, dir_count, err_count: var int, mode: int) =
  if mode == 0:
    scanFile(scanner, compiler, fileOrDirName, user_data, file_count, dir_count, err_count)
  elif mode == 1:
    scanDir(scanner, compiler, fileOrDirName, user_data, file_count, dir_count, err_count)


proc handle_scan(scanner: ptr YR_SCANNER, compiler: ptr YR_COMPILER, fileOrDirName: seq[string], user_data: ptr CallbackArgs, file_count, dir_count, err_count: var int, mode: int) =
  if mode == 3:
    scanDirs(scanner, compiler, fileOrDirName, user_data, file_count, dir_count, err_count)


proc createScan*(dbPath: string, fileOrDirName: (string | seq[string]), isFastScan: bool = false, mode=0): int =
  #[
    Scan mode:
      0. File
      1. Dir
      2. Dirs
  ]#
  var
    compiler: ptr YR_COMPILER
    rules: ptr YR_RULES
    scanner: ptr YR_SCANNER
    user_data = CALLBACK_ARGS(filePath: fileORDirName, current_count: 0)
    file_count, dir_count, err_count = 0
  let
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE
    timeout = 1000000
    flags = 0

  result = yr_initialize()

  if result != ERROR_SUCCESS:
    return result
  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return -1

  # LOAD DB FROM COMPILED DB. (yr_scanner_create is for text file rules so we don't use it)
  result = yr_rules_load(dbPath, addr(rules))

  case result
  of ERROR_COULD_NOT_OPEN_FILE:
    echo "Could not open db"
    return ERROR_COULD_NOT_OPEN_FILE
  of ERROR_INSUFFICIENT_MEMORY:
    echo "Memory error"
    return ERROR_INSUFFICIENT_MEMORY
  of ERROR_INVALID_FILE:
    echo "Invalid database file"
    return ERROR_INVALID_FILE
  of ERROR_CORRUPT_FILE:
    echo "Corrupted db"
    return ERROR_CORRUPT_FILE
  of ERROR_UNSUPPORTED_FILE_VERSION:
    echo "Unsupported Db version"
    return ERROR_UNSUPPORTED_FILE_VERSION
  else:
    discard

  discard yr_set_configuration(YR_CONFIG_STACK_SIZE, unsafeAddr(stack_size))
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(max_strings_per_rule))

  # INIT SCANNER
  result = yr_scanner_create(rules, addr(scanner))

  yr_scanner_set_flags(scanner, cast[cint](flags))
  yr_scanner_set_timeout(scanner, cast[cint](timeout))

  if result != ERROR_SUCCESS:
    echo "create_scanner_error"
    return -7

  yr_scanner_set_callback(scanner, callback_scan, addr(user_data))

  handle_scan(scanner, compiler, fileOrDirName, addr(user_data), file_count, dir_count, err_count, mode)

  echo "Signatures: ", rules.num_rules
  echo "Dir scanned: ", dir_count
  echo "File scanned: ", file_count
  echo "Error: ", err_count
  echo "Infected: ", user_data.current_count

  if scanner != nil:
    yr_scanner_destroy(scanner)
  if compiler != nil:
    yr_compiler_destroy(compiler)
  if rules != nil:
    discard yr_rules_destroy(rules)
  discard yr_finalize()


discard createScan("/tmp/sig.db", "/tmp", mode=1)
