import libyara / nimyara
import os
import segfaults

type
  CALLBACK_ARGS = object
    file_path*: string
    current_count*: int


const MAX_FILE_SIZE = 1024 * 1024 * 10 # 10 mb?
const collection_path = "/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/"


proc on_detected(file_path: string) =
  #[
    Move file to other place
    This is for debugging only
  ]#
  let file_name = splitPath(file_path).tail
  if not dirExists(collection_path):
    createDir(collection_path)
  moveFile(file_path, collection_path & file_name)


proc callback_scan(context: ptr YR_SCAN_CONTEXT; message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.} =
  if message == CALLBACK_MSG_RULE_MATCHING:
    let rule = cast[ptr YR_RULE](message_data)
    cast[ptr CALLBACK_ARGS](user_data).current_count += 1
    echo "Detected:\n  Rule: ", rule.identifier, "\n  Path: ", cast[ptr CALLBACK_ARGS](user_data).file_path
    # Skip if rules are matched
    on_detected(cast[ptr CALLBACK_ARGS](user_data).file_path)
    return CALLBACK_ABORT

  return CALLBACK_CONTINUE


proc scanFile(rules: ptr YR_RULES, fileName: string, user_data: ptr CALLBACK_ARGS, file_count, err_count: var int) =
  if not fileExists(fileName):
    return
  else:
    # Don't scan if file is too big
    if getFileSize(fileName) > MAX_FILE_SIZE:
      return
    user_data.file_path = fileName
    file_count += 1
    let meta_file_name = splitFile(fileName)

    discard yr_rules_define_string_variable(rules, "file_path", fileName)
    discard yr_rules_define_string_variable(rules, "file_name", meta_file_name.name)
    discard yr_rules_define_string_variable(rules, "file_dir", meta_file_name.dir)
    discard yr_rules_define_string_variable(rules, "file_ext", meta_file_name.ext)

    let scan_result = yr_rules_scan_file(rules, fileName, 0, callback_scan, user_data, 1000000)
    if scan_result != ERROR_SUCCESS:
      err_count += 1


proc scanDir(rules: ptr YR_RULES, dirName: string, user_data: ptr CallbackArgs, file_count, dir_count, err_count: var int) =
  if not dirExists(dirName):
    return
  else:
    dir_count += 1
    for path in walkDirRec(dirName):
      scanFile(rules, path, user_data, file_count, err_count)


proc scanDirs(rules: ptr YR_RULES, dirNames: seq[string], user_data: ptr CallbackArgs, file_count, dir_count, err_count: var int) =
  for dir in dirNames:
    scanDir(rules, dir, user_data, file_count, dir_count, err_count)


proc handle_scan(rules: ptr YR_RULES, fileOrDirName: string, user_data: ptr CallbackArgs, file_count, dir_count, err_count: var int, mode: int) =
  if mode == 0:
    scanFile(rules, fileOrDirName, user_data, file_count, err_count)
  elif mode == 1:
    scanDir(rules, fileOrDirName, user_data, file_count, dir_count, err_count)


proc handle_scan(rules: ptr YR_RULES, fileOrDirName: seq[string], user_data: ptr CallbackArgs, file_count, dir_count, err_count: var int, mode: int) =
  if mode == 3:
    scanDirs(rules, fileOrDirName, user_data, file_count, dir_count, err_count)


# FIXME the fileOrDirName seems doesn't work for the seq. Need to fix later
proc createScan*(dbPath: string, fileOrDirName: (string | seq[string]), isFastScan: bool = false, mode=0): int =
  #[
    Scan mode:
      0. File
      1. Dir
      2. Dirs
  ]#
  var
    rules: ptr YR_RULES
    user_data = CALLBACK_ARGS(filePath: fileORDirName, current_count: 0)
    file_count, dir_count, err_count = 0
  let
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE

  result = yr_initialize()

  if result != ERROR_SUCCESS:
    return result

  # LOAD DB FROM COMPILED DB. (yr_scanner_create is for text file rules so we don't use it)
  # result = yr_rules_load(dbPath, addr(rules))
  result = yr_rules_load(dbPath & "botnet.ydb", addr(rules))
  result = yr_rules_load(dbPath & "rootkit.ydb", addr(rules))
  result = yr_rules_load(dbPath & "coin_miner.ydb", addr(rules))
  result = yr_rules_load(dbPath & "trojan.ydb", addr(rules))

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

  if result != ERROR_SUCCESS:
    echo "create_scanner_error"
    return -7

  handle_scan(rules, fileOrDirName, addr(user_data), file_count, dir_count, err_count, mode)

  echo "Signatures: ", rules.num_rules
  echo "Dir scanned: ", dir_count
  echo "File scanned: ", file_count
  echo "Error: ", err_count
  echo "Infected: ", user_data.current_count

  if rules != nil:
    discard yr_rules_destroy(rules)
  discard yr_finalize()


discard createScan("database/", "/home/dmknght/Desktop/MalwareLab/Linux-Malware-Samples/", mode=1)
