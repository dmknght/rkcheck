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
    echo "Detected:\n  Rule: ", rule.identifier, "\n  Path: ", cast[ptr CALLBACK_ARGS](user_data).file_path
  return CALLBACK_CONTINUE



proc scanFile(rules: ptr YR_RULES, fileName: string, user_data: ptr CALLBACK_ARGS, file_count, err_count: var int) =
  if not fileExists(fileName):
    return
  else:
    user_data.file_path = fileName
    file_count += 1
    let meta_file_name = splitFile(fileName)

    discard yr_rules_define_string_variable(rules, "file_path", fileName)
    discard yr_rules_define_string_variable(rules, "file_name", meta_file_name.name)
    discard yr_rules_define_string_variable(rules, "file_dir", meta_file_name.dir)
    discard yr_rules_define_string_variable(rules, "file_ext", meta_file_name.ext)

    # Print value of extenal variables in rules
    echo "Extern-var: ", rules.externals_list_head.identifier, " value: ", rules.externals_list_head.value.s

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


proc createScan*(dbPath: string, fileOrDirName: (string | seq[string]), isFastScan: bool = false, mode=0): int =
  #[
    Scan mode:
      0. File
      1. Dir
      2. Dirs
  ]#
  var
    # compiler: ptr YR_COMPILER
    rules: ptr YR_RULES
    # scanner: ptr YR_SCANNER
    user_data = CALLBACK_ARGS(filePath: fileORDirName, current_count: 0)
    file_count, dir_count, err_count = 0
  let
    stack_size = DEFAULT_STACK_SIZE
    max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE
    # timeout = 1000000
    # flags = 0

  result = yr_initialize()

  if result != ERROR_SUCCESS:
    return result
  # if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
  #   return -1

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
  # result = yr_scanner_create(rules, addr(scanner))

  # yr_scanner_set_flags(scanner, cast[cint](flags))
  # yr_scanner_set_timeout(scanner, cast[cint](timeout))

  if result != ERROR_SUCCESS:
    echo "create_scanner_error"
    return -7

  # yr_scanner_set_callback(scanner, callback_scan, addr(user_data))

  handle_scan(rules, fileOrDirName, addr(user_data), file_count, dir_count, err_count, mode)

  echo "Signatures: ", rules.num_rules
  echo "Dir scanned: ", dir_count
  echo "File scanned: ", file_count
  echo "Error: ", err_count
  echo "Infected: ", user_data.current_count

  # if scanner != nil:
  #   yr_scanner_destroy(scanner)
  # if compiler != nil:
  #   yr_compiler_destroy(compiler)
  if rules != nil:
    discard yr_rules_destroy(rules)
  discard yr_finalize()


discard createScan("/tmp/sig.db", "/tmp/testfile", mode=0)
