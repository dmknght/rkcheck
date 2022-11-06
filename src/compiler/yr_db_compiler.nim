#[
  Compile rules using yr_compiler. Should be similar to yarac and user can use any (libyara must be the same)
  TODO take input options so we can use params from make file
]#

import .. / engine / libyara
import os
import strformat

type
  COMPILER_RESULT = object
    errors: int
    warnings: int


proc report_error(error_level: cint; file_name: cstring; line_number: cint; rule: ptr YR_RULE; message: cstring; user_data: pointer) {.cdecl.} =
  if rule != nil:
    echo fmt"{message} at {file_name}:{line_number}"


proc compile_rules(dst: string) =
  # Init yara
  var
    compiler: ptr YR_COMPILER
    rules: ptr YR_RULES
    compiler_result: COMPILER_RESULT

  let setting_max_string = DEFAULT_MAX_STRINGS_PER_RULE

  if yr_initialize() != ERROR_SUCCESS:
    return
  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return

  # Load yara rules

  # discard yr_compiler_define_string_variable(compiler, "file_path", "")
  # discard yr_compiler_define_string_variable(compiler, "file_name", "")
  # discard yr_compiler_define_string_variable(compiler, "file_dir", "")
  # discard yr_compiler_define_string_variable(compiler, "file_ext", ""

  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(setting_max_string))
  yr_compiler_set_callback(compiler, report_error, unsafeAddr(compiler_result))

  discard yr_compiler_add_file(compiler, open("rules/magics.yar"), "Magic", "magics.yar")
  discard yr_compiler_add_file(compiler, open("rules/ransomware.yar"), "Rans", "ransomware.yar")
  discard yr_compiler_add_file(compiler, open("rules/commons.yar"), "Heur", "commons.yar")
  discard yr_compiler_add_file(compiler, open("rules/rootkit.yar"), "Rkit", "rootkit.yar")
  discard yr_compiler_add_file(compiler, open("rules/trojan.yar"), "Trjn", "trojan.yar")
  discard yr_compiler_add_file(compiler, open("rules/coin_miner.yar"), "Minr", "coin_miner.yar")
  discard yr_compiler_add_file(compiler, open("rules/botnet.yar"), "Botn", "botnet.yar")

  discard yr_compiler_get_rules(compiler, addr(rules))
  discard yr_rules_save(rules, dst)


  # finityara
  if compiler != nil:
    yr_compiler_destroy(compiler)
  if rules != nil:
    discard yr_rules_destroy(rules)
  discard yr_finalize()


if not dirExists("database"):
  createDir("database")

compile_rules("build/database/signatures.ydb")
