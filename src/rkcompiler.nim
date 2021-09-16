#[
  Compile rules using yr_compiler. Should be similar to yarac and user can use any (libyara must be the same)
]#

import libyara / nimyara
import os
import strutils


proc compile_rules(src, dst: string) =
  # Init yara
  var
    compiler: ptr YR_COMPILER
    rules: ptr YR_RULES
  let setting_max_string = DEFAULT_MAX_STRINGS_PER_RULE
  if yr_initialize() != ERROR_SUCCESS:
    return
  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return
  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, unsafeAddr(setting_max_string))

  # Load yara rules
  if fileExists(src):
    discard yr_compiler_define_string_variable(compiler, "file_path", "")
    discard yr_compiler_define_string_variable(compiler, "file_name", "")
    discard yr_compiler_define_string_variable(compiler, "file_dir", "")
    discard yr_compiler_define_string_variable(compiler, "file_ext", "")
    discard yr_compiler_add_file(compiler, open(src), nil, src)
    discard yr_compiler_get_rules(compiler, addr(rules))
    discard yr_rules_save(rules, dst)
  elif dirExists(src):
    for kind, path in walkDir(src):
      if kind == pcFile and splitFile(path).ext == ".yara" or splitFile(path).ext == ".yar":
        discard yr_compiler_add_file(compiler, open(path), nil, path.split("/")[^1])
        discard yr_compiler_get_rules(compiler, addr(rules))
    discard yr_rules_save(rules, dst)
  else:
    echo "Invalid file or dir ", src

  # finityara
  if compiler != nil:
    yr_compiler_destroy(compiler)
  if rules != nil:
    discard yr_rules_destroy(rules)
  discard yr_finalize()


if not dirExists("database"):
  createDir("database")

compile_rules("rules/quick.yar", "database/quick_signatures.ydb")
