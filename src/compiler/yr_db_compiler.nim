#[
  Compile rules using yr_compiler. Should be similar to yarac and user can use any (libyara must be the same)
]#

import ../engine/bindings/libyara
import compiler_utils


proc compile_default_rules(dst: string) =
  # Init yara
  var
    compiler: ptr YR_COMPILER
    rules: ptr YR_RULES
    compiler_result: COMPILER_RESULT
    setting_max_string = DEFAULT_MAX_STRINGS_PER_RULE
  if yr_initialize() != ERROR_SUCCESS:
    return
  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return

  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, addr(setting_max_string))
  yr_compiler_set_callback(compiler, yr_rules_report_errors, addr(compiler_result))

  # Set variables
  discard yr_compiler_define_boolean_variable(compiler, cstring("proc_exe_exists"), cint(0))
  discard yr_compiler_define_string_variable(compiler, cstring("proc_exe"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("proc_name"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("fd_stdin"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("fd_stdout"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("fd_stderr"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("proc_cmdline"), cstring(""))

  # Set scan block type for better memory scan's accuracy
  discard yr_compiler_add_file(compiler, open("rules/magics.yar"), "Magic", "magics.yar")
  discard yr_compiler_add_file(compiler, open("rules/ransomware.yar"), "Rans", "ransomware.yar")
  discard yr_compiler_add_file(compiler, open("rules/commons.yar"), "Heur", "commons.yar")
  discard yr_compiler_add_file(compiler, open("rules/rootkit.yar"), "Rkit", "rootkit.yar")
  discard yr_compiler_add_file(compiler, open("rules/trojan.yar"), "Trjn", "trojan.yar")
  discard yr_compiler_add_file(compiler, open("rules/coin_miner.yar"), "Minr", "coin_miner.yar")
  discard yr_compiler_add_file(compiler, open("rules/botnet.yar"), "Botn", "botnet.yar")

  discard yr_compiler_get_rules(compiler, addr(rules))
  let loaded_sigs = uint(rules.num_rules)
  echo "Compiling ", loaded_sigs, " signatures from default ruleset"
  discard yr_rules_save(rules, dst)

  # finityara
  if compiler != nil:
    yr_compiler_destroy(compiler)
  if rules != nil:
    discard yr_rules_destroy(rules)
  discard yr_finalize()


compile_default_rules("build/release/databases/signatures.ydb")
