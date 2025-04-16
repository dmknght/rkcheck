#[
  Handle compiling rules
  1. Provide API to compile rules at compile time
  2. Provide API to compile rules at scan time (which helps decreasing memory usage)
  3. Provide API to select and compile text rules, or load custom compiled rules (todo ignore rules at db) at pre-scan time
  TODO previous logic uses Namespace for malware type. Must change to use tag or something different instead because
    there's no way to handle this value with current logic
]#

import strformat
import strutils
import ../engine/bindings/libyara

type
  COMPILER_RESULT* = object
    errors*: int
    warnings*: int


proc compiler_print_err(error_level: cint; file_name: cstring; line_number: cint; rule: ptr YR_RULE; message: cstring; user_data: pointer) {.cdecl.} =
  if rule != nil:
    echo fmt"{message} at {file_name}:{line_number}"

#[
  Init compiler engine
]#
proc compiler_init(compiler: var ptr YR_COMPILER): bool =
  var
    compiler_result: COMPILER_RESULT
    setting_max_string = DEFAULT_MAX_STRINGS_PER_RULE

  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return false

  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, addr(setting_max_string))
  yr_compiler_set_callback(compiler, compiler_print_err, addr(compiler_result))

  return true


proc compiler_finit(compiler: var ptr YR_COMPILER, rules: var ptr YR_RULES) =
  # let loaded_sigs = uint(rules.num_rules)
  # echo "Compiled ", loaded_sigs, " signatures from ", path

  if compiler != nil:
    yr_compiler_destroy(compiler)
  if rules != nil:
    discard yr_rules_destroy(rules)


#[
  Define variable that could be used at scan time.
]#
proc compiler_define_scan_variables(compiler: var ptr YR_COMPILER) =
  discard yr_compiler_define_boolean_variable(compiler, cstring("proc_exe_exists"), cint(0))
  discard yr_compiler_define_string_variable(compiler, cstring("proc_exe"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("proc_name"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("fd_stdin"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("fd_stdout"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("fd_stderr"), cstring(""))
  discard yr_compiler_define_string_variable(compiler, cstring("proc_cmdline"), cstring(""))


#[
  Load default rules and compile at compile time, save as compiled files
]#
proc compiler_compile_db(compiler: var ptr YR_COMPILER, rules: var ptr YR_RULES, file_path, compiled_path: string) =
  discard yr_compiler_add_file(compiler, open(file_path), nil, cstring(file_path))
  discard yr_compiler_get_rules(compiler, addr(rules))
  discard yr_rules_save(rules, compiled_path)


#[
  Load text rules from CLI and compile at pre-scan time (in memory compile)
]#
proc compiler_load_rules(compiler: var ptr YR_COMPILER, rules: var ptr YR_RULES, list_path: seq[string]): bool =
  for path in list_path:

    if yr_compiler_add_file(compiler, open(path), "ExtrRules", cstring(path)) != ERROR_SUCCESS:
      return false

    if yr_compiler_get_rules(compiler, addr(rules)) != ERROR_SUCCESS:
      return false

  return true


#[
  Compile text rule to make and save compiled rule
  Should be used at compile time. Research further for dynamic load from CLI
  YR rules pointer should be from parent function, either by scanner or compile-time compiler
]#
proc compiler_do_compile(rules: var ptr YR_RULES, file_path, compiled_path: string) =
  var
    compiler: ptr YR_COMPILER

  if not compiler_init(compiler):
    return

  compiler_define_scan_variables(compiler)
  compiler_compile_db(compiler, rules, file_path, compiled_path)
  compiler_finit(compiler, rules)


#[
  Compile text rule and load into memory
  Should be used at pre-scan time
]#
proc compiler_do_compile(rules: var ptr YR_RULES, list_path: seq[string]): bool =
  var
    compiler: ptr YR_COMPILER

  if not compiler_init(compiler):
    return

  compiler_define_scan_variables(compiler)
  result = compiler_load_rules(compiler, rules, list_path)
  compiler_finit(compiler, rules)
