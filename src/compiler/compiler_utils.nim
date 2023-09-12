import .. / engine / libyara
import strformat

type
  COMPILER_RESULT* = object
    errors*: int
    warnings*: int


proc yr_rules_report_errors*(error_level: cint; file_name: cstring; line_number: cint; rule: ptr YR_RULE; message: cstring; user_data: pointer) {.cdecl.} =
  if rule != nil:
    echo fmt"{message} at {file_name}:{line_number}"


proc yr_rules_compile_custom_rules*(rules: var ptr YR_RULES, path: string) =
  var
    compiler: ptr YR_COMPILER
    compiler_result: COMPILER_RESULT
    setting_max_string = DEFAULT_MAX_STRINGS_PER_RULE

  if yr_initialize() != ERROR_SUCCESS:
    return
  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return

  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, addr(setting_max_string))
  discard yr_compiler_define_integer_variable(compiler, "scan_block_type", 0)
  yr_compiler_set_callback(compiler, yr_rules_report_errors, addr(compiler_result))

  discard yr_compiler_add_file(compiler, open(path), "CustomRules", path)

  discard yr_compiler_get_rules(compiler, addr(rules))

  # finityara
  if compiler != nil:
    yr_compiler_destroy(compiler)
  discard yr_finalize()
