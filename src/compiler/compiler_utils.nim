import ../engine/bindings/libyara
import strformat

type
  COMPILER_RESULT* = object
    errors*: int
    warnings*: int


proc yr_rules_report_errors*(error_level: cint; file_name: var cstring; line_number: cint; rule: var ptr YR_RULE; message: var cstring; user_data: pointer) {.cdecl.} =
  if rule != nil:
    echo fmt"{message} at {file_name}:{line_number}"


proc yr_rules_compile_custom_rules*(rules: var ptr YR_RULES, path_list: seq[string]): bool =
  var
    compiler: ptr YR_COMPILER
    compiler_result: COMPILER_RESULT
    setting_max_string = DEFAULT_MAX_STRINGS_PER_RULE

  if yr_initialize() != ERROR_SUCCESS:
    return false
  if yr_compiler_create(addr(compiler)) != ERROR_SUCCESS:
    return false

  discard yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, addr(setting_max_string))
  yr_compiler_set_callback(compiler, yr_rules_report_errors, addr(compiler_result))

  for path in path_list:
    if yr_compiler_add_file(compiler, open(path), "ExtrRules", cstring(path)) != ERROR_SUCCESS:
      return false

  if yr_compiler_get_rules(compiler, addr(rules)) != ERROR_SUCCESS:
    return false

  # finityara
  if compiler != nil:
    yr_compiler_destroy(compiler)
  discard yr_finalize()
