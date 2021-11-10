# Generated @ 2020-10-07T00:01:26+07:00
# Command line:
#   /home/dmknght/.nimble/pkgs/nimterop-#head/nimterop/toast --preprocess -m:c --recurse --includeDirs+=/home/dmknght/.cache/nim/nimterop/nimyara/libyara/include --passL+=/home/dmknght/.cache/nim/nimterop/nimyara/libyara/.libs/libyara.a --pnim --symOverride=timeval,timespec,pthread_t,pthread_key_t,pthread_mutex_t,jmp_buf --nim:/usr/bin/nim --pluginSourcePath=/home/dmknght/.cache/nim/nimterop/cPlugins/nimterop_2208387551.nim /home/dmknght/.cache/nim/nimterop/nimyara/libyara/include/yara.h -o /home/dmknght/.cache/nim/nimterop/toastCache/nimterop_2867451765.nim

# const 'bool' has unsupported value 'int'
# const 'YR_API' has unsupported value 'EXTERNC __attribute__((visibility ("default")))'
# const 'YR_DEPRECATED_API' has unsupported value 'YR_API __attribute__((deprecated))'
# const 'YR_FILE_DESCRIPTOR' has unsupported value 'int'
# const 'YR_ARENA_NULL_REF' has unsupported value '(YR_ARENA_REF){ UINT32_MAX, UINT32_MAX }'
# const 'YR_BITMASK' has unsupported value 'unsigned long'
# const 'YR_BITMASK_SLOT_BITS' has unsupported value '(sizeof(YR_BITMASK) * 8)'
# const 'OBJECT_COMMON_FIELDS' has unsupported value 'int canary; int8_t type; const char* identifier; YR_OBJECT* parent; void* data;'
# const 'OP_INT_END' has unsupported value 'OP_INT_MINUS'
# const 'OP_DBL_END' has unsupported value 'OP_DBL_MINUS'
# const 'YR_VERSION' has unsupported value 'version_str(YR_MAJOR_VERSION) "." version_str(YR_MINOR_VERSION) "." version_str(YR_MICRO_VERSION)'
# const 'module_declarations' has unsupported value 'YR_CONCAT(MODULE_NAME, __declarations)'
# const 'module_load' has unsupported value 'YR_CONCAT(MODULE_NAME, __load)'
# const 'module_unload' has unsupported value 'YR_CONCAT(MODULE_NAME, __unload)'
# const 'module_initialize' has unsupported value 'YR_CONCAT(MODULE_NAME, __initialize)'
# const 'module_finalize' has unsupported value 'YR_CONCAT(MODULE_NAME, __finalize)'
# const 'begin_declarations' has unsupported value 'int module_declarations(YR_OBJECT* module) { YR_OBJECT* stack[64]; int stack_top = 0; stack[stack_top] = module;'
# const 'end_declarations' has unsupported value 'return ERROR_SUCCESS; }'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}
import macros

macro defineEnum(typ: untyped): untyped =
  result = newNimNode(nnkStmtList)

  # Enum mapped to distinct cint
  result.add quote do:
    type `typ`* = distinct cint

  for i in ["+", "-", "*", "div", "mod", "shl", "shr", "or", "and", "xor", "<", "<=", "==", ">", ">="]:
    let
      ni = newIdentNode(i)
      typout = if i[0] in "<=>": newIdentNode("bool") else: typ # comparisons return bool
    if i[0] == '>': # cannot borrow `>` and `>=` from templates
      let
        nopp = if i.len == 2: newIdentNode("<=") else: newIdentNode("<")
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` = `nopp`(y, x)
        proc `ni`*(x: cint, y: `typ`): `typout` = `nopp`(y, x)
        proc `ni`*(x, y: `typ`): `typout` = `nopp`(y, x)
    else:
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` {.borrow.}
        proc `ni`*(x: cint, y: `typ`): `typout` {.borrow.}
        proc `ni`*(x, y: `typ`): `typout` {.borrow.}
    result.add quote do:
      proc `ni`*(x: `typ`, y: int): `typout` = `ni`(x, y.cint)
      proc `ni`*(x: int, y: `typ`): `typout` = `ni`(x.cint, y)

  let
    divop = newIdentNode("/")   # `/`()
    dlrop = newIdentNode("$")   # `$`()
    notop = newIdentNode("not") # `not`()
  result.add quote do:
    proc `divop`*(x, y: `typ`): `typ` = `typ`((x.float / y.float).cint)
    proc `divop`*(x: `typ`, y: cint): `typ` = `divop`(x, `typ`(y))
    proc `divop`*(x: cint, y: `typ`): `typ` = `divop`(`typ`(x), y)
    proc `divop`*(x: `typ`, y: int): `typ` = `divop`(x, y.cint)
    proc `divop`*(x: int, y: `typ`): `typ` = `divop`(x.cint, y)

    proc `dlrop`*(x: `typ`): string {.borrow.}
    proc `notop`*(x: `typ`): `typ` {.borrow.}


{.pragma: impyaraHdr, header: "yara.h".}
{.experimental: "codeReordering".}
{.passL: "-lssl -lcrypto -lpthread -lm -lyara".} # Add nix Lib that yara import
defineEnum(YR_CONFIG_NAME)    ## ```
                          ##   Enumerated type listing configuration options
                          ## ```
const
  MAX_PATH* = 1024
  YR_MAX_THREADS* = 32
  YR_MAX_ARENA_BUFFERS* = 16
  YR_MAX_COMPILER_ERROR_EXTRA_INFO* = 256
  YR_MAX_ATOM_LENGTH* = 4
  YR_MAX_ATOM_QUALITY* = 255
  YR_MIN_ATOM_QUALITY* = 0
  YR_ATOM_QUALITY_WARNING_THRESHOLD* = YR_MAX_ATOM_QUALITY -
      typeof(YR_MAX_ATOM_QUALITY)(20 *
      typeof(YR_MAX_ATOM_QUALITY)(YR_MAX_ATOM_LENGTH)) +
      typeof(YR_MAX_ATOM_QUALITY)(38)
  YR_ATOMS_PER_RULE_WARNING_THRESHOLD* = 10000
  YR_MAX_LOOP_NESTING* = 4
  YR_MAX_LOOP_VARS* = 2
  YR_MAX_INCLUDE_DEPTH* = 16
  YR_MAX_STRING_MATCHES* = 1000000
  YR_MAX_FUNCTION_ARGS* = 128
  YR_MAX_OVERLOADED_FUNCTIONS* = 10
  YR_MAX_FAST_RE_STACK* = 300
  YR_STRING_CHAINING_THRESHOLD* = 200
  YR_LEX_BUF_SIZE* = 8192
  YR_MATCH_VERIFICATION_PROFILING_RATE* = 1024
  RE_MAX_SPLIT_ID* = 128
  RE_MAX_STACK* = 1024
  YR_RE_SCAN_LIMIT* = 4096
  RE_MAX_FIBERS* = 1024
  EOL* = (cast[uint32](-1))
  YR_ARENA_FILE_VERSION* = 18
  SIZED_STRING_FLAGS_NO_CASE* = 1
  SIZED_STRING_FLAGS_DOT_ALL* = 2
  RULE_FLAGS_PRIVATE* = 0x00000001
  RULE_FLAGS_GLOBAL* = 0x00000002
  RULE_FLAGS_NULL* = 0x00000004
  RULE_FLAGS_DISABLED* = 0x00000008
  STRING_FLAGS_REFERENCED* = 0x00000001
  STRING_FLAGS_HEXADECIMAL* = 0x00000002
  STRING_FLAGS_NO_CASE* = 0x00000004
  STRING_FLAGS_ASCII* = 0x00000008
  STRING_FLAGS_WIDE* = 0x00000010
  STRING_FLAGS_REGEXP* = 0x00000020
  STRING_FLAGS_FAST_REGEXP* = 0x00000040
  STRING_FLAGS_FULL_WORD* = 0x00000080
  STRING_FLAGS_ANONYMOUS* = 0x00000100
  STRING_FLAGS_SINGLE_MATCH* = 0x00000200
  STRING_FLAGS_LITERAL* = 0x00000400
  STRING_FLAGS_FITS_IN_ATOM* = 0x00000800
  STRING_FLAGS_LAST_IN_RULE* = 0x00001000
  STRING_FLAGS_CHAIN_PART* = 0x00002000
  STRING_FLAGS_CHAIN_TAIL* = 0x00004000
  STRING_FLAGS_FIXED_OFFSET* = 0x00008000
  STRING_FLAGS_GREEDY_REGEXP* = 0x00010000
  STRING_FLAGS_DOT_ALL* = 0x00020000
  STRING_FLAGS_DISABLED* = 0x00040000
  STRING_FLAGS_XOR* = 0x00080000
  STRING_FLAGS_PRIVATE* = 0x00100000
  STRING_FLAGS_BASE64* = 0x00200000
  STRING_FLAGS_BASE64_WIDE* = 0x00400000
  META_TYPE_INTEGER* = 1
  META_TYPE_STRING* = 2
  META_TYPE_BOOLEAN* = 3
  META_FLAGS_LAST_IN_RULE* = 1
  EXTERNAL_VARIABLE_TYPE_NULL* = 0
  EXTERNAL_VARIABLE_TYPE_FLOAT* = 1
  EXTERNAL_VARIABLE_TYPE_INTEGER* = 2
  EXTERNAL_VARIABLE_TYPE_BOOLEAN* = 3
  EXTERNAL_VARIABLE_TYPE_STRING* = 4
  EXTERNAL_VARIABLE_TYPE_MALLOC_STRING* = 5
  RE_NODE_LITERAL* = 1
  RE_NODE_MASKED_LITERAL* = 2
  RE_NODE_ANY* = 3
  RE_NODE_CONCAT* = 4
  RE_NODE_ALT* = 5
  RE_NODE_RANGE* = 6
  RE_NODE_STAR* = 7
  RE_NODE_PLUS* = 8
  RE_NODE_CLASS* = 9
  RE_NODE_WORD_CHAR* = 10
  RE_NODE_NON_WORD_CHAR* = 11
  RE_NODE_SPACE* = 12
  RE_NODE_NON_SPACE* = 13
  RE_NODE_DIGIT* = 14
  RE_NODE_NON_DIGIT* = 15
  RE_NODE_EMPTY* = 16
  RE_NODE_ANCHOR_START* = 17
  RE_NODE_ANCHOR_END* = 18
  RE_NODE_WORD_BOUNDARY* = 19
  RE_NODE_NON_WORD_BOUNDARY* = 20
  RE_NODE_RANGE_ANY* = 21
  RE_OPCODE_ANY* = 0x000000A0
  RE_OPCODE_LITERAL* = 0x000000A2
  RE_OPCODE_MASKED_LITERAL* = 0x000000A4
  RE_OPCODE_CLASS* = 0x000000A5
  RE_OPCODE_WORD_CHAR* = 0x000000A7
  RE_OPCODE_NON_WORD_CHAR* = 0x000000A8
  RE_OPCODE_SPACE* = 0x000000A9
  RE_OPCODE_NON_SPACE* = 0x000000AA
  RE_OPCODE_DIGIT* = 0x000000AB
  RE_OPCODE_NON_DIGIT* = 0x000000AC
  RE_OPCODE_MATCH* = 0x000000AD
  RE_OPCODE_MATCH_AT_END* = 0x000000B0
  RE_OPCODE_MATCH_AT_START* = 0x000000B1
  RE_OPCODE_WORD_BOUNDARY* = 0x000000B2
  RE_OPCODE_NON_WORD_BOUNDARY* = 0x000000B3
  RE_OPCODE_REPEAT_ANY_GREEDY* = 0x000000B4
  RE_OPCODE_REPEAT_ANY_UNGREEDY* = 0x000000B5
  RE_OPCODE_SPLIT_A* = 0x000000C0
  RE_OPCODE_SPLIT_B* = 0x000000C1
  RE_OPCODE_JUMP* = 0x000000C2
  RE_OPCODE_REPEAT_START_GREEDY* = 0x000000C3
  RE_OPCODE_REPEAT_END_GREEDY* = 0x000000C4
  RE_OPCODE_REPEAT_START_UNGREEDY* = 0x000000C5
  RE_OPCODE_REPEAT_END_UNGREEDY* = 0x000000C6
  RE_FLAGS_FAST_REGEXP* = 0x00000002
  RE_FLAGS_BACKWARDS* = 0x00000004
  RE_FLAGS_EXHAUSTIVE* = 0x00000008
  RE_FLAGS_WIDE* = 0x00000010
  RE_FLAGS_NO_CASE* = 0x00000020
  RE_FLAGS_SCAN* = 0x00000040
  RE_FLAGS_DOT_ALL* = 0x00000080
  RE_FLAGS_GREEDY* = 0x00000400
  RE_FLAGS_UNGREEDY* = 0x00000800
  ATOM_TREE_LEAF* = 1
  ATOM_TREE_AND* = 2
  ATOM_TREE_OR* = 3
  YR_AC_SLOT_OFFSET_BITS* = 9
  YR_AC_MAX_TRANSITION_TABLE_SIZE* = 0x00800000
  YR_AC_ROOT_STATE* = 0
  YARA_ERROR_LEVEL_ERROR* = 0
  YARA_ERROR_LEVEL_WARNING* = 1
  EXPRESSION_TYPE_UNKNOWN* = 0
  EXPRESSION_TYPE_BOOLEAN* = 1
  EXPRESSION_TYPE_INTEGER* = 2
  EXPRESSION_TYPE_STRING* = 4
  EXPRESSION_TYPE_REGEXP* = 8
  EXPRESSION_TYPE_OBJECT* = 16
  EXPRESSION_TYPE_FLOAT* = 32
  YR_NAMESPACES_TABLE* = 0
  YR_RULES_TABLE* = 1
  YR_METAS_TABLE* = 2
  YR_STRINGS_TABLE* = 3
  YR_EXTERNAL_VARIABLES_TABLE* = 4
  YR_SZ_POOL* = 5
  YR_CODE_SECTION* = 6
  YR_RE_CODE_SECTION* = 7
  YR_AC_TRANSITION_TABLE* = 8
  YR_AC_STATE_MATCHES_TABLE* = 9
  YR_AC_STATE_MATCHES_POOL* = 10
  YR_SUMMARY_SECTION* = 11
  YR_NUM_SECTIONS* = 12
  YR_INTERNAL_LOOP_VARS* = 3
  ERROR_SUCCESS* = 0
  ERROR_INSUFICIENT_MEMORY* = 1
  ERROR_INSUFFICIENT_MEMORY* = 1
  ERROR_COULD_NOT_ATTACH_TO_PROCESS* = 2
  ERROR_COULD_NOT_OPEN_FILE* = 3
  ERROR_COULD_NOT_MAP_FILE* = 4
  ERROR_INVALID_FILE* = 6
  ERROR_CORRUPT_FILE* = 7
  ERROR_UNSUPPORTED_FILE_VERSION* = 8
  ERROR_INVALID_REGULAR_EXPRESSION* = 9
  ERROR_INVALID_HEX_STRING* = 10
  ERROR_SYNTAX_ERROR* = 11
  ERROR_LOOP_NESTING_LIMIT_EXCEEDED* = 12
  ERROR_DUPLICATED_LOOP_IDENTIFIER* = 13
  ERROR_DUPLICATED_IDENTIFIER* = 14
  ERROR_DUPLICATED_TAG_IDENTIFIER* = 15
  ERROR_DUPLICATED_META_IDENTIFIER* = 16
  ERROR_DUPLICATED_STRING_IDENTIFIER* = 17
  ERROR_UNREFERENCED_STRING* = 18
  ERROR_UNDEFINED_STRING* = 19
  ERROR_UNDEFINED_IDENTIFIER* = 20
  ERROR_MISPLACED_ANONYMOUS_STRING* = 21
  ERROR_INCLUDES_CIRCULAR_REFERENCE* = 22
  ERROR_INCLUDE_DEPTH_EXCEEDED* = 23
  ERROR_WRONG_TYPE* = 24
  ERROR_EXEC_STACK_OVERFLOW* = 25
  ERROR_SCAN_TIMEOUT* = 26
  ERROR_TOO_MANY_SCAN_THREADS* = 27
  ERROR_CALLBACK_ERROR* = 28
  ERROR_INVALID_ARGUMENT* = 29
  ERROR_TOO_MANY_MATCHES* = 30
  ERROR_INTERNAL_FATAL_ERROR* = 31
  ERROR_NESTED_FOR_OF_LOOP* = 32
  ERROR_INVALID_FIELD_NAME* = 33
  ERROR_UNKNOWN_MODULE* = 34
  ERROR_NOT_A_STRUCTURE* = 35
  ERROR_NOT_INDEXABLE* = 36
  ERROR_NOT_A_FUNCTION* = 37
  ERROR_INVALID_FORMAT* = 38
  ERROR_TOO_MANY_ARGUMENTS* = 39
  ERROR_WRONG_ARGUMENTS* = 40
  ERROR_WRONG_RETURN_TYPE* = 41
  ERROR_DUPLICATED_STRUCTURE_MEMBER* = 42
  ERROR_EMPTY_STRING* = 43
  ERROR_DIVISION_BY_ZERO* = 44
  ERROR_REGULAR_EXPRESSION_TOO_LARGE* = 45
  ERROR_TOO_MANY_RE_FIBERS* = 46
  ERROR_COULD_NOT_READ_PROCESS_MEMORY* = 47
  ERROR_INVALID_EXTERNAL_VARIABLE_TYPE* = 48
  ERROR_REGULAR_EXPRESSION_TOO_COMPLEX* = 49
  ERROR_INVALID_MODULE_NAME* = 50
  ERROR_TOO_MANY_STRINGS* = 51
  ERROR_INTEGER_OVERFLOW* = 52
  ERROR_CALLBACK_REQUIRED* = 53
  ERROR_INVALID_OPERAND* = 54
  ERROR_COULD_NOT_READ_FILE* = 55
  ERROR_DUPLICATED_EXTERNAL_VARIABLE* = 56
  ERROR_INVALID_MODULE_DATA* = 57
  ERROR_WRITING_FILE* = 58
  ERROR_INVALID_MODIFIER* = 59
  ERROR_DUPLICATED_MODIFIER* = 60
  SCAN_FLAGS_FAST_MODE* = 1
  SCAN_FLAGS_PROCESS_MEMORY* = 2
  SCAN_FLAGS_NO_TRYCATCH* = 4
  SCAN_FLAGS_REPORT_RULES_MATCHING* = 8
  SCAN_FLAGS_REPORT_RULES_NOT_MATCHING* = 16
  CALLBACK_MSG_RULE_MATCHING* = 1
  CALLBACK_MSG_RULE_NOT_MATCHING* = 2
  CALLBACK_MSG_SCAN_FINISHED* = 3
  CALLBACK_MSG_IMPORT_MODULE* = 4
  CALLBACK_MSG_MODULE_IMPORTED* = 5
  CALLBACK_CONTINUE* = 0
  CALLBACK_ABORT* = 1
  CALLBACK_ERROR* = 2
  YR_UNDEFINED* = 0xFFFABADAFABADAFF'i64
  OP_ERROR* = 0
  OP_HALT* = 255
  OP_NOP* = 254
  OP_AND* = 1
  OP_OR* = 2
  OP_NOT* = 3
  OP_BITWISE_NOT* = 4
  OP_BITWISE_AND* = 5
  OP_BITWISE_OR* = 6
  OP_BITWISE_XOR* = 7
  OP_SHL* = 8
  OP_SHR* = 9
  OP_MOD* = 10
  OP_INT_TO_DBL* = 11
  OP_STR_TO_BOOL* = 12
  OP_PUSH* = 13
  OP_POP* = 14
  OP_CALL* = 15
  OP_OBJ_LOAD* = 16
  OP_OBJ_VALUE* = 17
  OP_OBJ_FIELD* = 18
  OP_INDEX_ARRAY* = 19
  OP_COUNT* = 20
  OP_LENGTH* = 21
  OP_FOUND* = 22
  OP_FOUND_AT* = 23
  OP_FOUND_IN* = 24
  OP_OFFSET* = 25
  OP_OF* = 26
  OP_PUSH_RULE* = 27
  OP_INIT_RULE* = 28
  OP_MATCH_RULE* = 29
  OP_INCR_M* = 30
  OP_CLEAR_M* = 31
  OP_ADD_M* = 32
  OP_POP_M* = 33
  OP_PUSH_M* = 34
  OP_SET_M* = 35
  OP_SWAPUNDEF* = 36
  OP_FILESIZE* = 37
  OP_ENTRYPOINT* = 38
  OP_MATCHES* = 40
  OP_IMPORT* = 41
  OP_LOOKUP_DICT* = 42
  OP_JUNDEF* = 43
  OP_JUNDEF_P* = 44
  OP_JNUNDEF* = 45
  OP_JNUNDEF_P* = 46
  OP_JFALSE* = 47
  OP_JFALSE_P* = 48
  OP_JTRUE* = 49
  OP_JTRUE_P* = 50
  OP_JL_P* = 51
  OP_JLE_P* = 52
  OP_ITER_NEXT* = 53
  OP_ITER_START_ARRAY* = 54
  OP_ITER_START_DICT* = 55
  OP_ITER_START_INT_RANGE* = 56
  OP_ITER_START_INT_ENUM* = 57
  OP_JZ* = 58
  OP_JZ_P* = 59
  OP_PUSH_8* = 60
  OP_PUSH_16* = 61
  OP_PUSH_32* = 62
  OP_PUSH_U* = 63
  OP_CONTAINS* = 64
  OP_STARTSWITH* = 65
  OP_ENDSWITH* = 66
  OP_ICONTAINS* = 67
  OP_ISTARTSWITH* = 68
  OP_IENDSWITH* = 69
  OP_EQ* = 0
  OP_NEQ* = 1
  OP_LT* = 2
  OP_GT* = 3
  OP_LE* = 4
  OP_GE* = 5
  OP_ADD* = 6
  OP_SUB* = 7
  OP_MUL* = 8
  OP_DIV* = 9
  OP_MINUS* = 10
  OP_INT_BEGIN* = 100
  OP_INT_EQ* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_EQ))
  OP_INT_NEQ* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_NEQ))
  OP_INT_LT* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_LT))
  OP_INT_GT* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_GT))
  OP_INT_LE* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_LE))
  OP_INT_GE* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_GE))
  OP_INT_ADD* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_ADD))
  OP_INT_SUB* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_SUB))
  OP_INT_MUL* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_MUL))
  OP_INT_DIV* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_DIV))
  OP_INT_MINUS* = (OP_INT_BEGIN + typeof(OP_INT_BEGIN)(OP_MINUS))
  OP_DBL_BEGIN* = 120
  OP_DBL_EQ* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_EQ))
  OP_DBL_NEQ* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_NEQ))
  OP_DBL_LT* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_LT))
  OP_DBL_GT* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_GT))
  OP_DBL_LE* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_LE))
  OP_DBL_GE* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_GE))
  OP_DBL_ADD* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_ADD))
  OP_DBL_SUB* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_SUB))
  OP_DBL_MUL* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_MUL))
  OP_DBL_DIV* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_DIV))
  OP_DBL_MINUS* = (OP_DBL_BEGIN + typeof(OP_DBL_BEGIN)(OP_MINUS))
  OP_STR_BEGIN* = 140
  OP_STR_EQ* = (OP_STR_BEGIN + typeof(OP_STR_BEGIN)(OP_EQ))
  OP_STR_NEQ* = (OP_STR_BEGIN + typeof(OP_STR_BEGIN)(OP_NEQ))
  OP_STR_LT* = (OP_STR_BEGIN + typeof(OP_STR_BEGIN)(OP_LT))
  OP_STR_GT* = (OP_STR_BEGIN + typeof(OP_STR_BEGIN)(OP_GT))
  OP_STR_LE* = (OP_STR_BEGIN + typeof(OP_STR_BEGIN)(OP_LE))
  OP_STR_GE* = (OP_STR_BEGIN + typeof(OP_STR_BEGIN)(OP_GE))
  OP_STR_END* = OP_STR_GE
  OP_READ_INT* = 240
  OP_INT8* = (OP_READ_INT + typeof(OP_READ_INT)(0))
  OP_INT16* = (OP_READ_INT + typeof(OP_READ_INT)(1))
  OP_INT32* = (OP_READ_INT + typeof(OP_READ_INT)(2))
  OP_UINT8* = (OP_READ_INT + typeof(OP_READ_INT)(3))
  OP_UINT16* = (OP_READ_INT + typeof(OP_READ_INT)(4))
  OP_UINT32* = (OP_READ_INT + typeof(OP_READ_INT)(5))
  OP_INT8BE* = (OP_READ_INT + typeof(OP_READ_INT)(6))
  OP_INT16BE* = (OP_READ_INT + typeof(OP_READ_INT)(7))
  OP_INT32BE* = (OP_READ_INT + typeof(OP_READ_INT)(8))
  OP_UINT8BE* = (OP_READ_INT + typeof(OP_READ_INT)(9))
  OP_UINT16BE* = (OP_READ_INT + typeof(OP_READ_INT)(10))
  OP_UINT32BE* = (OP_READ_INT + typeof(OP_READ_INT)(11))
  OBJECT_CREATE* = 1
  OBJECT_TYPE_INTEGER* = 1
  OBJECT_TYPE_STRING* = 2
  OBJECT_TYPE_STRUCTURE* = 3
  OBJECT_TYPE_ARRAY* = 4
  OBJECT_TYPE_FUNCTION* = 5
  OBJECT_TYPE_DICTIONARY* = 6
  OBJECT_TYPE_FLOAT* = 7
  YR_MAJOR_VERSION* = 4
  YR_MINOR_VERSION* = 0
  YR_MICRO_VERSION* = 2
  YR_VERSION_HEX* = ((YR_MAJOR_VERSION shl typeof(YR_MAJOR_VERSION)(16)) or
      typeof(YR_MAJOR_VERSION)((YR_MINOR_VERSION shl typeof(YR_MAJOR_VERSION)(8))) or
      typeof(YR_MAJOR_VERSION)((YR_MICRO_VERSION shl typeof(YR_MAJOR_VERSION)(0))))
  YR_CONFIG_STACK_SIZE* = (0).YR_CONFIG_NAME
  YR_CONFIG_MAX_STRINGS_PER_RULE* = (YR_CONFIG_STACK_SIZE + 1).YR_CONFIG_NAME
  YR_CONFIG_MAX_MATCH_DATA* = (YR_CONFIG_MAX_STRINGS_PER_RULE + 1).YR_CONFIG_NAME
  YR_CONFIG_LAST* = (YR_CONFIG_MAX_MATCH_DATA + 1).YR_CONFIG_NAME ## ```
                                                             ##   End-of-enum marker, not a configuration
                                                             ## ```
  DEFAULT_STACK_SIZE* = 16384
  DEFAULT_MAX_STRINGS_PER_RULE* = 10000
  DEFAULT_MAX_MATCH_DATA* = 512
type
  pthread_key_t = object
  pthread_mutex_t = object
  jmp_buf = object
  pthread_t = object
  timespec = object
  timeval = object
  YR_MAPPED_FILE* {.bycopy, impyaraHdr, importc: "struct _YR_MAPPED_FILE".} = object
    file*: cint
    size*: uint
    data*: ptr uint8

  YR_STREAM_READ_FUNC* {.importc, impyaraHdr.} = proc (`ptr`: pointer; size: uint;
      count: uint; user_data: pointer): uint {.cdecl.}
  YR_STREAM_WRITE_FUNC* {.importc, impyaraHdr.} = proc (`ptr`: pointer; size: uint;
      count: uint; user_data: pointer): uint {.cdecl.}
  YR_STREAM* {.bycopy, impyaraHdr, importc: "struct _YR_STREAM".} = object
    user_data*: pointer
    read*: YR_STREAM_READ_FUNC
    write*: YR_STREAM_WRITE_FUNC

  yr_arena_off_t* {.importc, impyaraHdr.} = uint32
  YR_ARENA* {.importc, impyaraHdr, bycopy.} = object
    xrefs*: cint ## ```
               ##   Number of users of this arena. This is set to one when the arena is created,
               ##      and can be incremented by calling yr_arena_acquire. On each call
               ##      to yr_arena_release it gets decremented by one, if xrefs reaches zero
               ##      the buffers and the YR_ARENA structures are freed.
               ## ```
    num_buffers*: cint         ## ```
                     ##   Number of buffers in this arena.
                     ## ```
    buffers*: array[16, YR_ARENA_BUFFER] ## ```
                                      ##   Status of individual buffers.
                                      ## ```
    initial_buffer_size*: uint ## ```
                             ##   Initial size for each buffer.
                             ## ```
    reloc_list_head*: ptr YR_RELOC ## ```
                                ##   Head of the list containing relocation entries.
                                ## ```
    reloc_list_tail*: ptr YR_RELOC ## ```
                                ##   Tail of the list containing relocation entries.
                                ## ```

  YR_ARENA_BUFFER* {.importc, impyaraHdr, bycopy.} = object
    data*: ptr uint8            ## ```
                  ##   Pointer the buffer's data.
                  ## ```
    size*: uint ## ```
              ##   Total buffer size, including the used and unused areas.
              ## ```
    used*: uint ## ```
              ##   Number of bytes that are actually used (equal to or lower than size).
              ## ```

  YR_ARENA_REF* {.importc, impyaraHdr, bycopy.} = object
    buffer_id*: uint32
    offset*: uint32

  YR_RELOC* {.importc, impyaraHdr, bycopy.} = object
    buffer_id*: uint32         ## ```
                     ##   Buffer ID associated to this relocation entry.
                     ## ```
    offset*: yr_arena_off_t ## ```
                          ##   Offset within the buffer where the relocatable pointer resides.
                          ## ```
    next*: ptr YR_RELOC         ## ```
                     ##   Pointer to the next entry in the list.
                     ## ```

  YR_HASH_TABLE_ENTRY* {.bycopy, impyaraHdr, importc: "struct _YR_HASH_TABLE_ENTRY".} = object
    key*: pointer
    key_length*: uint
    ns*: cstring
    value*: pointer
    next*: ptr YR_HASH_TABLE_ENTRY

  YR_HASH_TABLE* {.bycopy, impyaraHdr, importc: "struct _YR_HASH_TABLE".} = object
    size*: cint
    buckets*: array[1, ptr YR_HASH_TABLE_ENTRY]

  YR_HASH_TABLE_FREE_VALUE_FUNC* {.importc, impyaraHdr.} = proc (value: pointer): cint {.
      cdecl.}
  SIZED_STRING* {.bycopy, impyaraHdr, importc: "struct _SIZED_STRING".} = object ## ```
                                                                          ##   This struct is used to support strings containing null chars. The length of
                                                                          ##      the string is stored along the string data. However the string data is also
                                                                          ##      terminated with a null char.
                                                                          ## ```
    length*: uint32
    flags*: uint32
    c_string*: array[1, cchar]

  YR_STOPWATCH* {.bycopy, impyaraHdr, importc: "struct _YR_STOPWATCH".} = object
    tv_start*: timeval
    ts_start*: timespec

  YR_THREAD_ID* {.importc, impyaraHdr.} = pthread_t
  YR_THREAD_STORAGE_KEY* {.importc, impyaraHdr.} = pthread_key_t
  YR_MUTEX* {.importc, impyaraHdr.} = pthread_mutex_t
  YR_NOTEBOOK* {.importc, impyaraHdr, incompleteStruct.} = object
  RE* {.importc, impyaraHdr, bycopy.} = object
    flags*: uint32
    code*: array[0, uint8]

  RE_AST* {.importc, impyaraHdr, bycopy.} = object
    flags*: uint32
    root_node*: ptr RE_NODE

  RE_NODE* {.importc, impyaraHdr, bycopy.} = object
    `type`*: cint
    value*: cint
    count*: cint
    start*: cint
    mask*: cint
    `end`*: cint
    greedy*: cint
    re_class*: ptr RE_CLASS
    children_head*: ptr RE_NODE
    children_tail*: ptr RE_NODE
    prev_sibling*: ptr RE_NODE
    next_sibling*: ptr RE_NODE
    forward_code_ref*: YR_ARENA_REF
    backward_code_ref*: YR_ARENA_REF

  RE_CLASS* {.importc, impyaraHdr, bycopy.} = object
    negated*: uint8
    bitmap*: array[32, uint8]

  RE_ERROR* {.importc, impyaraHdr, bycopy.} = object
    message*: array[384, cchar]

  RE_FIBER* {.importc, impyaraHdr, bycopy.} = object
    ip*: ptr uint8              ## ```
                ##   instruction pointer
                ## ```
    sp*: int32                 ## ```
             ##   stack pointer
             ## ```
    rc*: int32                 ## ```
             ##   repeat counter
             ## ```
    prev*: ptr RE_FIBER
    next*: ptr RE_FIBER
    stack*: array[1024, uint16]

  RE_FIBER_LIST* {.importc, impyaraHdr, bycopy.} = object
    head*: ptr RE_FIBER
    tail*: ptr RE_FIBER

  RE_FIBER_POOL* {.importc, impyaraHdr, bycopy.} = object
    fiber_count*: cint
    fibers*: RE_FIBER_LIST

  YR_AC_STATE* {.importc, impyaraHdr, bycopy.} = object
    failure*: ptr YR_AC_STATE
    first_child*: ptr YR_AC_STATE
    siblings*: ptr YR_AC_STATE
    matches_ref*: YR_ARENA_REF ## ```
                             ##   Reference to the YR_AC_MATCH structure that heads the list of matches
                             ##      for this state.
                             ## ```
    depth*: uint8
    input*: uint8
    t_table_slot*: uint32

  YR_AC_AUTOMATON* {.importc, impyaraHdr, bycopy.} = object
    arena*: ptr YR_ARENA ## ```
                      ##   Arena used by this automaton to store the transition and match tables.
                      ## ```
    tables_size*: uint32 ## ```
                       ##   Both m_table and t_table have the same number of elements, which is
                       ##      stored in tables_size.
                       ## ```
    t_table_unused_candidate*: uint32 ## ```
                                    ##   The first slot in the transition table (t_table) that may be be unused.
                                    ##      Used for speeding up the construction of the transition table.
                                    ## ```
    bitmask*: ptr culong ## ```
                      ##   Bitmask where each bit indicates if the corresponding slot in the
                      ##      transition table is already in use.
                      ## ```
    root*: ptr YR_AC_STATE      ## ```
                        ##   Pointer to the root Aho-Corasick state.
                        ## ```

  YR_AC_TABLES* {.importc, impyaraHdr, incompleteStruct.} = object
  YR_AC_MATCH_LIST_ENTRY* {.importc, impyaraHdr, bycopy.} = object
    backtrack*: uint16
    string_idx*: uint32
    `ref`*: YR_ARENA_REF
    forward_code_ref*: YR_ARENA_REF
    backward_code_ref*: YR_ARENA_REF
    next*: ptr YR_AC_MATCH_LIST_ENTRY

  YR_AC_MATCH* {.importc, impyaraHdr, bycopy.} = object
    string*: ptr YR_STRING
    string_g*: YR_ARENA_REF
    forward_code*: ptr uint8
    forward_code_g*: YR_ARENA_REF
    backward_code*: ptr uint8
    backward_code_g*: YR_ARENA_REF
    next*: ptr YR_AC_MATCH
    next_g*: YR_ARENA_REF
    backtrack*: uint16 ## ```
                     ##   When the Aho-Corasick automaton reaches some state that has associated
                     ##      matches, the current position in the input buffer is a few bytes past
                     ##      the point where the match actually occurs, for example, when looking for
                     ##      string "bar" in "foobarbaz", when the automaton reaches the state associated
                     ##      to the ending "r" in "bar, which is the one that has a match, the current
                     ##      position in the input is 6 (the "b" after the "r"), but the match is at
                     ##      position 3. The backtrack field indicates how many bytes the scanner has
                     ##      to go back to find the point where the match actually start.
                     ##
                     ##      YR_ALIGN(8) forces the backtrack field to be treated as a 8-bytes field
                     ##      and therefore the struct's size is 40 bytes. This is necessary only for
                     ##      32-bits versions of YARA compiled with Visual Studio. See: #1358.
                     ## ```

  YR_NAMESPACE* {.importc, impyaraHdr, bycopy.} = object
    name*: cstring
    name_g*: YR_ARENA_REF
    idx*: uint32 ## ```
               ##   Index of this namespace in the array of YR_NAMESPACE structures stored
               ##      in YR_NAMESPACES_TABLE.
               ##
               ##      YR_ALIGN(8) forces the idx field to be treated as a 8-bytes field
               ##      and therefore the struct's size is 16 bytes. This is necessary only for
               ##      32-bits versions of YARA compiled with Visual Studio. See: #1358.
               ## ```

  YR_META* {.importc, impyaraHdr, bycopy.} = object
    identifier*: cstring
    identifier_g*: YR_ARENA_REF
    string*: cstring
    string_g*: YR_ARENA_REF
    integer*: int64
    `type`*: int32
    flags*: int32

  YR_MATCHES* {.importc, impyaraHdr, bycopy.} = object
    head*: ptr YR_MATCH
    tail*: ptr YR_MATCH
    count*: int32

  YR_STRING* {.importc, impyaraHdr, bycopy.} = object
    flags*: uint32 ## ```
                 ##   Flags, see STRING_FLAGS_XXX macros defined above.
                 ## ```
    idx*: uint32 ## ```
               ##   Index of this string in the array of YR_STRING structures stored in
               ##      YR_STRINGS_TABLE.
               ## ```
    fixed_offset*: int64 ## ```
                       ##   If the string can only match at a specific offset (for example if the
                       ##      condition is "$a at 0" the string $a can only match at offset 0), the
                       ##      fixed_offset field contains the offset, it have the YR_UNDEFINED value for
                       ##      strings that can match anywhere.
                       ## ```
    rule_idx*: uint32 ## ```
                    ##   Index of the rule containing this string in the array of YR_RULE
                    ##      structures stored in YR_RULES_TABLE.
                    ## ```
    length*: int32             ## ```
                 ##   String's length.
                 ## ```
    string*: ptr uint8
    string_g*: YR_ARENA_REF
    chained_to*: ptr YR_STRING
    chained_to_g*: YR_ARENA_REF
    chain_gap_min*: int32 ## ```
                        ##   When this string is chained to some other string, chain_gap_min and
                        ##      chain_gap_max contain the minimum and maximum distance between the two
                        ##      strings. For example in { 01 02 03 04 [X-Y] 05 06 07 08 }, the string
                        ##      { 05 06 07 08 } is chained to { 01 02 03 04 } and chain_gap_min is X
                        ##      and chain_gap_max is Y. These fields are ignored for strings that are not
                        ##      part of a string chain.
                        ## ```
    chain_gap_max*: int32
    identifier*: cstring
    identifier_g*: YR_ARENA_REF

  YR_RULE* {.importc, impyaraHdr, bycopy.} = object
    flags*: int32
    num_atoms*: int32          ## ```
                    ##   Number of atoms generated for this rule.
                    ## ```
    identifier*: cstring
    identifier_g*: YR_ARENA_REF
    tags*: cstring
    tags_g*: YR_ARENA_REF
    metas*: ptr YR_META
    metas_g*: YR_ARENA_REF
    strings*: ptr YR_STRING
    strings_g*: YR_ARENA_REF
    ns*: ptr YR_NAMESPACE
    ns_g*: YR_ARENA_REF

  YR_RULES* {.importc, impyaraHdr, bycopy.} = object
    arena*: ptr YR_ARENA
    rules_list_head*: ptr YR_RULE
    strings_list_head*: ptr YR_STRING
    externals_list_head*: ptr YR_EXTERNAL_VARIABLE
    ac_transition_table*: ptr YR_AC_TRANSITION
    ac_match_pool*: ptr YR_AC_MATCH
    ac_match_table*: ptr uint32
    code_start*: ptr uint8
    num_rules*: uint32         ## ```
                     ##   Total number of rules.
                     ## ```
    num_strings*: uint32       ## ```
                       ##   Total number of strings.
                       ## ```
    num_namespaces*: uint32    ## ```
                          ##   Total number of namespaces.
                          ## ```

  YR_SUMMARY* {.importc, impyaraHdr, bycopy.} = object
    num_rules*: uint32
    num_strings*: uint32
    num_namespaces*: uint32

  YR_RULES_STATS* {.importc, impyaraHdr, bycopy.} = object
    num_rules*: uint32         ## ```
                     ##   Total number of rules
                     ## ```
    num_strings*: uint32       ## ```
                       ##   Total number of strings across all rules.
                       ## ```
    ac_matches*: uint32 ## ```
                      ##   Total number of Aho-Corasick matches. Each node in the Aho-Corasick
                      ##      automaton has a list of YR_AC_MATCH_LIST_ENTRY structures (match list)
                      ##      pointing to strings that are potential matches. This field holds the total
                      ##      number of those structures across all nodes in the automaton.
                      ## ```
    ac_root_match_list_length*: uint32 ## ```
                                     ##   Length of the match list for the root node in the Aho-Corasick automaton.
                                     ## ```
    ac_average_match_list_length*: cfloat ## ```
                                        ##   Average number of matches per match list.
                                        ## ```
    top_ac_match_list_lengths*: array[100, uint32] ## ```
                                                ##   Top 10 longest match lists.
                                                ## ```
    ac_match_list_length_pctls*: array[101, uint32] ## ```
                                                 ##   Percentiles of match lists' lengths. If the i-th value in the array is N
                                                 ##      then i percent of the match lists have N or less items.
                                                 ## ```
    ac_tables_size*: uint32    ## ```
                          ##   Size of Aho-Corasick transition & match tables.
                          ## ```

  YR_PROFILING_INFO* {.importc, impyaraHdr, bycopy.} = object ## ```
                                                        ##   YR_PROFILING_INFO contains profiling information for a rule.
                                                        ## ```
    atom_matches*: uint32 ## ```
                        ##   Number of times that some atom belonging to the rule matched. Each
                        ##      matching atom means a potential string match that needs to be verified.
                        ## ```
    match_time*: uint64 ## ```
                      ##   Amount of time (in nanoseconds) spent verifying atom matches for
                      ##      determining if the corresponding string actually matched or not. This
                      ##      time is not measured for all atom matches, only 1 out of 1024 matches
                      ##      are actually measured.
                      ## ```
    exec_time*: uint64 ## ```
                     ##   Amount of time (in nanoseconds) spent evaluating the rule condition.
                     ## ```

  YR_RULE_PROFILING_INFO* {.importc, impyaraHdr, bycopy.} = object ## ```
                                                             ##   YR_RULE_PROFILING_INFO is the structure returned by
                                                             ##      yr_scanner_get_profiling_info
                                                             ## ```
    rule*: ptr YR_RULE
    cost*: uint64

  YR_EXTERNAL_VARIABLE* {.importc, impyaraHdr, bycopy.} = object
    `type`*: int32
    value*: Union_yarah13
    identifier*: cstring
    identifier_g*: YR_ARENA_REF

  YR_MATCH* {.importc, impyaraHdr, bycopy.} = object
    base*: int64               ## ```
               ##   Base address for the match
               ## ```
    offset*: int64             ## ```
                 ##   Offset relative to base for the match
                 ## ```
    match_length*: int32       ## ```
                       ##   Match length
                       ## ```
    data_length*: int32        ## ```
                      ##   Match length
                      ## ```
    data*: ptr uint8 ## ```
                  ##   Pointer to a buffer containing a portion of the matched data. The size of
                  ##      the buffer is data_length. data_length is always <= length and is limited
                  ##      to YR_CONFIG_MAX_MATCH_DATA bytes.
                  ## ```
    prev*: ptr YR_MATCH
    next*: ptr YR_MATCH
    chain_length*: int32 ## ```
                       ##   If the match belongs to a chained string chain_length contains the
                       ##      length of the chain. This field is used only in unconfirmed matches.
                       ## ```
    is_private*: bool

  YR_SCAN_CONTEXT* {.importc, impyaraHdr, bycopy.} = object
    file_size*: uint64         ## ```
                     ##   File size of the file being scanned.
                     ## ```
    entry_point*: uint64 ## ```
                       ##   Entry point of the file being scanned, if the file is PE or ELF.
                       ## ```
    flags*: cint               ## ```
               ##   Scanning flags.
               ## ```
    canary*: cint ## ```
                ##   Canary value used for preventing hand-crafted objects from being embedded
                ##      in compiled rules and used to exploit YARA. The canary value is initialized
                ##      to a random value and is subsequently set to all objects created by
                ##      yr_object_create. The canary is verified when objects are used by
                ##      yr_execute_code.
                ## ```
    timeout*: uint64           ## ```
                   ##   Scan timeout in nanoseconds.
                   ## ```
    user_data*: pointer ## ```
                      ##   Pointer to user-provided data passed to the callback function.
                      ## ```
    callback*: YR_CALLBACK_FUNC ## ```
                              ##   Pointer to the user-provided callback function that is called when an
                              ##      event occurs during the scan (a rule matching, a module being loaded, etc)
                              ## ```
    rules*: ptr YR_RULES ## ```
                      ##   Pointer to the YR_RULES object associated to this scan context.
                      ## ```
    last_error_string*: ptr YR_STRING ## ```
                                   ##   Pointer to the YR_STRING causing the most recent scan error.
                                   ## ```
    `iterator`*: ptr YR_MEMORY_BLOCK_ITERATOR ## ```
                                           ##   Pointer to the iterator used for scanning
                                           ## ```
    objects_table*: ptr YR_HASH_TABLE ## ```
                                   ##   Pointer to a table mapping identifiers to YR_OBJECT structures. This table
                                   ##      contains entries for external variables and modules.
                                   ## ```
    matches_notebook*: ptr YR_NOTEBOOK ## ```
                                    ##   Notebook used for storing YR_MATCH structures associated to the matches
                                    ##      found.
                                    ## ```
    stopwatch*: YR_STOPWATCH ## ```
                           ##   Stopwatch used for measuring the time elapsed during the scan.
                           ## ```
    re_fiber_pool*: RE_FIBER_POOL ## ```
                                ##   Fiber pool used by yr_re_exec.
                                ## ```
    rule_matches_flags*: ptr culong ## ```
                                 ##   A bitmap with one bit per rule, bit N is set when the rule with index N
                                 ##      has matched.
                                 ## ```
    ns_unsatisfied_flags*: ptr culong ## ```
                                   ##   A bitmap with one bit per namespace, bit N is set if the namespace with
                                   ##      index N has some global rule that is not satisfied.
                                   ## ```
    matches*: ptr YR_MATCHES ## ```
                          ##   Array with pointers to lists of matches. Item N in the array has the
                          ##      list of matches for string with index N.
                          ## ```
    unconfirmed_matches*: ptr YR_MATCHES ## ```
                                      ##   "unconfirmed_matches" is like "matches" but for strings that are part of
                                      ##      a chain. Let's suppose that the string S is split in two chained strings
                                      ##      S1 <- S2. When a match is found for S1, we can't be sure that S matches
                                      ##      until a match for S2 is found (within the range defined by chain_gap_min
                                      ##      and chain_gap_max), so the matches for S1 are put in "unconfirmed_matches"
                                      ##      until they can be confirmed or discarded.
                                      ## ```
    profiling_info*: ptr YR_PROFILING_INFO ## ```
                                        ##   profiling_info is a pointer to an array of YR_PROFILING_INFO structures,
                                        ##      one per rule. Entry N has the profiling information for rule with index N.
                                        ## ```

  YR_VALUE* {.importc, impyaraHdr, bycopy.} = object
    i*: int64
    d*: cdouble
    p*: pointer
    o*: ptr YR_OBJECT
    s*: ptr YR_STRING
    it*: ptr YR_ITERATOR
    ss*: ptr SIZED_STRING
    re*: ptr RE

  YR_VALUE_STACK* {.importc, impyaraHdr, bycopy.} = object
    sp*: int32
    capacity*: int32
    items*: ptr YR_VALUE

  YR_OBJECT* {.importc, impyaraHdr, bycopy.} = object
    canary*: cint
    `type`*: int8
    identifier*: cstring
    parent*: ptr YR_OBJECT
    data*: pointer
    value*: YR_VALUE

  YR_OBJECT_STRUCTURE* {.importc, impyaraHdr, bycopy.} = object
    canary*: cint
    `type`*: int8
    identifier*: cstring
    parent*: ptr YR_OBJECT
    data*: pointer
    members*: ptr YR_STRUCTURE_MEMBER

  YR_OBJECT_ARRAY* {.importc, impyaraHdr, bycopy.} = object
    canary*: cint
    `type`*: int8
    identifier*: cstring
    parent*: ptr YR_OBJECT
    data*: pointer
    prototype_item*: ptr YR_OBJECT
    items*: ptr YR_ARRAY_ITEMS

  YR_OBJECT_DICTIONARY* {.importc, impyaraHdr, bycopy.} = object
    canary*: cint
    `type`*: int8
    identifier*: cstring
    parent*: ptr YR_OBJECT
    data*: pointer
    prototype_item*: ptr YR_OBJECT
    items*: ptr YR_DICTIONARY_ITEMS

  YR_OBJECT_FUNCTION* {.importc, impyaraHdr, bycopy.} = object
    canary*: cint
    `type`*: int8
    identifier*: cstring
    parent*: ptr YR_OBJECT
    data*: pointer
    return_obj*: ptr YR_OBJECT
    arguments_fmt*: cstring
    code*: YR_MODULE_FUNC

  YR_STRUCTURE_MEMBER* {.importc, impyaraHdr, bycopy.} = object
    `object`*: ptr YR_OBJECT
    next*: ptr YR_STRUCTURE_MEMBER

  YR_ARRAY_ITEMS* {.importc, impyaraHdr, bycopy.} = object
    capacity*: cint            ## ```
                  ##   Capacity is the size of the objects array.
                  ## ```
    length*: cint ## ```
                ##   Length is determined by the last element in the array. If the index of the
                ##      last element is N, then length is N+1 because indexes start at 0.
                ## ```
    objects*: array[1, ptr YR_OBJECT]

  YR_DICTIONARY_ITEMS* {.importc, impyaraHdr, bycopy.} = object
    used*: cint
    free*: cint
    key*: ptr SIZED_STRING
    obj*: ptr YR_OBJECT

  YR_MODULE* {.importc, impyaraHdr, bycopy.} = object
    name*: cstring
    declarations*: YR_EXT_DECLARATIONS_FUNC
    load*: YR_EXT_LOAD_FUNC
    unload*: YR_EXT_UNLOAD_FUNC
    initialize*: YR_EXT_INITIALIZE_FUNC
    finalize*: YR_EXT_FINALIZE_FUNC

  YR_MODULE_IMPORT* {.importc, impyaraHdr, bycopy.} = object
    module_name*: cstring
    module_data*: pointer
    module_data_size*: uint

  YR_MEMORY_BLOCK* {.importc, impyaraHdr, bycopy.} = object
    size*: uint
    base*: uint64
    context*: pointer
    fetch_data*: YR_MEMORY_BLOCK_FETCH_DATA_FUNC

  YR_MEMORY_BLOCK_ITERATOR* {.importc, impyaraHdr, bycopy.} = object
    context*: pointer
    first*: YR_MEMORY_BLOCK_ITERATOR_FUNC
    next*: YR_MEMORY_BLOCK_ITERATOR_FUNC

  YR_MODIFIER* {.importc, impyaraHdr, bycopy.} = object
    flags*: int32
    xor_min*: uint8
    xor_max*: uint8
    alphabet*: ptr SIZED_STRING

  YR_ITERATOR* {.importc, impyaraHdr, bycopy.} = object
    next*: YR_ITERATOR_NEXT_FUNC
    array_it*: YR_ARRAY_ITERATOR
    dict_it*: YR_DICT_ITERATOR
    int_range_it*: YR_INT_RANGE_ITERATOR
    int_enum_it*: YR_INT_ENUM_ITERATOR

  YR_AC_TRANSITION* {.importc, impyaraHdr.} = uint32
  Union_yarah13* {.union, bycopy, impyaraHdr, importc: "union Union_yarah13".} = object
    i*: int64
    f*: cdouble
    s*: cstring

  YR_MEMORY_BLOCK_FETCH_DATA_FUNC* {.importc, impyaraHdr.} = proc (
      self: ptr YR_MEMORY_BLOCK): ptr uint8 {.cdecl.}
  YR_MEMORY_BLOCK_ITERATOR_FUNC* {.importc, impyaraHdr.} = proc (
      self: ptr YR_MEMORY_BLOCK_ITERATOR): ptr YR_MEMORY_BLOCK {.cdecl.}
  YR_CALLBACK_FUNC* {.importc, impyaraHdr.} = proc (context: ptr YR_SCAN_CONTEXT;
      message: cint; message_data: pointer; user_data: pointer): cint {.cdecl.}
  YR_MODULE_FUNC* {.importc, impyaraHdr.} = proc (args: ptr YR_VALUE;
      context: ptr YR_SCAN_CONTEXT; function_obj: ptr YR_OBJECT_FUNCTION): cint {.cdecl.}
  YR_ITERATOR_NEXT_FUNC* {.importc, impyaraHdr.} = proc (self: ptr YR_ITERATOR;
      stack: ptr YR_VALUE_STACK): cint {.cdecl.}
  YR_ARRAY_ITERATOR* {.bycopy, impyaraHdr, importc: "struct YR_ARRAY_ITERATOR".} = object
    array*: ptr YR_OBJECT
    index*: cint

  YR_DICT_ITERATOR* {.bycopy, impyaraHdr, importc: "struct YR_DICT_ITERATOR".} = object
    dict*: ptr YR_OBJECT
    index*: cint

  YR_INT_RANGE_ITERATOR* {.bycopy, impyaraHdr,
                          importc: "struct YR_INT_RANGE_ITERATOR".} = object
    next*: int64
    last*: int64

  YR_INT_ENUM_ITERATOR* {.bycopy, impyaraHdr,
                         importc: "struct YR_INT_ENUM_ITERATOR".} = object
    next*: cint
    count*: cint
    items*: array[1, int64]

  RE_MATCH_CALLBACK_FUNC* {.importc, impyaraHdr.} = proc (match: ptr uint8;
      match_length: cint; flags: cint; args: pointer): cint {.cdecl.}
  YR_ATOM* {.importc, impyaraHdr, bycopy.} = object
    length*: uint8
    bytes*: array[4, uint8]
    mask*: array[4, uint8]

  YR_ATOM_TREE_NODE* {.importc, impyaraHdr, bycopy.} = object
    `type`*: uint8
    atom*: YR_ATOM
    re_nodes*: array[4, ptr RE_NODE] ## ```
                                 ##   RE nodes that correspond to each byte in the atom.
                                 ## ```
    children_head*: ptr YR_ATOM_TREE_NODE
    children_tail*: ptr YR_ATOM_TREE_NODE
    next_sibling*: ptr YR_ATOM_TREE_NODE

  YR_ATOM_TREE* {.importc, impyaraHdr, bycopy.} = object
    root_node*: ptr YR_ATOM_TREE_NODE

  YR_ATOM_LIST_ITEM* {.importc, impyaraHdr, bycopy.} = object
    atom*: YR_ATOM
    backtrack*: uint16
    forward_code_ref*: YR_ARENA_REF
    backward_code_ref*: YR_ARENA_REF
    next*: ptr YR_ATOM_LIST_ITEM

  YR_ATOM_QUALITY_TABLE_ENTRY* {.importc, impyaraHdr, bycopy.} = object
    atom*: array[4, uint8]
    quality*: uint8

  YR_ATOMS_CONFIG* {.importc, impyaraHdr, bycopy.} = object
    get_atom_quality*: YR_ATOMS_QUALITY_FUNC
    quality_table*: ptr YR_ATOM_QUALITY_TABLE_ENTRY
    quality_warning_threshold*: cint
    quality_table_entries*: cint
    free_quality_table*: bool

  YR_ATOMS_QUALITY_FUNC* {.importc, impyaraHdr.} = proc (config: ptr YR_ATOMS_CONFIG;
      atom: ptr YR_ATOM): cint {.cdecl.}
  Union_yarah22* {.union, bycopy, impyaraHdr, importc: "union Union_yarah22".} = object
    integer*: int64
    `object`*: ptr YR_OBJECT
    sized_string_ref*: YR_ARENA_REF

  Type_yarah3* {.bycopy, impyaraHdr, importc: "struct Type_yarah3".} = object ## ```
                                                                       ##   An expression can have an associated identifier, if "ptr" is not NULL it
                                                                       ##      points to the identifier name, if it is NULL, then "ref" holds a reference
                                                                       ##      to the identifier within YR_SZ_POOL. When the identifier is in YR_SZ_POOL
                                                                       ##      a pointer can't be used as the YR_SZ_POOL can be moved to a different
                                                                       ##      memory location.
                                                                       ## ```
    `ptr`*: cstring
    `ref`*: YR_ARENA_REF

  YR_EXPRESSION* {.bycopy, impyaraHdr, importc: "struct _YR_EXPRESSION".} = object
    `type`*: cint
    value*: Union_yarah22
    identifier*: Type_yarah3 ## ```
                           ##   An expression can have an associated identifier, if "ptr" is not NULL it
                           ##      points to the identifier name, if it is NULL, then "ref" holds a reference
                           ##      to the identifier within YR_SZ_POOL. When the identifier is in YR_SZ_POOL
                           ##      a pointer can't be used as the YR_SZ_POOL can be moved to a different
                           ##      memory location.
                           ## ```

  YR_COMPILER_CALLBACK_FUNC* {.importc, impyaraHdr.} = proc (error_level: cint;
      file_name: cstring; line_number: cint; rule: ptr YR_RULE; message: cstring;
      user_data: pointer) {.cdecl.}
  YR_COMPILER_INCLUDE_CALLBACK_FUNC* {.importc, impyaraHdr.} = proc (
      include_name: cstring; calling_rule_filename: cstring;
      calling_rule_namespace: cstring; user_data: pointer): cstring {.cdecl.}
  YR_COMPILER_INCLUDE_FREE_FUNC* {.importc, impyaraHdr.} = proc (
      callback_result_ptr: cstring; user_data: pointer) {.cdecl.}
  YR_COMPILER_RE_AST_CALLBACK_FUNC* {.importc, impyaraHdr.} = proc (
      rule: ptr YR_RULE; string_identifier: cstring; re_ast: ptr RE_AST;
      user_data: pointer) {.cdecl.}
  YR_FIXUP* {.bycopy, impyaraHdr, importc: "struct _YR_FIXUP".} = object
    `ref`*: YR_ARENA_REF
    next*: ptr YR_FIXUP

  YR_LOOP_CONTEXT* {.bycopy, impyaraHdr, importc: "struct _YR_LOOP_CONTEXT".} = object
    start_ref*: YR_ARENA_REF ## ```
                           ##   Reference indicating the the place in the code where the loop starts. The
                           ##      loop goes back to this address on each iteration.
                           ## ```
    vars_count*: cint ## ```
                    ##   vars_count is the number of local variables defined by the loop, and vars
                    ##      is an array of expressions with the identifier and type for each of those
                    ##      local variables.
                    ## ```
    vars*: array[2, YR_EXPRESSION]
    vars_internal_count*: cint ## ```
                             ##   vars_internal_count is the number of variables used by the loop which are
                             ##      not defined by the rule itself but that are necessary for keeping the
                             ##      loop's state. One example is the iteration counter.
                             ## ```

  YR_COMPILER* {.bycopy, impyaraHdr, importc: "struct _YR_COMPILER".} = object
    arena*: ptr YR_ARENA ## ```
                      ##   Arena that contains the data generated by the compiled. The arena has
                      ##      the following buffers:
                      ##
                      ##        YR_SUMMARY_SECTION:
                      ##           A YR_SUMMARY struct.
                      ##        YR_RULES_TABLE:
                      ##           An array of YR_RULE structures, one per each rule.
                      ##        YR_STRINGS_TABLE:
                      ##           An array of YR_STRING structures, one per each string.
                      ##        YR_METAS_TABLE:
                      ##           An array of YR_META structures, one per each meta definition.
                      ##        YR_NAMESPACES_TABLE:
                      ##           An array of YR_NAMESPACE structures, one per each namespace.
                      ##        YR_EXTERNAL_VARIABLES_TABLE:
                      ##           An array of YR_EXTERNAL_VARIABLE structures, one per each external
                      ##           variable defined.
                      ##        YR_SZ_POOL:
                      ##           A collection of null-terminated strings. This buffer contains
                      ##           identifiers, literal strings, and in general any null-terminated
                      ##           string referenced by other data structures.
                      ##        YR_CODE_SECTION:
                      ##           The code for the condition section of all the rules. This is the
                      ##           code executed by yr_execute_code.
                      ##        YR_RE_CODE_SECTION:
                      ##           Similar to YR_CODE_SECTION, but it contains the code for regular
                      ##           expressions. This is the code executed by yr_re_exec and
                      ##           yr_re_fast_exec.
                      ##        YR_AC_TRANSITION_TABLE:
                      ##           An array of uint32_t containing the Aho-Corasick transition table.
                      ##           See comment in _yr_ac_build_transition_table for details.
                      ##        YR_AC_STATE_MATCHES_TABLE:
                      ##           An array of uint32_t with the same number of items than the transition
                      ##           table. If entry N in the transition table corresponds to some
                      ##           Aho-Corasick state, the N-th item in this array has the index within
                      ##           the matches pool where the list of matches for that state begins.
                      ##        YR_AC_STATE_MATCHES_POOL:
                      ##           An array of YR_AC_MATCH structures.
                      ## ```
    current_rule_idx*: uint32 ## ```
                            ##   Index of the rule being compiled in the array of YR_RULE structures
                            ##      stored in YR_RULES_TABLE. If this is MAX_UINT32 the compiler is not
                            ##      parsing a rule.
                            ## ```
    next_rule_idx*: uint32 ## ```
                         ##   Index of the rule that comes next during parsing.
                         ## ```
    current_string_idx*: uint32 ## ```
                              ##   Index of the string being compiled in the array of YR_STRING structures
                              ##      stored in YR_STRINGS_TABLE.
                              ## ```
    current_namespace_idx*: uint32 ## ```
                                 ##   Index of the current namespace in the array of YR_NAMESPACE structures
                                 ##      stored in YR_NAMESPACES_TABLE.
                                 ## ```
    current_meta_idx*: uint32 ## ```
                            ##   Index of the current meta in the array of YR_META structures stored in
                            ##      YR_METAS_TABLE.
                            ## ```
    rules*: ptr YR_RULES ## ```
                      ##   Pointer to a YR_RULES structure that represents the compiled rules. This
                      ##      is what yr_compiler_get_rules returns. Once these rules are generated you
                      ##      can't call any of the yr_compiler_add_xxx functions.
                      ## ```
    errors*: cint
    current_line*: cint
    last_error*: cint
    last_error_line*: cint
    error_recovery*: jmp_buf
    automaton*: ptr YR_AC_AUTOMATON
    rules_table*: ptr YR_HASH_TABLE
    objects_table*: ptr YR_HASH_TABLE
    strings_table*: ptr YR_HASH_TABLE
    sz_table*: ptr YR_HASH_TABLE ## ```
                              ##   Hash table that contains all the strings that has been written to the
                              ##      YR_SZ_POOL buffer in the compiler's arena. Values in the hash table are
                              ##      the offset within the YR_SZ_POOL where the string resides. This allows to
                              ##      know is some string has already been written in order to reuse instead of
                              ##      writting it again.
                              ## ```
    fixup_stack_head*: ptr YR_FIXUP
    num_namespaces*: cint
    loop*: array[4, YR_LOOP_CONTEXT]
    loop_index*: cint
    loop_for_of_var_index*: cint
    file_name_stack*: array[16, cstring]
    file_name_stack_ptr*: cint
    last_error_extra_info*: array[256, cchar]
    lex_buf*: array[8192, cchar]
    lex_buf_ptr*: cstring
    lex_buf_len*: cushort
    include_base_dir*: array[1024, cchar]
    user_data*: pointer
    incl_clbk_user_data*: pointer
    re_ast_clbk_user_data*: pointer
    callback*: YR_COMPILER_CALLBACK_FUNC
    include_callback*: YR_COMPILER_INCLUDE_CALLBACK_FUNC
    include_free*: YR_COMPILER_INCLUDE_FREE_FUNC
    re_ast_callback*: YR_COMPILER_RE_AST_CALLBACK_FUNC
    atoms_config*: YR_ATOMS_CONFIG

  YR_EXT_INITIALIZE_FUNC* {.importc, impyaraHdr.} = proc (module: ptr YR_MODULE): cint {.
      cdecl.}
  YR_EXT_FINALIZE_FUNC* {.importc, impyaraHdr.} = proc (module: ptr YR_MODULE): cint {.
      cdecl.}
  YR_EXT_DECLARATIONS_FUNC* {.importc, impyaraHdr.} = proc (
      module_object: ptr YR_OBJECT): cint {.cdecl.}
  YR_EXT_LOAD_FUNC* {.importc, impyaraHdr.} = proc (context: ptr YR_SCAN_CONTEXT;
      module_object: ptr YR_OBJECT; module_data: pointer; module_data_size: uint): cint {.
      cdecl.}
  YR_EXT_UNLOAD_FUNC* {.importc, impyaraHdr.} = proc (module_object: ptr YR_OBJECT): cint {.
      cdecl.}
  YR_SCANNER* {.importc, impyaraHdr.} = YR_SCAN_CONTEXT
var yr_scanner_scan_mem* {.importc: "_yr_scanner_scan_mem", impyaraHdr.}: proc (
    scanner: ptr YR_SCANNER; buffer: ptr uint8; buffer_size: uint): cint {.cdecl.}
proc xtoi*(hexstr: cstring): uint64 {.importc, cdecl, impyaraHdr.}
  ## ```
  ##   Other "compilers" and later versions of Microsoft Visual Studio C++ and
  ##      Borland C/C++ define the types in <stdint.h>
  ##      Cygwin already has these functions.
  ## ```
proc strlcpy*(dst: cstring; src: cstring; size: uint): uint {.importc, cdecl, impyaraHdr.}
proc strlcat*(dst: cstring; src: cstring; size: uint): uint {.importc, cdecl, impyaraHdr.}
proc memmem*(haystack: pointer; haystack_size: uint; needle: pointer; needle_size: uint): pointer {.
    importc, cdecl, impyaraHdr.}
proc strnlen_w*(w_str: cstring): cint {.importc, cdecl, impyaraHdr.}
proc strcmp_w*(w_str: cstring; str: cstring): cint {.importc, cdecl, impyaraHdr.}
proc strlcpy_w*(dst: cstring; w_src: cstring; n: uint): uint {.importc, cdecl, impyaraHdr.}
proc yr_filemap_map*(file_path: cstring; pmapped_file: ptr YR_MAPPED_FILE): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_filemap_map_fd*(file: cint; offset: clong; size: uint;
                       pmapped_file: ptr YR_MAPPED_FILE): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_filemap_map_ex*(file_path: cstring; offset: clong; size: uint;
                       pmapped_file: ptr YR_MAPPED_FILE): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_filemap_unmap*(pmapped_file: ptr YR_MAPPED_FILE) {.importc, cdecl, impyaraHdr.}
proc yr_filemap_unmap_fd*(pmapped_file: ptr YR_MAPPED_FILE) {.importc, cdecl,
    impyaraHdr.}
proc yr_stream_read*(`ptr`: pointer; size: uint; count: uint; stream: ptr YR_STREAM): uint {.
    importc, cdecl, impyaraHdr.}
proc yr_stream_write*(`ptr`: pointer; size: uint; count: uint; stream: ptr YR_STREAM): uint {.
    importc, cdecl, impyaraHdr.}
proc yr_arena_create*(num_buffers: cint; initial_buffer_size: uint;
                     arena: ptr ptr YR_ARENA): cint {.importc, cdecl, impyaraHdr.}
  ## ```
  ##   Creates an arena with the specified number of buffers and takes ownership of
  ##      it. Initially each buffer is empty, the first time that some data is written
  ##      into a buffer at least initial_buffer_size are reserved for the buffer.
  ## ```
proc yr_arena_acquire*(arena: ptr YR_ARENA) {.importc, cdecl, impyaraHdr.}
  ## ```
  ##   Takes ownership of the arena.
  ## ```
proc yr_arena_release*(arena: ptr YR_ARENA): cint {.importc, cdecl, impyaraHdr.}
  ## ```
  ##   Release ownership of the arena. If the number of owners drops to zero the
  ##      arena is destroyed and all its resources are freed.
  ## ```
proc yr_arena_ref_to_ptr*(arena: ptr YR_ARENA; `ref`: ptr YR_ARENA_REF): pointer {.
    importc, cdecl, impyaraHdr.}
  ## ```
  ##   Given a reference to some data within the arena, it returns a pointer to
  ##      the data. This pointer is valid only until the next call to any of the
  ##      functions that allocates space in the buffer where the data resides, like
  ##      yr_arena_allocate_xxx and yr_arena_write_xxx. These functions can cause
  ##      the buffer to be moved to different memory location and the pointer won't
  ##      valid any longer.
  ## ```
proc yr_arena_ptr_to_ref*(arena: ptr YR_ARENA; address: pointer;
                         `ref`: ptr YR_ARENA_REF): cint {.importc, cdecl, impyaraHdr.}
  ## ```
  ##   Given a pointer into the arena, it returns a reference to it. The reference
  ##      can be used with yr_arena_ref_to_ptr to obtain a pointer again. Unlike
  ##      pointers, references are during the arena's lifetime, even if the buffers
  ##      are moved to a different memory location.
  ## ```
proc yr_arena_get_ptr*(arena: ptr YR_ARENA; buffer_id: uint32; offset: yr_arena_off_t): pointer {.
    importc, cdecl, impyaraHdr.}
  ## ```
  ##   Given a buffer number and an offset within the buffer, returns a pointer
  ##      to that offset. The same limitations explained for yr_arena_ref_to_ptr
  ##      applies for the pointers returned by this function.
  ## ```
proc yr_arena_get_current_offset*(arena: ptr YR_ARENA; buffer_id: uint32): yr_arena_off_t {.
    importc, cdecl, impyaraHdr.}
proc yr_arena_allocate_memory*(arena: ptr YR_ARENA; buffer_id: uint32; size: uint;
                              `ref`: ptr YR_ARENA_REF): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_arena_allocate_zeroed_memory*(arena: ptr YR_ARENA; buffer_id: uint32;
                                     size: uint; `ref`: ptr YR_ARENA_REF): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_arena_allocate_struct*(arena: ptr YR_ARENA; buffer_id: uint32; size: uint;
                              `ref`: ptr YR_ARENA_REF): cint {.importc, cdecl,
    impyaraHdr, varargs.}
proc yr_arena_make_ptr_relocatable*(arena: ptr YR_ARENA; buffer_id: uint32): cint {.
    importc, cdecl, impyaraHdr, varargs.}
proc yr_arena_write_data*(arena: ptr YR_ARENA; buffer_id: uint32; data: pointer;
                         size: uint; `ref`: ptr YR_ARENA_REF): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_arena_write_string*(arena: ptr YR_ARENA; buffer_id: uint32; string: cstring;
                           `ref`: ptr YR_ARENA_REF): cint {.importc, cdecl, impyaraHdr.}
proc yr_arena_write_uint32*(arena: ptr YR_ARENA; buffer_id: uint32; integer: uint32;
                           `ref`: ptr YR_ARENA_REF): cint {.importc, cdecl, impyaraHdr.}
proc yr_arena_load_stream*(stream: ptr YR_STREAM; arena: ptr ptr YR_ARENA): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_arena_save_stream*(arena: ptr YR_ARENA; stream: ptr YR_STREAM): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_bitmask_find_non_colliding_offset*(a: ptr culong; b: ptr culong; len_a: uint32;
    len_b: uint32; off_a: ptr uint32): uint32 {.importc, cdecl, impyaraHdr.}
proc yr_hash*(seed: uint32; buffer: pointer; len: uint): uint32 {.importc, cdecl,
    impyaraHdr.}
proc yr_hash_table_create*(size: cint; table: ptr ptr YR_HASH_TABLE): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_hash_table_clean*(table: ptr YR_HASH_TABLE;
                         free_value: YR_HASH_TABLE_FREE_VALUE_FUNC) {.importc,
    cdecl, impyaraHdr.}
proc yr_hash_table_destroy*(table: ptr YR_HASH_TABLE;
                           free_value: YR_HASH_TABLE_FREE_VALUE_FUNC) {.importc,
    cdecl, impyaraHdr.}
proc yr_hash_table_lookup*(table: ptr YR_HASH_TABLE; key: cstring; ns: cstring): pointer {.
    importc, cdecl, impyaraHdr.}
proc yr_hash_table_remove*(table: ptr YR_HASH_TABLE; key: cstring; ns: cstring): pointer {.
    importc, cdecl, impyaraHdr.}
proc yr_hash_table_add*(table: ptr YR_HASH_TABLE; key: cstring; ns: cstring;
                       value: pointer): cint {.importc, cdecl, impyaraHdr.}
proc yr_hash_table_add_uint32*(table: ptr YR_HASH_TABLE; key: cstring; ns: cstring;
                              value: uint32): cint {.importc, cdecl, impyaraHdr.}
proc yr_hash_table_lookup_uint32*(table: ptr YR_HASH_TABLE; key: cstring; ns: cstring): uint32 {.
    importc, cdecl, impyaraHdr.}
proc yr_hash_table_lookup_raw_key*(table: ptr YR_HASH_TABLE; key: pointer;
                                  key_length: uint; ns: cstring): pointer {.importc,
    cdecl, impyaraHdr.}
proc yr_hash_table_remove_raw_key*(table: ptr YR_HASH_TABLE; key: pointer;
                                  key_length: uint; ns: cstring): pointer {.importc,
    cdecl, impyaraHdr.}
proc yr_hash_table_add_raw_key*(table: ptr YR_HASH_TABLE; key: pointer;
                               key_length: uint; ns: cstring; value: pointer): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_hash_table_add_uint32_raw_key*(table: ptr YR_HASH_TABLE; key: pointer;
                                      key_length: uint; ns: cstring; value: uint32): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_hash_table_lookup_uint32_raw_key*(table: ptr YR_HASH_TABLE; key: pointer;
    key_length: uint; ns: cstring): uint32 {.importc, cdecl, impyaraHdr.}
proc ss_compare*(s1: ptr SIZED_STRING; s2: ptr SIZED_STRING): cint {.importc, cdecl,
    impyaraHdr.}
proc ss_icompare*(s1: ptr SIZED_STRING; s2: ptr SIZED_STRING): cint {.importc, cdecl,
    impyaraHdr.}
proc ss_contains*(s1: ptr SIZED_STRING; s2: ptr SIZED_STRING): bool {.importc, cdecl,
    impyaraHdr.}
proc ss_icontains*(s1: ptr SIZED_STRING; s2: ptr SIZED_STRING): bool {.importc, cdecl,
    impyaraHdr.}
proc ss_startswith*(s1: ptr SIZED_STRING; s2: ptr SIZED_STRING): bool {.importc, cdecl,
    impyaraHdr.}
proc ss_istartswith*(s1: ptr SIZED_STRING; s2: ptr SIZED_STRING): bool {.importc, cdecl,
    impyaraHdr.}
proc ss_endswith*(s1: ptr SIZED_STRING; s2: ptr SIZED_STRING): bool {.importc, cdecl,
    impyaraHdr.}
proc ss_iendswith*(s1: ptr SIZED_STRING; s2: ptr SIZED_STRING): bool {.importc, cdecl,
    impyaraHdr.}
proc ss_dup*(s: ptr SIZED_STRING): ptr SIZED_STRING {.importc, cdecl, impyaraHdr.}
proc ss_new*(s: cstring): ptr SIZED_STRING {.importc, cdecl, impyaraHdr.}
proc ss_convert_to_wide*(s: ptr SIZED_STRING): ptr SIZED_STRING {.importc, cdecl,
    impyaraHdr.}
proc yr_stopwatch_start*(stopwatch: ptr YR_STOPWATCH) {.importc, cdecl, impyaraHdr.}
  ## ```
  ##   yr_stopwatch_start starts measuring time.
  ## ```
proc yr_stopwatch_elapsed_ns*(stopwatch: ptr YR_STOPWATCH): uint64 {.importc, cdecl,
    impyaraHdr.}
  ## ```
  ##   yr_stopwatch_elapsed_ns returns the number of nanoseconds elapsed
  ##      since the last call to yr_stopwatch_start.
  ## ```
proc yr_current_thread_id*(): YR_THREAD_ID {.importc, cdecl, impyaraHdr.}
proc yr_mutex_create*(a1: ptr YR_MUTEX): cint {.importc, cdecl, impyaraHdr.}
proc yr_mutex_destroy*(a1: ptr YR_MUTEX): cint {.importc, cdecl, impyaraHdr.}
proc yr_mutex_lock*(a1: ptr YR_MUTEX): cint {.importc, cdecl, impyaraHdr.}
proc yr_mutex_unlock*(a1: ptr YR_MUTEX): cint {.importc, cdecl, impyaraHdr.}
proc yr_thread_storage_create*(a1: ptr YR_THREAD_STORAGE_KEY): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_thread_storage_destroy*(a1: ptr YR_THREAD_STORAGE_KEY): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_thread_storage_set_value*(a1: ptr YR_THREAD_STORAGE_KEY; a2: pointer): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_thread_storage_get_value*(a1: ptr YR_THREAD_STORAGE_KEY): pointer {.importc,
    cdecl, impyaraHdr.}
  ## ```
  ##   Created by Victor Manuel Alvarez on 3/4/20.
  ## ```
proc yr_notebook_create*(page_size: uint; pool: ptr ptr YR_NOTEBOOK): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_notebook_destroy*(pool: ptr YR_NOTEBOOK): cint {.importc, cdecl, impyaraHdr.}
proc yr_notebook_alloc*(notebook: ptr YR_NOTEBOOK; size: uint): pointer {.importc,
    cdecl, impyaraHdr.}
proc yr_re_ast_create*(re_ast: ptr ptr RE_AST): cint {.importc, cdecl, impyaraHdr.}
proc yr_re_ast_destroy*(re_ast: ptr RE_AST) {.importc, cdecl, impyaraHdr.}
proc yr_re_ast_print*(re_ast: ptr RE_AST) {.importc, cdecl, impyaraHdr.}
proc yr_re_ast_extract_literal*(re_ast: ptr RE_AST): ptr SIZED_STRING {.importc, cdecl,
    impyaraHdr.}
proc yr_re_ast_contains_dot_star*(re_ast: ptr RE_AST): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_re_ast_split_at_chaining_point*(re_ast: ptr RE_AST;
                                       remainder_re_ast: ptr ptr RE_AST;
                                       min_gap: ptr int32; max_gap: ptr int32): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_re_ast_emit_code*(re_ast: ptr RE_AST; arena: ptr YR_ARENA; backwards_code: cint): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_re_node_create*(`type`: cint): ptr RE_NODE {.importc, cdecl, impyaraHdr.}
proc yr_re_node_destroy*(node: ptr RE_NODE) {.importc, cdecl, impyaraHdr.}
proc yr_re_node_append_child*(node: ptr RE_NODE; child: ptr RE_NODE) {.importc, cdecl,
    impyaraHdr.}
proc yr_re_node_prepend_child*(node: ptr RE_NODE; child: ptr RE_NODE) {.importc, cdecl,
    impyaraHdr.}
proc yr_re_exec*(context: ptr YR_SCAN_CONTEXT; code: ptr uint8; input_data: ptr uint8;
                input_forwards_size: uint; input_backwards_size: uint; flags: cint;
                callback: RE_MATCH_CALLBACK_FUNC; callback_args: pointer;
                matches: ptr cint): cint {.importc, cdecl, impyaraHdr.}
proc yr_re_fast_exec*(context: ptr YR_SCAN_CONTEXT; code: ptr uint8;
                     input_data: ptr uint8; input_forwards_size: uint;
                     input_backwards_size: uint; flags: cint;
                     callback: RE_MATCH_CALLBACK_FUNC; callback_args: pointer;
                     matches: ptr cint): cint {.importc, cdecl, impyaraHdr.}
proc yr_re_parse*(re_string: cstring; re_ast: ptr ptr RE_AST; error: ptr RE_ERROR): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_re_parse_hex*(hex_string: cstring; re_ast: ptr ptr RE_AST; error: ptr RE_ERROR): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_re_compile*(re_string: cstring; flags: cint; arena: ptr YR_ARENA;
                   `ref`: ptr YR_ARENA_REF; error: ptr RE_ERROR): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_re_match*(context: ptr YR_SCAN_CONTEXT; re: ptr RE; target: cstring): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_atoms_extract_from_re*(config: ptr YR_ATOMS_CONFIG; re_ast: ptr RE_AST;
                              modifier: YR_MODIFIER;
                              atoms: ptr ptr YR_ATOM_LIST_ITEM;
                              min_atom_quality: ptr cint): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_atoms_extract_from_string*(config: ptr YR_ATOMS_CONFIG; string: ptr uint8;
                                  string_length: cint; modifier: YR_MODIFIER;
                                  atoms: ptr ptr YR_ATOM_LIST_ITEM;
                                  min_atom_quality: ptr cint): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_atoms_extract_triplets*(re_node: ptr RE_NODE;
                               atoms: ptr ptr YR_ATOM_LIST_ITEM): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_atoms_heuristic_quality*(config: ptr YR_ATOMS_CONFIG; atom: ptr YR_ATOM): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_atoms_table_quality*(config: ptr YR_ATOMS_CONFIG; atom: ptr YR_ATOM): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_atoms_min_quality*(config: ptr YR_ATOMS_CONFIG;
                          atom_list: ptr YR_ATOM_LIST_ITEM): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_atoms_list_destroy*(list_head: ptr YR_ATOM_LIST_ITEM) {.importc, cdecl,
    impyaraHdr.}
proc yr_ac_automaton_create*(arena: ptr YR_ARENA; automaton: ptr ptr YR_AC_AUTOMATON): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_ac_automaton_destroy*(automaton: ptr YR_AC_AUTOMATON): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_ac_add_string*(automaton: ptr YR_AC_AUTOMATON; string: ptr YR_STRING;
                      string_idx: uint32; atom: ptr YR_ATOM_LIST_ITEM;
                      arena: ptr YR_ARENA): cint {.importc, cdecl, impyaraHdr.}
proc yr_ac_compile*(automaton: ptr YR_AC_AUTOMATON; arena: ptr YR_ARENA): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_ac_print_automaton*(automaton: ptr YR_AC_AUTOMATON) {.importc, cdecl,
    impyaraHdr.}
proc yr_compiler_push_file_name*(compiler: ptr YR_COMPILER; file_name: cstring): cint {.
    importc: "_yr_compiler_push_file_name", cdecl, impyaraHdr.}
proc yr_compiler_pop_file_name*(compiler: ptr YR_COMPILER) {.
    importc: "_yr_compiler_pop_file_name", cdecl, impyaraHdr.}
proc yr_compiler_get_var_frame*(compiler: ptr YR_COMPILER): cint {.
    importc: "_yr_compiler_get_var_frame", cdecl, impyaraHdr.}
proc yr_compiler_default_include_callback*(include_name: cstring;
    calling_rule_filename: cstring; calling_rule_namespace: cstring;
    user_data: pointer): cstring {.importc: "_yr_compiler_default_include_callback",
                                cdecl, impyaraHdr.}
proc yr_compiler_get_rule_by_idx*(compiler: ptr YR_COMPILER; rule_idx: uint32): ptr YR_RULE {.
    importc: "_yr_compiler_get_rule_by_idx", cdecl, impyaraHdr.}
proc yr_compiler_store_string*(compiler: ptr YR_COMPILER; string: cstring;
                              `ref`: ptr YR_ARENA_REF): cint {.
    importc: "_yr_compiler_store_string", cdecl, impyaraHdr.}
proc yr_compiler_store_data*(compiler: ptr YR_COMPILER; data: pointer;
                            data_length: uint; `ref`: ptr YR_ARENA_REF): cint {.
    importc: "_yr_compiler_store_data", cdecl, impyaraHdr.}
proc yr_compiler_create*(compiler: ptr ptr YR_COMPILER): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_compiler_destroy*(compiler: ptr YR_COMPILER) {.importc, cdecl, impyaraHdr.}
proc yr_compiler_set_callback*(compiler: ptr YR_COMPILER;
                              callback: YR_COMPILER_CALLBACK_FUNC;
                              user_data: pointer) {.importc, cdecl, impyaraHdr.}
proc yr_compiler_set_include_callback*(compiler: ptr YR_COMPILER; include_callback: YR_COMPILER_INCLUDE_CALLBACK_FUNC;
    include_free: YR_COMPILER_INCLUDE_FREE_FUNC; user_data: pointer) {.importc,
    cdecl, impyaraHdr.}
proc yr_compiler_set_re_ast_callback*(compiler: ptr YR_COMPILER; re_ast_callback: YR_COMPILER_RE_AST_CALLBACK_FUNC;
                                     user_data: pointer) {.importc, cdecl,
    impyaraHdr.}
proc yr_compiler_set_atom_quality_table*(compiler: ptr YR_COMPILER; table: pointer;
                                        entries: cint; warning_threshold: cuchar) {.
    importc, cdecl, impyaraHdr.}
proc yr_compiler_load_atom_quality_table*(compiler: ptr YR_COMPILER;
    filename: cstring; warning_threshold: cuchar): cint {.importc, cdecl, impyaraHdr.}
proc yr_compiler_add_file*(compiler: ptr YR_COMPILER; rules_file: File;
                          namespace_g: cstring; file_name: cstring): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_compiler_add_fd*(compiler: ptr YR_COMPILER; rules_fd: cint;
                        namespace_g: cstring; file_name: cstring): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_compiler_add_string*(compiler: ptr YR_COMPILER; rules_string: cstring;
                            namespace_g: cstring): cint {.importc, cdecl, impyaraHdr.}
proc yr_compiler_get_error_message*(compiler: ptr YR_COMPILER; buffer: cstring;
                                   buffer_size: cint): cstring {.importc, cdecl,
    impyaraHdr.}
proc yr_compiler_get_current_file_name*(compiler: ptr YR_COMPILER): cstring {.
    importc, cdecl, impyaraHdr.}
proc yr_compiler_define_integer_variable*(compiler: ptr YR_COMPILER;
    identifier: cstring; value: int64): cint {.importc, cdecl, impyaraHdr.}
proc yr_compiler_define_boolean_variable*(compiler: ptr YR_COMPILER;
    identifier: cstring; value: cint): cint {.importc, cdecl, impyaraHdr.}
proc yr_compiler_define_float_variable*(compiler: ptr YR_COMPILER;
                                       identifier: cstring; value: cdouble): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_compiler_define_string_variable*(compiler: ptr YR_COMPILER;
                                        identifier: cstring; value: cstring): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_compiler_get_rules*(compiler: ptr YR_COMPILER; rules: ptr ptr YR_RULES): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_scan_verify_match*(context: ptr YR_SCAN_CONTEXT; ac_match: ptr YR_AC_MATCH;
                          data: ptr uint8; data_size: uint; data_base: uint64;
                          offset: uint): cint {.importc, cdecl, impyaraHdr.}
proc yr_rules_scan_mem_blocks*(rules: ptr YR_RULES;
                              `iterator`: ptr YR_MEMORY_BLOCK_ITERATOR;
                              flags: cint; callback: YR_CALLBACK_FUNC;
                              user_data: pointer; timeout: cint): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_rules_scan_mem*(rules: ptr YR_RULES; buffer: ptr uint8; buffer_size: uint;
                       flags: cint; callback: YR_CALLBACK_FUNC; user_data: pointer;
                       timeout: cint): cint {.importc, cdecl, impyaraHdr.}
proc yr_rules_scan_file*(rules: ptr YR_RULES; filename: cstring; flags: cint;
                        callback: YR_CALLBACK_FUNC; user_data: pointer;
                        timeout: cint): cint {.importc, cdecl, impyaraHdr.}
proc yr_rules_scan_fd*(rules: ptr YR_RULES; fd: cint; flags: cint;
                      callback: YR_CALLBACK_FUNC; user_data: pointer; timeout: cint): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_rules_scan_proc*(rules: ptr YR_RULES; pid: cint; flags: cint;
                        callback: YR_CALLBACK_FUNC; user_data: pointer;
                        timeout: cint): cint {.importc, cdecl, impyaraHdr.}
proc yr_rules_save*(rules: ptr YR_RULES; filename: cstring): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_rules_save_stream*(rules: ptr YR_RULES; stream: ptr YR_STREAM): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_rules_load*(filename: cstring; rules: ptr ptr YR_RULES): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_rules_load_stream*(stream: ptr YR_STREAM; rules: ptr ptr YR_RULES): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_rules_destroy*(rules: ptr YR_RULES): cint {.importc, cdecl, impyaraHdr.}
proc yr_rules_define_integer_variable*(rules: ptr YR_RULES; identifier: cstring;
                                      value: int64): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_rules_define_boolean_variable*(rules: ptr YR_RULES; identifier: cstring;
                                      value: cint): cint {.importc, cdecl, impyaraHdr.}
proc yr_rules_define_float_variable*(rules: ptr YR_RULES; identifier: cstring;
                                    value: cdouble): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_rules_define_string_variable*(rules: ptr YR_RULES; identifier: cstring;
                                     value: cstring): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_rules_get_stats*(rules: ptr YR_RULES; stats: ptr YR_RULES_STATS): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_rule_disable*(rule: ptr YR_RULE) {.importc, cdecl, impyaraHdr.}
proc yr_rule_enable*(rule: ptr YR_RULE) {.importc, cdecl, impyaraHdr.}
proc yr_rules_from_arena*(arena: ptr YR_ARENA; rules: ptr ptr YR_RULES): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_execute_code*(context: ptr YR_SCAN_CONTEXT): cint {.importc, cdecl, impyaraHdr.}
proc yr_object_create*(`type`: int8; identifier: cstring; parent: ptr YR_OBJECT;
                      `object`: ptr ptr YR_OBJECT): cint {.importc, cdecl, impyaraHdr.}
proc yr_object_set_canary*(`object`: ptr YR_OBJECT; canary: cint) {.importc, cdecl,
    impyaraHdr.}
proc yr_object_function_create*(identifier: cstring; arguments_fmt: cstring;
                               return_fmt: cstring; `func`: YR_MODULE_FUNC;
                               parent: ptr YR_OBJECT; function: ptr ptr YR_OBJECT): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_object_from_external_variable*(external: ptr YR_EXTERNAL_VARIABLE;
                                      `object`: ptr ptr YR_OBJECT): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_object_destroy*(`object`: ptr YR_OBJECT) {.importc, cdecl, impyaraHdr.}
proc yr_object_copy*(`object`: ptr YR_OBJECT; object_copy: ptr ptr YR_OBJECT): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_object_lookup_field*(`object`: ptr YR_OBJECT; field_name: cstring): ptr YR_OBJECT {.
    importc, cdecl, impyaraHdr.}
proc yr_object_lookup*(root: ptr YR_OBJECT; flags: cint; pattern: cstring): ptr YR_OBJECT {.
    importc, cdecl, impyaraHdr, varargs.}
proc yr_object_has_undefined_value*(`object`: ptr YR_OBJECT; field: cstring): bool {.
    importc, cdecl, impyaraHdr, varargs.}
proc yr_object_get_float*(`object`: ptr YR_OBJECT; field: cstring): cdouble {.importc,
    cdecl, impyaraHdr, varargs.}
proc yr_object_get_integer*(`object`: ptr YR_OBJECT; field: cstring): int64 {.importc,
    cdecl, impyaraHdr, varargs.}
proc yr_object_get_string*(`object`: ptr YR_OBJECT; field: cstring): ptr SIZED_STRING {.
    importc, cdecl, impyaraHdr, varargs.}
proc yr_object_set_integer*(value: int64; `object`: ptr YR_OBJECT; field: cstring): cint {.
    importc, cdecl, impyaraHdr, varargs.}
proc yr_object_set_float*(value: cdouble; `object`: ptr YR_OBJECT; field: cstring): cint {.
    importc, cdecl, impyaraHdr, varargs.}
proc yr_object_set_string*(value: cstring; len: uint; `object`: ptr YR_OBJECT;
                          field: cstring): cint {.importc, cdecl, impyaraHdr, varargs.}
proc yr_object_array_length*(`object`: ptr YR_OBJECT): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_object_array_get_item*(`object`: ptr YR_OBJECT; flags: cint; index: cint): ptr YR_OBJECT {.
    importc, cdecl, impyaraHdr.}
proc yr_object_array_set_item*(`object`: ptr YR_OBJECT; item: ptr YR_OBJECT;
                              index: cint): cint {.importc, cdecl, impyaraHdr.}
proc yr_object_dict_get_item*(`object`: ptr YR_OBJECT; flags: cint; key: cstring): ptr YR_OBJECT {.
    importc, cdecl, impyaraHdr.}
proc yr_object_dict_set_item*(`object`: ptr YR_OBJECT; item: ptr YR_OBJECT;
                             key: cstring): cint {.importc, cdecl, impyaraHdr.}
proc yr_object_structure_set_member*(`object`: ptr YR_OBJECT; member: ptr YR_OBJECT): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_object_get_root*(`object`: ptr YR_OBJECT): ptr YR_OBJECT {.importc, cdecl,
    impyaraHdr.}
proc yr_object_print_data*(`object`: ptr YR_OBJECT; indent: cint;
                          print_identifier: cint) {.importc, cdecl, impyaraHdr.}
proc yr_initialize*(): cint {.importc, cdecl, impyaraHdr.}
proc yr_finalize*(): cint {.importc, cdecl, impyaraHdr.}
proc yr_set_configuration*(a1: YR_CONFIG_NAME; a2: pointer): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_get_configuration*(a1: YR_CONFIG_NAME; a2: pointer): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_modules_initialize*(): cint {.importc, cdecl, impyaraHdr.}
proc yr_modules_finalize*(): cint {.importc, cdecl, impyaraHdr.}
proc yr_modules_do_declarations*(module_name: cstring;
                                main_structure: ptr YR_OBJECT): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_modules_load*(module_name: cstring; context: ptr YR_SCAN_CONTEXT): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_modules_unload_all*(context: ptr YR_SCAN_CONTEXT): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_scanner_create*(rules: ptr YR_RULES; scanner: ptr ptr YR_SCANNER): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_scanner_destroy*(scanner: ptr YR_SCANNER) {.importc, cdecl, impyaraHdr.}
proc yr_scanner_set_callback*(scanner: ptr YR_SCANNER; callback: YR_CALLBACK_FUNC;
                             user_data: pointer) {.importc, cdecl, impyaraHdr.}
proc yr_scanner_set_timeout*(scanner: ptr YR_SCANNER; timeout: cint) {.importc, cdecl,
    impyaraHdr.}
proc yr_scanner_set_flags*(scanner: ptr YR_SCANNER; flags: cint) {.importc, cdecl,
    impyaraHdr.}
proc yr_scanner_define_integer_variable*(scanner: ptr YR_SCANNER;
                                        identifier: cstring; value: int64): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_scanner_define_boolean_variable*(scanner: ptr YR_SCANNER;
                                        identifier: cstring; value: cint): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_scanner_define_float_variable*(scanner: ptr YR_SCANNER; identifier: cstring;
                                      value: cdouble): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_scanner_define_string_variable*(scanner: ptr YR_SCANNER;
                                       identifier: cstring; value: cstring): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_scanner_scan_mem_blocks*(scanner: ptr YR_SCANNER;
                                `iterator`: ptr YR_MEMORY_BLOCK_ITERATOR): cint {.
    importc, cdecl, impyaraHdr.}
proc yr_scanner_scan_file*(scanner: ptr YR_SCANNER; filename: cstring): cint {.importc,
    cdecl, impyaraHdr.}
proc yr_scanner_scan_fd*(scanner: ptr YR_SCANNER; fd: cint): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_scanner_scan_proc*(scanner: ptr YR_SCANNER; pid: cint): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_scanner_last_error_rule*(scanner: ptr YR_SCANNER): ptr YR_RULE {.importc,
    cdecl, impyaraHdr.}
proc yr_scanner_last_error_string*(scanner: ptr YR_SCANNER): ptr YR_STRING {.importc,
    cdecl, impyaraHdr.}
proc yr_scanner_get_profiling_info*(scanner: ptr YR_SCANNER): ptr YR_RULE_PROFILING_INFO {.
    importc, cdecl, impyaraHdr.}
proc yr_scanner_reset_profiling_info*(scanner: ptr YR_SCANNER) {.importc, cdecl,
    impyaraHdr.}
proc yr_scanner_print_profiling_info*(scanner: ptr YR_SCANNER): cint {.importc, cdecl,
    impyaraHdr.}
proc yr_calloc*(count: uint; size: uint): pointer {.importc, cdecl, impyaraHdr.}
proc yr_malloc*(size: uint): pointer {.importc, cdecl, impyaraHdr.}
proc yr_realloc*(`ptr`: pointer; size: uint): pointer {.importc, cdecl, impyaraHdr.}
proc yr_free*(`ptr`: pointer) {.importc, cdecl, impyaraHdr.}
proc yr_strdup*(str: cstring): cstring {.importc, cdecl, impyaraHdr.}
proc yr_strndup*(str: cstring; n: uint): cstring {.importc, cdecl, impyaraHdr.}
proc yr_heap_alloc*(): cint {.importc, cdecl, impyaraHdr.}
proc yr_heap_free*(): cint {.importc, cdecl, impyaraHdr.}
{.pop.}