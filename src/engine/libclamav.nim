# Generated @ 2021-11-10T02:04:08+07:00
# Command line:
#   /home/dmknght/.nimble/pkgs/nimterop-#head/nimterop/toast --preprocess -m:c --recurse --pnim --nim:/usr/bin/nim /tmp/clamav/libclamav/clamav.h --includeDirs+=/tmp/clamav/libclamav -o /tmp/clamav.nim

# const 'STATBUF' has unsupported value 'struct stat'
# const 'CLAMSTAT' has unsupported value 'stat'
# const 'LSTAT' has unsupported value 'lstat'
# const 'FSTAT' has unsupported value 'fstat'
# const 'safe_open' has unsupported value 'open'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}
import macros
import posix

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


{.pragma: impclamavHdr, header: "clamav.h".}
{.experimental: "codeReordering".}

defineEnum(cl_error_t)
defineEnum(cl_engine_field)
defineEnum(bytecode_security)
defineEnum(bytecode_mode)
defineEnum(cl_msg)
const
  CL_SUCCESS* = (0).cl_error_t
  CL_CLEAN* = (0).cl_error_t
  CL_VIRUS* = (CL_SUCCESS + 1).cl_error_t
  CL_ENULLARG* = (CL_VIRUS + 1).cl_error_t
  CL_EARG* = (CL_ENULLARG + 1).cl_error_t
  CL_EMALFDB* = (CL_EARG + 1).cl_error_t
  CL_ECVD* = (CL_EMALFDB + 1).cl_error_t
  CL_EVERIFY* = (CL_ECVD + 1).cl_error_t
  CL_EUNPACK* = (CL_EVERIFY + 1).cl_error_t
  CL_EOPEN* = (CL_EUNPACK + 1).cl_error_t
  CL_ECREAT* = (CL_EOPEN + 1).cl_error_t
  CL_EUNLINK* = (CL_ECREAT + 1).cl_error_t
  CL_ESTAT* = (CL_EUNLINK + 1).cl_error_t
  CL_EREAD* = (CL_ESTAT + 1).cl_error_t
  CL_ESEEK* = (CL_EREAD + 1).cl_error_t
  CL_EWRITE* = (CL_ESEEK + 1).cl_error_t
  CL_EDUP* = (CL_EWRITE + 1).cl_error_t
  CL_EACCES* = (CL_EDUP + 1).cl_error_t
  CL_ETMPFILE* = (CL_EACCES + 1).cl_error_t
  CL_ETMPDIR* = (CL_ETMPFILE + 1).cl_error_t
  CL_EMAP* = (CL_ETMPDIR + 1).cl_error_t
  CL_EMEM* = (CL_EMAP + 1).cl_error_t
  CL_ETIMEOUT* = (CL_EMEM + 1).cl_error_t
  CL_BREAK* = (CL_ETIMEOUT + 1).cl_error_t
  CL_EMAXREC* = (CL_BREAK + 1).cl_error_t
  CL_EMAXSIZE* = (CL_EMAXREC + 1).cl_error_t
  CL_EMAXFILES* = (CL_EMAXSIZE + 1).cl_error_t
  CL_EFORMAT* = (CL_EMAXFILES + 1).cl_error_t
  CL_EPARSE* = (CL_EFORMAT + 1).cl_error_t
  CL_EBYTECODE* = (CL_EPARSE + 1).cl_error_t
  CL_EBYTECODE_TESTFAIL* = (CL_EBYTECODE + 1).cl_error_t
  CL_ELOCK* = (CL_EBYTECODE_TESTFAIL + 1).cl_error_t
  CL_EBUSY* = (CL_ELOCK + 1).cl_error_t
  CL_ESTATE* = (CL_EBUSY + 1).cl_error_t
  CL_VERIFIED* = (CL_ESTATE + 1).cl_error_t
  CL_ERROR* = (CL_VERIFIED + 1).cl_error_t
  CL_ELAST_ERROR* = (CL_ERROR + 1).cl_error_t
  CL_ENGINE_MAX_SCANSIZE* = (0).cl_engine_field
  CL_ENGINE_MAX_FILESIZE* = (CL_ENGINE_MAX_SCANSIZE + 1).cl_engine_field
  CL_ENGINE_MAX_RECURSION* = (CL_ENGINE_MAX_FILESIZE + 1).cl_engine_field
  CL_ENGINE_MAX_FILES* = (CL_ENGINE_MAX_RECURSION + 1).cl_engine_field
  CL_ENGINE_MIN_CC_COUNT* = (CL_ENGINE_MAX_FILES + 1).cl_engine_field
  CL_ENGINE_MIN_SSN_COUNT* = (CL_ENGINE_MIN_CC_COUNT + 1).cl_engine_field
  CL_ENGINE_PUA_CATEGORIES* = (CL_ENGINE_MIN_SSN_COUNT + 1).cl_engine_field
  CL_ENGINE_DB_OPTIONS* = (CL_ENGINE_PUA_CATEGORIES + 1).cl_engine_field
  CL_ENGINE_DB_VERSION* = (CL_ENGINE_DB_OPTIONS + 1).cl_engine_field
  CL_ENGINE_DB_TIME* = (CL_ENGINE_DB_VERSION + 1).cl_engine_field
  CL_ENGINE_AC_ONLY* = (CL_ENGINE_DB_TIME + 1).cl_engine_field
  CL_ENGINE_AC_MINDEPTH* = (CL_ENGINE_AC_ONLY + 1).cl_engine_field
  CL_ENGINE_AC_MAXDEPTH* = (CL_ENGINE_AC_MINDEPTH + 1).cl_engine_field
  CL_ENGINE_TMPDIR* = (CL_ENGINE_AC_MAXDEPTH + 1).cl_engine_field
  CL_ENGINE_KEEPTMP* = (CL_ENGINE_TMPDIR + 1).cl_engine_field
  CL_ENGINE_BYTECODE_SECURITY* = (CL_ENGINE_KEEPTMP + 1).cl_engine_field
  CL_ENGINE_BYTECODE_TIMEOUT* = (CL_ENGINE_BYTECODE_SECURITY + 1).cl_engine_field
  CL_ENGINE_BYTECODE_MODE* = (CL_ENGINE_BYTECODE_TIMEOUT + 1).cl_engine_field
  CL_ENGINE_MAX_EMBEDDEDPE* = (CL_ENGINE_BYTECODE_MODE + 1).cl_engine_field
  CL_ENGINE_MAX_HTMLNORMALIZE* = (CL_ENGINE_MAX_EMBEDDEDPE + 1).cl_engine_field
  CL_ENGINE_MAX_HTMLNOTAGS* = (CL_ENGINE_MAX_HTMLNORMALIZE + 1).cl_engine_field
  CL_ENGINE_MAX_SCRIPTNORMALIZE* = (CL_ENGINE_MAX_HTMLNOTAGS + 1).cl_engine_field
  CL_ENGINE_MAX_ZIPTYPERCG* = (CL_ENGINE_MAX_SCRIPTNORMALIZE + 1).cl_engine_field
  CL_ENGINE_FORCETODISK* = (CL_ENGINE_MAX_ZIPTYPERCG + 1).cl_engine_field
  CL_ENGINE_DISABLE_CACHE* = (CL_ENGINE_FORCETODISK + 1).cl_engine_field
  CL_ENGINE_DISABLE_PE_STATS* = (CL_ENGINE_DISABLE_CACHE + 1).cl_engine_field
  CL_ENGINE_STATS_TIMEOUT* = (CL_ENGINE_DISABLE_PE_STATS + 1).cl_engine_field
  CL_ENGINE_MAX_PARTITIONS* = (CL_ENGINE_STATS_TIMEOUT + 1).cl_engine_field
  CL_ENGINE_MAX_ICONSPE* = (CL_ENGINE_MAX_PARTITIONS + 1).cl_engine_field
  CL_ENGINE_MAX_RECHWP3* = (CL_ENGINE_MAX_ICONSPE + 1).cl_engine_field
  CL_ENGINE_MAX_SCANTIME* = (CL_ENGINE_MAX_RECHWP3 + 1).cl_engine_field
  CL_ENGINE_PCRE_MATCH_LIMIT* = (CL_ENGINE_MAX_SCANTIME + 1).cl_engine_field
  CL_ENGINE_PCRE_RECMATCH_LIMIT* = (CL_ENGINE_PCRE_MATCH_LIMIT + 1).cl_engine_field
  CL_ENGINE_PCRE_MAX_FILESIZE* = (CL_ENGINE_PCRE_RECMATCH_LIMIT + 1).cl_engine_field
  CL_ENGINE_DISABLE_PE_CERTS* = (CL_ENGINE_PCRE_MAX_FILESIZE + 1).cl_engine_field
  CL_ENGINE_PE_DUMPCERTS* = (CL_ENGINE_DISABLE_PE_CERTS + 1).cl_engine_field
  CL_BYTECODE_TRUST_ALL* = (0).bytecode_security
  CL_BYTECODE_TRUST_SIGNED* = (CL_BYTECODE_TRUST_ALL + 1).bytecode_security
  CL_BYTECODE_TRUST_NOTHING* = (CL_BYTECODE_TRUST_SIGNED + 1).bytecode_security
  CL_BYTECODE_MODE_AUTO* = (0).bytecode_mode
  CL_BYTECODE_MODE_JIT* = (CL_BYTECODE_MODE_AUTO + 1).bytecode_mode
  CL_BYTECODE_MODE_INTERPRETER* = (CL_BYTECODE_MODE_JIT + 1).bytecode_mode
  CL_BYTECODE_MODE_TEST* = (CL_BYTECODE_MODE_INTERPRETER + 1).bytecode_mode
  CL_BYTECODE_MODE_OFF* = (CL_BYTECODE_MODE_TEST + 1).bytecode_mode
  CL_MSG_INFO_VERBOSE* = (32).cl_msg
  CL_MSG_WARN* = (64).cl_msg
  CL_MSG_ERROR* = (128).cl_msg

const
  STAT64_BLACKLIST* = 1
  CL_COUNT_PRECISION* = 4096
  CL_DB_PHISHING* = 0x00000002
  CL_DB_PHISHING_URLS* = 0x00000008
  CL_DB_PUA* = 0x00000010
  CL_DB_CVDNOTMP* = 0x00000020
  CL_DB_OFFICIAL* = 0x00000040
  CL_DB_PUA_MODE* = 0x00000080
  CL_DB_PUA_INCLUDE* = 0x00000100
  CL_DB_PUA_EXCLUDE* = 0x00000200
  CL_DB_COMPILED* = 0x00000400
  CL_DB_DIRECTORY* = 0x00000800
  CL_DB_OFFICIAL_ONLY* = 0x00001000
  CL_DB_BYTECODE* = 0x00002000
  CL_DB_SIGNED* = 0x00004000
  CL_DB_BYTECODE_UNSIGNED* = 0x00008000
  CL_DB_UNSIGNED* = 0x00010000
  CL_DB_BYTECODE_STATS* = 0x00020000
  CL_DB_ENHANCED* = 0x00040000
  CL_DB_PCRE_STATS* = 0x00080000
  CL_DB_YARA_EXCLUDE* = 0x00100000
  CL_DB_YARA_ONLY* = 0x00200000
  CL_DB_STDOPT* = (CL_DB_PHISHING or typeof(CL_DB_PHISHING)(CL_DB_PHISHING_URLS) or
      typeof(CL_DB_PHISHING)(CL_DB_BYTECODE))
  CL_SCAN_GENERAL_ALLMATCHES* = 0x00000001
  CL_SCAN_GENERAL_COLLECT_METADATA* = 0x00000002
  CL_SCAN_GENERAL_HEURISTICS* = 0x00000004
  CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE* = 0x00000008
  CL_SCAN_GENERAL_UNPRIVILEGED* = 0x00000010
  CL_SCAN_PARSE_ARCHIVE* = 0x00000001
  CL_SCAN_PARSE_ELF* = 0x00000002
  CL_SCAN_PARSE_PDF* = 0x00000004
  CL_SCAN_PARSE_SWF* = 0x00000008
  CL_SCAN_PARSE_HWP3* = 0x00000010
  CL_SCAN_PARSE_XMLDOCS* = 0x00000020
  CL_SCAN_PARSE_MAIL* = 0x00000040
  CL_SCAN_PARSE_OLE2* = 0x00000080
  CL_SCAN_PARSE_HTML* = 0x00000100
  CL_SCAN_PARSE_PE* = 0x00000200
  CL_SCAN_HEURISTIC_BROKEN* = 0x00000002
  CL_SCAN_HEURISTIC_EXCEEDS_MAX* = 0x00000004
  CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH* = 0x00000008
  CL_SCAN_HEURISTIC_PHISHING_CLOAK* = 0x00000010
  CL_SCAN_HEURISTIC_MACROS* = 0x00000020
  CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE* = 0x00000040
  CL_SCAN_HEURISTIC_ENCRYPTED_DOC* = 0x00000080
  CL_SCAN_HEURISTIC_PARTITION_INTXN* = 0x00000100
  CL_SCAN_HEURISTIC_STRUCTURED* = 0x00000200
  CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL* = 0x00000400
  CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED* = 0x00000800
  CL_SCAN_HEURISTIC_STRUCTURED_CC* = 0x00001000
  CL_SCAN_HEURISTIC_BROKEN_MEDIA* = 0x00002000
  CL_SCAN_MAIL_PARTIAL_MESSAGE* = 0x00000001
  CL_SCAN_DEV_COLLECT_SHA* = 0x00000001
  CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO* = 0x00000002
  CL_COUNTSIGS_OFFICIAL* = 0x00000001
  CL_COUNTSIGS_UNOFFICIAL* = 0x00000002
  CL_COUNTSIGS_ALL* = (CL_COUNTSIGS_OFFICIAL or
      typeof(CL_COUNTSIGS_OFFICIAL)(CL_COUNTSIGS_UNOFFICIAL))
  ENGINE_OPTIONS_NONE* = 0x00000000
  ENGINE_OPTIONS_DISABLE_CACHE* = 0x00000001
  ENGINE_OPTIONS_FORCE_TO_DISK* = 0x00000002
  ENGINE_OPTIONS_DISABLE_PE_STATS* = 0x00000004
  ENGINE_OPTIONS_DISABLE_PE_CERTS* = 0x00000008
  ENGINE_OPTIONS_PE_DUMPCERTS* = 0x00000010
  CL_INIT_DEFAULT* = 0x00000000
  MD5_HASH_SIZE* = 16
  SHA1_HASH_SIZE* = 20
  SHA256_HASH_SIZE* = 32
  SHA384_HASH_SIZE* = 48
  SHA512_HASH_SIZE* = 64
type
  cl_scan_options* {.bycopy, impclamavHdr, importc: "struct cl_scan_options".} = object
    general*: uint32
    parse*: uint32
    heuristic*: uint32
    mail*: uint32
    dev*: uint32

  cl_engine* {.incompleteStruct, impclamavHdr, importc: "struct cl_engine".} = object
  cl_settings* {.incompleteStruct, impclamavHdr, importc: "struct cl_settings".} = object
  cli_section_hash* {.bycopy, impclamavHdr, importc: "struct cli_section_hash".} = object
    md5*: array[16, uint8]
    len*: uint

  cli_stats_sections* {.bycopy, impclamavHdr,
                        importc: "struct cli_stats_sections".} = object
    nsections*: uint
    sections*: ptr cli_section_hash

  stats_section_t* {.importc, impclamavHdr.} = cli_stats_sections
  clcb_pre_cache* {.importc, impclamavHdr.} = proc (fd: cint; `type`: cstring;
      context: pointer): cl_error_t {.cdecl.}
  clcb_pre_scan* {.importc, impclamavHdr.} = proc (fd: cint; `type`: cstring;
      context: pointer): cl_error_t {.cdecl.}
#[
 * @brief File inspection callback.
 *
 * DISCLAIMER: This interface is to be considered unstable while we continue to evaluate it.
 * We may change this interface in the future.
 *
 * Called for each NEW file (inner and outer).
 * Provides capability to record embedded file information during a scan.
 *
 * @param fd                  Current file descriptor which is about to be scanned.
 * @param type                Current file type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE").
 * @param ancestors           An array of ancestors filenames of size `recursion_level`. filenames may be NULL.
 * @param parent_file_size    Parent file size.
 * @param file_name           Current file name, or NULL if the file does not have a name or ClamAV failed to record the name.
 * @param file_size           Current file size.
 * @param file_buffer         Current file buffer pointer.
 * @param recursion_level     Recursion level / depth of the current file.
 * @param layer_attributes    See LAYER_ATTRIBUTES_* flags.
 * @param context             Opaque application provided data.
 * @return                    CL_CLEAN = File is scanned.
 * @return                    CL_BREAK = Whitelisted by callback - file is skipped and marked as clean.
 * @return                    CL_VIRUS = Blacklisted by callback - file is skipped and marked as infected.
]#
  clcb_file_inspection* {.importc, impclamavHdr.} = proc (fd: cint; `type`: cstring; ancestors: ptr cstring; parent_file_size: uint; file_name: cstring; file_size: uint; file_buffer: cstring; recursion_level: uint32; layer_attributes: uint32; context: pointer): cl_error_t {.cdecl.}
  clcb_post_scan* {.importc, impclamavHdr.} = proc (fd: cint; result: cint;
      virname: cstring; context: pointer): cl_error_t {.cdecl.}
  clcb_virus_found* {.importc, impclamavHdr.} = proc (fd: cint;
      virname: cstring; context: pointer) {.cdecl.}
  clcb_sigload* {.importc, impclamavHdr.} = proc (`type`: cstring;
      name: cstring; custom: cuint; context: pointer): cint {.cdecl.}
  clcb_msg* {.importc, impclamavHdr.} = proc (severity: cl_msg;
      fullmsg: cstring; msg: cstring; context: pointer) {.cdecl.}
  clcb_hash* {.importc, impclamavHdr.} = proc (fd: cint; size: culonglong;
      md5: ptr uint8; virname: cstring; context: pointer) {.cdecl.}
  clcb_meta* {.importc, impclamavHdr.} = proc (container_type: cstring;
      fsize_container: culong; filename: cstring; fsize_real: culong;
      is_encrypted: cint; filepos_container: cuint; context: pointer): cl_error_t {.
      cdecl.}
  clcb_file_props* {.importc, impclamavHdr.} = proc (j_propstr: cstring;
      rc: cint; cbdata: pointer): cint {.cdecl.}
  clcb_stats_add_sample* {.importc, impclamavHdr.} = proc (virname: cstring;
      md5: ptr uint8; size: uint; sections: ptr stats_section_t;
      cbdata: pointer) {.cdecl.}
  clcb_stats_remove_sample* {.importc, impclamavHdr.} = proc (virname: cstring;
      md5: ptr uint8; size: uint; cbdata: pointer) {.cdecl.}
  clcb_stats_decrement_count* {.importc, impclamavHdr.} = proc (
      virname: cstring; md5: ptr uint8; size: uint; cbdata: pointer) {.cdecl.}
  clcb_stats_submit* {.importc, impclamavHdr.} = proc (engine: ptr cl_engine;
      cbdata: pointer) {.cdecl.}
  clcb_stats_flush* {.importc, impclamavHdr.} = proc (engine: ptr cl_engine;
      cbdata: pointer) {.cdecl.}
  clcb_stats_get_num* {.importc, impclamavHdr.} = proc (cbdata: pointer): uint {.
      cdecl.}
  clcb_stats_get_size* {.importc, impclamavHdr.} = proc (cbdata: pointer): uint {.
      cdecl.}
  clcb_stats_get_hostid* {.importc, impclamavHdr.} = proc (cbdata: pointer): cstring {.
      cdecl.}
  cl_cvd* {.bycopy, impclamavHdr, importc: "struct cl_cvd".} = object
    time*: cstring
    version*: cuint
    sigs*: cuint
    fl*: cuint
    md5*: cstring
    dsig*: cstring
    builder*: cstring
    stime*: cuint
  
  cl_stat* {.bycopy, impclamavHdr, importc: "struct cl_stat".} = object
    dir*: cstring
    stattab*: ptr Stat
    statdname*: ptr cstring
    entries*: cuint

  cl_fmap* {.incompleteStruct, impclamavHdr, importc: "struct cl_fmap".} = object
  cl_fmap_t* {.importc, impclamavHdr.} = cl_fmap
  clcb_pread* {.importc, impclamavHdr.} = proc (handle: pointer; buf: pointer;
      count: uint; offset: clong): clong {.cdecl.}
proc cl_debug*() {.importc, cdecl, impclamavHdr.}
  ## ```
  ##   ----------------------------------------------------------------------------
  ##    Enable global libclamav features.
  ##    
  ##     
  ##    @brief Enable debug messages
  ## ```
proc cl_always_gen_section_hash*() {.importc, cdecl, impclamavHdr.}
  ## ```
  ##   @brief Set libclamav to always create section hashes for PE files.
  ##   
  ##    Section hashes are used in .mdb signature.
  ## ```
proc cl_initialize_crypto*(): cint {.importc, cdecl, impclamavHdr.}
  ## ```
  ##   ----------------------------------------------------------------------------
  ##    Scan engine functions.
  ##    
  ##     
  ##    @brief This function initializes the openssl crypto system.
  ##   
  ##    Called by cl_init() and does not need to be cleaned up as de-init
  ##    is handled automatically by openssl 1.0.2.h and 1.1.0
  ##   
  ##    @return Always returns 0
  ## ```
proc cl_cleanup_crypto*() {.importc, cdecl, impclamavHdr.}
  ## ```
                                                          ##   @brief This is a deprecated function that used to clean up ssl crypto inits.
                                                          ##   
                                                          ##    Call to EVP_cleanup() has been removed since cleanup is now handled by
                                                          ##    auto-deinit as of openssl 1.0.2h and 1.1.0
                                                          ## ```
proc cl_init*(initoptions: cuint): cl_error_t {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                              ##   @brief Initialize the ClamAV library.
                                                                              ##   
                                                                              ##    @param initoptions   Unused.
                                                                              ##    @return cl_error_t   CL_SUCCESS if everything initalized correctly.
                                                                              ## ```
proc cl_engine_new*(): ptr cl_engine {.importc, cdecl, impclamavHdr.}
  ## ```
  ##   @brief Allocate a new scanning engine and initialize default settings.
  ##   
  ##    The engine should be freed with cl_engine_free().
  ##   
  ##    @return struct cl_engine* Pointer to the scanning engine.
  ## ```
proc cl_engine_set_num*(engine: ptr cl_engine; field: cl_engine_field;
                        num: clonglong): cl_error_t {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Set a numerical engine option.
                  ##   
                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                  ##   
                  ##    @param engine            An initialized scan engine.
                  ##    @param cl_engine_field   A CL_ENGINE option.
                  ##    @param num               The new engine option value.
                  ##    @return cl_error_t       CL_SUCCESS if successfully set.
                  ##    @return cl_error_t       CL_EARG if the field number was incorrect.
                  ##    @return cl_error_t       CL_ENULLARG null arguments were provided.
                  ## ```
proc cl_engine_get_num*(engine: ptr cl_engine; field: cl_engine_field;
                        err: ptr cint): clonglong {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                                  ##   @brief Get a numerical engine option.
                                                                                  ##   
                                                                                  ##    @param engine            An initialized scan engine.
                                                                                  ##    @param cl_engine_field   A CL_ENGINE option.
                                                                                  ##    @param err               (optional) A cl_error_t status code.
                                                                                  ##    @return long long        The numerical option value.
                                                                                  ## ```
proc cl_engine_set_str*(engine: ptr cl_engine; field: cl_engine_field;
                        str: cstring): cl_error_t {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                                  ##   @brief Set a string engine option.
                                                                                  ##   
                                                                                  ##    If the string option has already been set, the existing string will be free'd
                                                                                  ##    and the new string will replace it.
                                                                                  ##   
                                                                                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                                                                  ##   
                                                                                  ##    @param engine            An initialized scan engine.
                                                                                  ##    @param cl_engine_field   A CL_ENGINE option.
                                                                                  ##    @param str               The new engine option value.
                                                                                  ##    @return cl_error_t       CL_SUCCESS if successfully set.
                                                                                  ##    @return cl_error_t       CL_EARG if the field number was incorrect.
                                                                                  ##    @return cl_error_t       CL_EMEM if a memory allocation error occurred.
                                                                                  ##    @return cl_error_t       CL_ENULLARG null arguments were provided.
                                                                                  ## ```
proc cl_engine_get_str*(engine: ptr cl_engine; field: cl_engine_field;
                        err: ptr cint): cstring {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                                ##   @brief Get a string engine option.
                                                                                ##   
                                                                                ##    @param engine            An initialized scan engine.
                                                                                ##    @param cl_engine_field   A CL_ENGINE option.
                                                                                ##    @param err               (optional) A cl_error_t status code.
                                                                                ##    @return const char     The string option value.
                                                                                ## ```
proc cl_engine_settings_copy*(engine: ptr cl_engine): ptr cl_settings {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   @brief Copy the settings from an existing scan engine.
                         ##   
                         ##    The cl_settings pointer is allocated and must be freed with cl_engine_settings_free().
                         ##   
                         ##    @param engine                An configured scan engine.
                         ##    @return struct cl_settings*  The settings.
                         ## ```
proc cl_engine_settings_apply*(engine: ptr cl_engine; settings: ptr cl_settings): cl_error_t {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Apply settings from a settings structure to a scan engine.
                                  ##   
                                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                  ##   
                                  ##    @param engine        A scan engine.
                                  ##    @param settings      The settings.
                                  ##    @return cl_error_t   CL_SUCCESS if successful.
                                  ##    @return cl_error_t   CL_EMEM if a memory allocation error occurred.
                                  ## ```
proc cl_engine_settings_free*(settings: ptr cl_settings): cl_error_t {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   @brief Free a settings struct pointer.
                         ##   
                         ##    @param settings      The settings struct pointer.
                         ##    @return cl_error_t   CL_SUCCESS if successful.
                         ##    @return cl_error_t   CL_ENULLARG null arguments were provided.
                         ## ```
proc cl_engine_compile*(engine: ptr cl_engine): cl_error_t {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Prepare the scanning engine.
                  ##   
                  ##    Called this after all required databases have been loaded and settings have
                  ##    been applied.
                  ##   
                  ##    @param engine        A scan engine.
                  ##    @return cl_error_t   CL_SUCCESS if successful.
                  ##    @return cl_error_t   CL_ENULLARG null arguments were provided.
                  ## ```
proc cl_engine_addref*(engine: ptr cl_engine): cl_error_t {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Add a reference count to the engine.
                  ##   
                  ##    Thread safety mechanism so that the engine is not free'd by another thread.
                  ##   
                  ##    The engine is initialized with refcount = 1, so this only needs to be called
                  ##    for additional scanning threads.
                  ##   
                  ##    @param engine        A scan engine.
                  ##    @return cl_error_t   CL_SUCCESS if successful.
                  ##    @return cl_error_t   CL_ENULLARG null arguments were provided.
                  ## ```
proc cl_engine_free*(engine: ptr cl_engine): cl_error_t {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Free an engine.
                  ##   
                  ##    Will lower the reference count on an engine. If the reference count hits
                  ##    zero, the engine will be freed.
                  ##   
                  ##    @param engine        A scan engine.
                  ##    @return cl_error_t   CL_SUCCESS if successful.
                  ##    @return cl_error_t   CL_ENULLARG null arguments were provided.
                  ## ```
proc cl_engine_set_clcb_pre_cache*(engine: ptr cl_engine;
                                   callback: clcb_pre_cache) {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Set a custom pre-cache callback function.
                  ##   
                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                  ##   
                  ##    @param engine    The initialized scanning engine.
                  ##    @param callback  The callback function pointer.
                  ## ```
proc cl_engine_set_clcb_pre_scan*(engine: ptr cl_engine; callback: clcb_pre_scan) {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Set a custom pre-scan callback function.
                                  ##   
                                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                  ##   
                                  ##    @param engine    The initialized scanning engine.
                                  ##    @param callback  The callback function pointer.
                                  ## ```

proc cl_engine_set_clcb_file_inspection*(engine: ptr cl_engine; callback: clcb_file_inspection) {.importc, cdecl, impclamavHdr.}

proc cl_engine_set_clcb_post_scan*(engine: ptr cl_engine;
                                   callback: clcb_post_scan) {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Set a custom post-scan callback function.
                  ##   
                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                  ##   
                  ##    @param engine    The initialized scanning engine.
                  ##    @param callback  The callback function pointer.
                  ## ```
proc cl_engine_set_clcb_virus_found*(engine: ptr cl_engine;
                                     callback: clcb_virus_found) {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   @brief Set a custom virus-found callback function.
                         ##   
                         ##    Caution: changing options for an engine that is in-use is not thread-safe!
                         ##   
                         ##    @param engine    The initialized scanning engine.
                         ##    @param callback  The callback function pointer.
                         ## ```
proc cl_engine_set_clcb_sigload*(engine: ptr cl_engine; callback: clcb_sigload;
                                 context: pointer) {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Set a custom signature-load callback function.
                  ##   
                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                  ##   
                  ##    @param engine    The initialized scanning engine.
                  ##    @param callback  The callback function pointer.
                  ##    @param context   Opaque application provided data.
                  ## ```
proc cl_set_clcb_msg*(callback: clcb_msg) {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                          ##   @brief Set a custom logging message callback function for all of libclamav.
                                                                          ##   
                                                                          ##    @param callback  The callback function pointer.
                                                                          ## ```
proc cl_engine_set_clcb_hash*(engine: ptr cl_engine; callback: clcb_hash) {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Set a custom hash stats callback function.
                                  ##   
                                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                  ##   
                                  ##    @param engine    The initialized scanning engine.
                                  ##    @param callback  The callback function pointer.
                                  ## ```
proc cl_engine_set_clcb_meta*(engine: ptr cl_engine; callback: clcb_meta) {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Set a custom archive metadata matching callback function.
                                  ##   
                                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                  ##   
                                  ##    @param engine    The initialized scanning engine.
                                  ##    @param callback  The callback function pointer.
                                  ## ```
proc cl_engine_set_clcb_file_props*(engine: ptr cl_engine;
                                    callback: clcb_file_props) {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Set a custom file properties callback function.
                  ##   
                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                  ##   
                  ##    @param engine    The initialized scanning engine.
                  ##    @param callback  The callback function pointer.
                  ## ```
proc cl_engine_set_stats_set_cbdata*(engine: ptr cl_engine; cbdata: pointer) {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   ----------------------------------------------------------------------------
                                  ##    Statistics/telemetry gathering callbacks.
                                  ##   
                                  ##    The statistics callback functions may be used to implement a telemetry
                                  ##    gathering feature.
                                  ##   
                                  ##    The structure definition for cbdata is entirely up to the caller, as are
                                  ##    the implementations of each of the callback functions defined below.
                                  ##    
                                  ##     
                                  ##    @brief Set a pointer the caller-defined cbdata structure.
                                  ##   
                                  ##    The data must persist at least until clcb_stats_submit() is called, or
                                  ##    clcb_stats_flush() is called (optional).
                                  ##   
                                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                  ##   
                                  ##    @param engine The scanning engine.
                                  ##    @param cbdata The statistics data. Probably a pointer to a malloc'd struct.
                                  ## ```
proc cl_engine_set_clcb_stats_add_sample*(engine: ptr cl_engine;
    callback: clcb_stats_add_sample) {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                     ##   @brief Set a custom callback function to add sample metadata to a statistics report.
                                                                     ##   
                                                                     ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                                                     ##   
                                                                     ##    @param engine    The initialized scanning engine.
                                                                     ##    @param callback  The callback function pointer.
                                                                     ## ```
proc cl_engine_set_clcb_stats_remove_sample*(engine: ptr cl_engine;
    callback: clcb_stats_remove_sample) {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                        ##   @brief Set a custom callback function to remove sample metadata from a statistics report.
                                                                        ##   
                                                                        ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                                                        ##   
                                                                        ##    @param engine    The initialized scanning engine.
                                                                        ##    @param callback  The callback function pointer.
                                                                        ## ```
proc cl_engine_set_clcb_stats_decrement_count*(engine: ptr cl_engine;
    callback: clcb_stats_decrement_count) {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                          ##   @brief Set a custom callback function to decrement the hit count listed in the statistics report for a specific sample.
                                                                          ##   
                                                                          ##    This function may remove the sample from the report if the hit count is decremented to 0.
                                                                          ##   
                                                                          ##    @param engine    The initialized scanning engine.
                                                                          ##    @param callback  The callback function pointer.
                                                                          ## ```
proc cl_engine_set_clcb_stats_submit*(engine: ptr cl_engine;
                                      callback: clcb_stats_submit) {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   @brief Set a custom callback function to submit the statistics report.
                         ##   
                         ##    Caution: changing options for an engine that is in-use is not thread-safe!
                         ##   
                         ##    @param engine    The initialized scanning engine.
                         ##    @param callback  The callback function pointer.
                         ## ```
proc cl_engine_set_clcb_stats_flush*(engine: ptr cl_engine;
                                     callback: clcb_stats_flush) {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   @brief Set a custom callback function to flush/free the statistics report data.
                         ##   
                         ##    Caution: changing options for an engine that is in-use is not thread-safe!
                         ##   
                         ##    @param engine    The initialized scanning engine.
                         ##    @param callback  The callback function pointer.
                         ## ```
proc cl_engine_set_clcb_stats_get_num*(engine: ptr cl_engine;
                                       callback: clcb_stats_get_num) {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   @brief Set a custom callback function to get the number of samples listed in the statistics report.
                         ##   
                         ##    Caution: changing options for an engine that is in-use is not thread-safe!
                         ##   
                         ##    @param engine    The initialized scanning engine.
                         ##    @param callback  The callback function pointer.
                         ## ```
proc cl_engine_set_clcb_stats_get_size*(engine: ptr cl_engine;
                                        callback: clcb_stats_get_size) {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Set a custom callback function to get the size of memory used to store the statistics report.
                                  ##   
                                  ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                  ##   
                                  ##    @param engine    The initialized scanning engine.
                                  ##    @param callback  The callback function pointer.
                                  ## ```
proc cl_engine_set_clcb_stats_get_hostid*(engine: ptr cl_engine;
    callback: clcb_stats_get_hostid) {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                     ##   @brief Set a custom callback function to get the machine's unique host ID.
                                                                     ##   
                                                                     ##    Caution: changing options for an engine that is in-use is not thread-safe!
                                                                     ##   
                                                                     ##    @param engine    The initialized scanning engine.
                                                                     ##    @param callback  The callback function pointer.
                                                                     ## ```
proc cl_engine_stats_enable*(engine: ptr cl_engine) {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Function enables the built-in statistics reporting feature.
                  ##   
                  ##    @param engine    The initialized scanning engine.
                  ## ```
proc cl_scandesc*(desc: cint; filename: cstring; virname: ptr cstring;
                  scanned: ptr culong; engine: ptr cl_engine;
                  scanoptions: ptr cl_scan_options): cl_error_t {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   ----------------------------------------------------------------------------
                         ##    File scanning.
                         ##    
                         ##     
                         ##    @brief Scan a file, given a file descriptor.
                         ##   
                         ##    @param desc              File descriptor of an open file. The caller must provide this or the map.
                         ##    @param filename          (optional) Filepath of the open file descriptor or file map.
                         ##    @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
                         ##    @param[out] scanned      The number of bytes scanned.
                         ##    @param engine            The scanning engine.
                         ##    @param scanoptions       Scanning options.
                         ##    @return cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
                         ## ```
proc cl_scandesc_callback*(desc: cint; filename: cstring; virname: ptr cstring;
                           scanned: ptr culong; engine: ptr cl_engine;
                           scanoptions: ptr cl_scan_options; context: pointer): cl_error_t {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Scan a file, given a file descriptor.
                                  ##   
                                  ##    This callback variant allows the caller to provide a context structure that caller provided callback functions can interpret.
                                  ##   
                                  ##    @param desc              File descriptor of an open file. The caller must provide this or the map.
                                  ##    @param filename          (optional) Filepath of the open file descriptor or file map.
                                  ##    @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
                                  ##    @param[out] scanned      The number of bytes scanned.
                                  ##    @param engine            The scanning engine.
                                  ##    @param scanoptions       Scanning options.
                                  ##    @param[in/out] context   An opaque context structure allowing the caller to record details about the sample being scanned.
                                  ##    @return cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
                                  ## ```
proc cl_scanfile*(filename: cstring; virname: ptr cstring; scanned: ptr culong;
                  engine: ptr cl_engine; scanoptions: ptr cl_scan_options): cl_error_t {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Scan a file, given a filename.
                                  ##   
                                  ##    @param filename          Filepath of the file to be scanned.
                                  ##    @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
                                  ##    @param[out] scanned      The number of bytes scanned.
                                  ##    @param engine            The scanning engine.
                                  ##    @param scanoptions       Scanning options.
                                  ##    @return cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
                                  ## ```
proc cl_scanfile_callback*(filename: cstring; virname: ptr cstring;
                           scanned: ptr culong; engine: ptr cl_engine;
                           scanoptions: ptr cl_scan_options; context: pointer): cl_error_t {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Scan a file, given a filename.
                                  ##   
                                  ##    This callback variant allows the caller to provide a context structure that caller provided callback functions can interpret.
                                  ##   
                                  ##    @param filename          Filepath of the file to be scanned.
                                  ##    @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
                                  ##    @param[out] scanned      The number of bytes scanned.
                                  ##    @param engine            The scanning engine.
                                  ##    @param scanoptions       Scanning options.
                                  ##    @param[in/out] context   An opaque context structure allowing the caller to record details about the sample being scanned.
                                  ##    @return cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
                                  ## ```
proc cl_load*(path: cstring; engine: ptr cl_engine; signo: ptr cuint;
              dboptions: cuint): cl_error_t {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                            ##   ----------------------------------------------------------------------------
                                                                            ##    Database handling.
                                                                            ## ```
proc cl_retdbdir*(): cstring {.importc, cdecl, impclamavHdr.}
proc cl_cvdhead*(file: cstring): ptr cl_cvd {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                            ##   @brief Read the CVD header data from a file.
                                                                            ##   
                                                                            ##    The returned pointer must be free'd with cl_cvdfree().
                                                                            ##   
                                                                            ##    @param file              Filepath of CVD file.
                                                                            ##    @return struct cl_cvd*   Pointer to an allocated CVD header data structure.
                                                                            ## ```
proc cl_cvdparse*(head: cstring): ptr cl_cvd {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                             ##   @brief Parse the CVD header.
                                                                             ##   
                                                                             ##    Buffer length is not an argument, and the check must be done
                                                                             ##    by the caller cl_cvdhead().
                                                                             ##   
                                                                             ##    The returned pointer must be free'd with cl_cvdfree().
                                                                             ##   
                                                                             ##    @param head              Pointer to the header data buffer.
                                                                             ##    @return struct cl_cvd*   Pointer to an allocated CVD header data structure.
                                                                             ## ```
proc cl_cvdverify*(file: cstring): cl_error_t {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                              ##   @brief Verify a CVD file by loading and unloading it.
                                                                              ##   
                                                                              ##    @param file          Filepath of CVD file.
                                                                              ##    @return cl_error_t   CL_SUCCESS if success, else a CL_E* error code.
                                                                              ## ```
proc cl_cvdfree*(cvd: ptr cl_cvd) {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                  ##   @brief Free a CVD header struct.
                                                                  ##   
                                                                  ##    @param cvd   Pointer to a CVD header struct.
                                                                  ## ```
proc cl_statinidir*(dirname: cstring; dbstat: ptr cl_stat): cl_error_t {.
    importc, cdecl, impclamavHdr.}
# ```
                                  ##   @brief Initialize a directory to be watched for database changes.
                                  ##   
                                  ##    The dbstat out variable is allocated and must be freed using cl_statfree().
                                  ##   
                                  ##    @param dirname       Pathname of the database directory.
                                  ##    @param[out] dbstat   dbstat handle.
                                  ##    @return cl_error_t   CL_SUCCESS if successfully initialized.
                                  ## ```
proc cl_statchkdir*(dbstat: ptr cl_stat): cint {.importc, cdecl, impclamavHdr.}
# ```
                                                                               ##   @brief Check the database directory for changes.
                                                                               ##   
                                                                               ##    @param dbstat dbstat handle.
                                                                               ##    @return int   0 No change.
                                                                               ##    @return int   1 Some change occured.
                                                                               ## ```
proc cl_statfree*(dbstat: ptr cl_stat): cl_error_t {.importc, cdecl,
    impclamavHdr.}
## ```
                  ##   @brief Free the dbstat handle.
                  ##   
                  ##    @param dbstat        dbstat handle.
                  ##    @return cl_error_t   CL_SUCCESS
                  ##    @return cl_error_t   CL_ENULLARG
                  ## ```
proc cl_countsigs*(path: cstring; countoptions: cuint; sigs: ptr cuint): cl_error_t {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Count the number of signatures in a database file or directory.
                                  ##   
                                  ##    @param path          Path of the database file or directory.
                                  ##    @param countoptions  A bitflag field. May be CL_COUNTSIGS_OFFICIAL, CL_COUNTSIGS_UNOFFICIAL, or CL_COUNTSIGS_ALL.
                                  ##    @param[out] sigs     The number of sigs.
                                  ##    @return cl_error_t   CL_SUCCESS if success, else a CL_E* error type.
                                  ## ```
proc cl_retflevel*(): cuint {.importc, cdecl, impclamavHdr.}
  ## ```
                                                            ##   ----------------------------------------------------------------------------
                                                            ##    Software versions.
                                                            ##    
                                                            ##     
                                                            ##    @brief Get the Functionality Level (FLEVEL).
                                                            ##   
                                                            ##    @return unsigned int The FLEVEL.
                                                            ## ```
proc cl_retver*(): cstring {.importc, cdecl, impclamavHdr.}
  ## ```
                                                           ##   @brief Get the ClamAV version string.
                                                           ##   
                                                           ##    E.g. clamav-0.100.0-beta
                                                           ##   
                                                           ##    @return const char* The version string.
                                                           ## ```
proc cl_strerror*(clerror: cint): cstring {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                          ##   ----------------------------------------------------------------------------
                                                                          ##    Others.
                                                                          ## ```
proc cl_fmap_open_handle*(handle: pointer; offset: uint; len: uint;
                          a4: clcb_pread; use_aging: cint): ptr cl_fmap_t {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Open a map given a handle.
                                  ##   
                                  ##    Open a map for scanning custom data accessed by a handle and pread (lseek +
                                  ##    read)-like interface. For example a WIN32 HANDLE.
                                  ##    By default fmap will use aging to discard old data, unless you tell it not
                                  ##    to.
                                  ##   
                                  ##    The handle will be passed to the callback each time.
                                  ##   
                                  ##    @param handle        A handle that may be accessed using lseek + read.
                                  ##    @param offset        Initial offset to start scanning.
                                  ##    @param len           Length of the data from the start (not the offset).
                                  ##    @param use_aging     Set to a non-zero value to enable aging.
                                  ##    @param pread_cb      A callback function to read data from the handle.
                                  ##    @return cl_fmap_t*   A map representing the handle interface.
                                  ## ```
proc cl_fmap_open_memory*(start: pointer; len: uint): ptr cl_fmap_t {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   @brief Open a map given a buffer.
                         ##   
                         ##    Open a map for scanning custom data, where the data is already in memory,
                         ##    either in the form of a buffer, a memory mapped file, etc.
                         ##    Note that the memory [start, start+len) must be the _entire_ file,
                         ##    you can't give it parts of a file and expect detection to work.
                         ##   
                         ##    @param start         Pointer to a buffer of data.
                         ##    @param len           Length in bytes of the data.
                         ##    @return cl_fmap_t*   A map representing the buffer.
                         ## ```
proc cl_fmap_close*(a1: ptr cl_fmap_t) {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                       ##   @brief Releases resources associated with the map.
                                                                       ##   
                                                                       ##    You should release any resources you hold only after (handles, maps) calling
                                                                       ##    this function.
                                                                       ##   
                                                                       ##    @param map           Map to be closed.
                                                                       ## ```
proc cl_scanmap_callback*(map: ptr cl_fmap_t; filename: cstring;
                          virname: ptr cstring; scanned: ptr culong;
                          engine: ptr cl_engine;
                          scanoptions: ptr cl_scan_options; context: pointer): cl_error_t {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Scan custom data.
                                  ##   
                                  ##    @param map           Buffer to be scanned, in form of a cl_fmap_t.
                                  ##    @param filename      Name of data origin. Does not need to be an actual
                                  ##                         file on disk. May be NULL if a name is not available.
                                  ##    @param[out] virname  Pointer to receive the signature match name name if a
                                  ##                         signature matched.
                                  ##    @param[out] scanned  Number of bytes scanned.
                                  ##    @param engine        The scanning engine.
                                  ##    @param scanoptions   The scanning options struct.
                                  ##    @param context       An application-defined context struct, opaque to
                                  ##                         libclamav. May be used within your callback functions.
                                  ##    @return cl_error_t   CL_CLEAN if no signature matched. CL_VIRUS if a
                                  ##                         signature matched. Another CL_E* error code if an
                                  ##                         error occured.
                                  ## ```
proc cl_hash_data*(alg: cstring; buf: pointer; len: uint; obuf: ptr uint8;
                   olen: ptr cuint): ptr uint8 {.importc, cdecl, impclamavHdr.}
  ## ```
                                                                                ##   @brief Generate a hash of data.
                                                                                ##   
                                                                                ##    @param alg       The hashing algorithm to use.
                                                                                ##    @param buf       The data to be hashed.
                                                                                ##    @param len       The length of the to-be-hashed data.
                                                                                ##    @param[out] obuf (optional) A buffer to store the generated hash. Use NULL to dynamically allocate buffer.
                                                                                ##    @param[out] olen (optional) A pointer that stores how long the generated hash is.
                                                                                ##    @return          A pointer to the generated hash or obuf if obuf is not NULL.
                                                                                ## ```
# proc cl_hash_file_fd_ctx*(ctx: ptr EVP_MD_CTX; fd: cint; olen: ptr cuint): ptr uint8 {.
#     importc, cdecl, impclamavHdr.}
## ```
                                  ##   @brief Generate a hash of a file.
                                  ##   
                                  ##    @param ctx       A pointer to the OpenSSL EVP_MD_CTX object.
                                  ##    @param fd        The file descriptor.
                                  ##    @param[out] olen (optional) The length of the generated hash.
                                  ##    @return          A pointer to a malloc'd buffer that holds the generated hash.
                                  ## ```
proc cl_hash_file_fd*(fd: cint; alg: cstring; olen: ptr cuint): ptr uint8 {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Generate a hash of a file.
                                  ##   
                                  ##    @param fd        The file descriptor.
                                  ##    @param alg       The hashing algorithm to use.
                                  ##    @param[out] olen (optional) The length of the generated hash.
                                  ##    @return          A pointer to a malloc'd buffer that holds the generated hash.
                                  ## ```
proc cl_hash_file_fp*(fp: File; alg: cstring; olen: ptr cuint): ptr uint8 {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Generate a hash of a file.
                                  ##   
                                  ##    @param fp        A pointer to a FILE object.
                                  ##    @param alg       The hashing algorithm to use.
                                  ##    @param[out] olen (optional) The length of the generated hash.
                                  ##    @return          A pointer to a malloc'd buffer that holds the generated hash.
                                  ## ```
proc cl_sha256*(buf: pointer; len: uint; obuf: ptr uint8; olen: ptr cuint): ptr uint8 {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Generate a sha256 hash of data.
                                  ##   
                                  ##    @param buf       The data to hash.
                                  ##    @param len       The length of the to-be-hashed data.
                                  ##    @param[out] obuf (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.
                                  ##    @param[out] olen (optional) The length of the generated hash.
                                  ##    @return          A pointer to a malloc'd buffer that holds the generated hash.
                                  ## ```
proc cl_sha384*(buf: pointer; len: uint; obuf: ptr uint8; olen: ptr cuint): ptr uint8 {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Generate a sha384 hash of data.
                                  ##   
                                  ##    @param buf       The data to hash.
                                  ##    @param len       The length of the to-be-hashed data.
                                  ##    @param[out] obuf (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.
                                  ##    @param[out] olen (optional) The length of the generated hash.
                                  ##    @return          A pointer to a malloc'd buffer that holds the generated hash.
                                  ## ```
proc cl_sha512*(buf: pointer; len: uint; obuf: ptr uint8; olen: ptr cuint): ptr uint8 {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Generate a sha512 hash of data.
                                  ##   
                                  ##    @param buf       The data to hash.
                                  ##    @param len       The length of the to-be-hashed data.
                                  ##    @param[out] obuf (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.
                                  ##    @param[out] olen (optional) The length of the generated hash.
                                  ##    @return          A pointer to a malloc'd buffer that holds the generated hash.
                                  ## ```
proc cl_sha1*(buf: pointer; len: uint; obuf: ptr uint8; olen: ptr cuint): ptr uint8 {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Generate a sha1 hash of data.
                                  ##   
                                  ##    @param buf       The data to hash.
                                  ##    @param len       The length of the to-be-hashed data.
                                  ##    @param[out] obuf (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.
                                  ##    @param[out] olen (optional) The length of the generated hash.
                                  ##    @return          A pointer to a malloc'd buffer that holds the generated hash.
                                  ## ```
# proc cl_verify_signature*(pkey: ptr EVP_PKEY; alg: cstring; sig: ptr uint8;
#                           siglen: cuint; data: ptr uint8; datalen: uint;
#                           decode: cint): cint {.importc, cdecl, impclamavHdr.}
## ```
                                                                              ##   @brief Verify validity of signed data.
                                                                              ##   
                                                                              ##    @param pkey      The public key of the keypair that signed the data.
                                                                              ##    @param alg       The algorithm used to hash the data.
                                                                              ##    @param sig       The signature block.
                                                                              ##    @param siglen    The length of the signature.
                                                                              ##    @param data      The data that was signed.
                                                                              ##    @param datalen   The length of the data.
                                                                              ##    @param decode    Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
                                                                              ##    @return          0 for success, -1 for error or invalid signature.
                                                                              ## ```
# proc cl_verify_signature_hash*(pkey: ptr EVP_PKEY; alg: cstring;
#                                sig: ptr uint8; siglen: cuint;
#                                digest: ptr uint8): cint {.importc, cdecl,
#     impclamavHdr.}
#   ## ```
##   @brief Verify validity of signed data.
##   
##    @param pkey      The public key of the keypair that signed the data.
##    @param alg       The algorithm used to hash the data.
##    @param sig       The signature block.
##    @param siglen    The length of the signature.
##    @param digest    The hash of the signed data.
##    @return          0 for success, -1 for error or invalid signature.
## ```
# proc cl_verify_signature_fd*(pkey: ptr EVP_PKEY; alg: cstring; sig: ptr uint8;
#                              siglen: cuint; fd: cint): cint {.importc, cdecl,
#     impclamavHdr.}
## ```
##   @brief Verify validity of signed data.
##   
##    @param pkey      The public key of the keypair that signed the data.
##    @param alg       The algorithm used to hash the data.
##    @param sig       The signature block.
##    @param siglen    The length of the signature.
##    @param fd        The file descriptor.
##    @return          0 for success, -1 for error or invalid signature.
## ```
proc cl_verify_signature_hash_x509_keyfile*(x509path: cstring; alg: cstring;
    sig: ptr uint8; siglen: cuint; digest: ptr uint8): cint {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Verify validity of signed data.
                  ##   
                  ##    @param x509path  The path to the public key of the keypair that signed the data.
                  ##    @param alg       The algorithm used to hash the data.
                  ##    @param sig       The signature block.
                  ##    @param siglen    The length of the signature.
                  ##    @param digest    The hash of the signed data.
                  ##    @return          0 for success, -1 for error or invalid signature.
                  ## ```
proc cl_verify_signature_fd_x509_keyfile*(x509path: cstring; alg: cstring;
    sig: ptr uint8; siglen: cuint; fd: cint): cint {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Verify validity of signed data.
                  ##   
                  ##    @param x509path  The path to the public key of the keypair that signed the data.
                  ##    @param alg       The algorithm used to hash the data.
                  ##    @param sig       The signature block.
                  ##    @param siglen    The length of the signature.
                  ##    @param fd        The file descriptor.
                  ##    @return          0 for success, -1 for error or invalid signature.
                  ## ```
proc cl_verify_signature_x509_keyfile*(x509path: cstring; alg: cstring;
                                       sig: ptr uint8; siglen: cuint;
                                       data: ptr uint8; datalen: uint;
                                       decode: cint): cint {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Verify validity of signed data.
                  ##   
                  ##    @param x509path  The path to the public key of the keypair that signed the data.
                  ##    @param alg       The algorithm used to hash the data.
                  ##    @param sig       The signature block.
                  ##    @param siglen    The length of the signature.
                  ##    @param data      The data that was signed.
                  ##    @param datalen   The length of the data.
                  ##    @param decode    Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
                  ##    @return          0 for success, -1 for error or invalid signature.
                  ## ```
# proc cl_verify_signature_hash_x509*(x509: ptr X509; alg: cstring;
#                                     sig: ptr uint8; siglen: cuint;
#                                     digest: ptr uint8): cint {.importc, cdecl,
#     impclamavHdr.}
## ```
##   @brief Verify validity of signed data
##   
##    @param x509      The X509 object of the public key of the keypair that signed the data.
##    @param alg       The algorithm used to hash the data.
##    @param sig       The signature block.
##    @param siglen    The length of the signature.
##    @param digest    The hash of the signed data.
##    @return          0 for success, -1 for error or invalid signature.
## ```
# proc cl_verify_signature_fd_x509*(x509: ptr X509; alg: cstring; sig: ptr uint8;
#                                   siglen: cuint; fd: cint): cint {.importc,
#     cdecl, impclamavHdr.}
## ```
##   @brief Verify validity of signed data.
##   
##    @param x509      The X509 object of the public key of the keypair that signed the data.
##    @param alg       The algorithm used to hash the data.
##    @param sig       The signature block.
##    @param siglen    The length of the signature.
##    @param fd        The file descriptor.
##    @return          0 for success, -1 for error or invalid signature.
## ```
# proc cl_verify_signature_x509*(x509: ptr X509; alg: cstring; sig: ptr uint8;
#                                siglen: cuint; data: ptr uint8; datalen: uint;
#                                decode: cint): cint {.importc, cdecl,
#     impclamavHdr.}
## ```
##   @brief Verify validity of signed data.
##   
##    @param x509      The X509 object of the public key of the keypair that signed the data.
##    @param alg       The algorithm used to hash the data.
##    @param sig       The signature block.
##    @param siglen    The length of the signature.
##    @param data      The data that was signed.
##    @param datalen   The length of the data.
##    @param decode    Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
##    @return          0 for success, -1 for error or invalid signature.
## ```
# proc cl_get_x509_from_mem*(data: pointer; len: cuint): ptr X509 {.importc,
#     cdecl, impclamavHdr.}
## ```
##   @brief Get an X509 object from memory.
##   
##    @param data      A pointer to a spot in memory that contains the PEM X509 cert.
##    @param len       The length of the data.
##    @return          A pointer to the X509 object on success, NULL on error.
## ```
proc cl_validate_certificate_chain_ts_dir*(tsdir: cstring; certpath: cstring): cint {.
    importc, cdecl, impclamavHdr.}
  ## ```
                                  ##   @brief Validate an X509 certificate chain, with the chain being located in a directory.
                                  ##   
                                  ##    @param tsdir     The path to the trust store directory.
                                  ##    @param certpath  The path to the X509 certificate to be validated.
                                  ##    @return          0 for success, -1 for error or invalid certificate.
                                  ## ```
proc cl_validate_certificate_chain*(authorities: ptr cstring; crlpath: cstring;
                                    certpath: cstring): cint {.importc, cdecl,
    impclamavHdr.}
  ## ```
                  ##   @brief Validate an X509 certificate chain with support for a CRL.
                  ##   
                  ##    @param authorities   A NULL-terminated array of strings that hold the path of the CA's X509 certificate.
                  ##    @param crlpath       (optional) A path to the CRL file. NULL if no CRL.
                  ##    @param certpath      The path to the X509 certificate to be validated.
                  ##    @return              0 for success, -1 for error or invalid certificate.
                  ## ```
# proc cl_load_cert*(certpath: cstring): ptr X509 {.importc, cdecl, impclamavHdr.}
## ```
##   @brief Load an X509 certificate from a file.
##   
##    @param certpath  The path to the X509 certificate.
## ```
# proc cl_ASN1_GetTimeT*(timeobj: ptr ASN1_TIME): ptr tm {.importc, cdecl,
#     impclamavHdr.}
## ```
##   @brief Parse an ASN1_TIME object.
##   
##    @param timeobj   The ASN1_TIME object.
##    @return          A pointer to a (struct tm). Adjusted for time zone and daylight savings time.
## ```
# proc cl_load_crl*(timeobj: cstring): ptr X509_CRL {.importc, cdecl, impclamavHdr.}
## ```
##   @brief Load a CRL file into an X509_CRL object.
##   
##    @param file  The path to the CRL.
##    @return      A pointer to an X509_CRL object or NULL on error.
## ```
proc cl_sign_data_keyfile*(keypath: cstring; alg: cstring; hash: ptr uint8;
                           olen: ptr cuint; encode: cint): ptr uint8 {.importc,
    cdecl, impclamavHdr.}
  ## ```
                         ##   @brief Sign data with a key stored on disk.
                         ##   
                         ##    @param keypath   The path to the RSA private key.
                         ##    @param alg       The hash/signature algorithm to use.
                         ##    @param hash      The hash to sign.
                         ##    @param[out] olen A pointer that stores the size of the signature.
                         ##    @param           Whether or not to base64-encode the signature. 1 for yes, 0 for no.
                         ##    @return          The generated signature.
                         ## ```
# proc cl_sign_data*(pkey: ptr EVP_PKEY; alg: cstring; hash: ptr uint8;
#                    olen: ptr cuint; encode: cint): ptr uint8 {.importc, cdecl,
#     impclamavHdr.}
## ```
##   @brief Sign data with an RSA private key object.
##   
##    @param pkey      The RSA private key object.
##    @param alg       The hash/signature algorithm to use.
##    @param hash      The hash to sign.
##    @param[out] olen A pointer that stores the size of the signature.
##    @param           Whether or not to base64-encode the signature. 1 for yes, 0 for no.
##    @return          The generated signature.
## ```
# proc cl_sign_file_fd*(fd: cint; pkey: ptr EVP_PKEY; alg: cstring;
#                       olen: ptr cuint; encode: cint): ptr uint8 {.importc,
#     cdecl, impclamavHdr.}
## ```
##   @brief Sign a file with an RSA private key object.
##   
##    @param fd        The file descriptor.
##    @param pkey      The RSA private key object.
##    @param alg       The hash/signature algorithm to use.
##    @param[out] olen A pointer that stores the size of the signature.
##    @param encode    Whether or not to base64-encode the signature. 1 for yes, 0 for no.
##    @return          The generated signature.
## ```
# proc cl_sign_file_fp*(fp: File; pkey: ptr EVP_PKEY; alg: cstring;
#                       olen: ptr cuint; encode: cint): ptr uint8 {.importc,
#     cdecl, impclamavHdr.}
## ```
##   @brief Sign a file with an RSA private key object.
##   
##    @param fp        A pointer to a FILE object.
##    @param pkey      The RSA private key object.
##    @param alg       The hash/signature algorithm to use.
##    @param[out] olen A pointer that stores the size of the signature.
##    @param encode    Whether or not to base64-encode the signature. 1 for yes, 0 for no.
##    @return          The generated signature.
## ```
# proc cl_get_pkey_file*(keypath: cstring): ptr EVP_PKEY {.importc, cdecl,
#     impclamavHdr.}
## ```
##   @brief Get the Private Key stored on disk.
##   
##    @param keypath   The path on disk where the private key is stored.
##    @return          A pointer to the EVP_PKEY object that contains the private key in memory.
## ```
proc cl_hash_init*(alg: cstring): pointer {.importc, cdecl, impclamavHdr.}
proc cl_update_hash*(ctx: pointer; data: pointer; sz: uint): cint {.importc,
    cdecl, impclamavHdr.}
proc cl_finish_hash*(ctx: pointer; buf: pointer): cint {.importc, cdecl,
    impclamavHdr.}
proc cl_hash_destroy*(ctx: pointer) {.importc, cdecl, impclamavHdr.}
{.pop.}
