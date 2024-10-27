import strutils
import os
import engine_cores
import bindings/[libyara, libclamav]
import .. /cli/[progress_bar, print_utils]
import posix


#[
  Print infected file for Yara
]#
proc fscanner_on_malware_found_yara(context: ptr YR_SCAN_CONTEXT, message: cint, message_data: pointer, user_data: pointer): cint {.cdecl.} =
  var
    ctx = cast[ptr FileScanCtx](user_data)

  if message == CALLBACK_MSG_RULE_MATCHING:
    let
      rule = cast[ptr YR_RULE](message_data)

    ctx.scan_result = CL_VIRUS
    ctx.virname = cstring($rule.ns.name & ":" & replace($rule.identifier, "_", "."))
    return CALLBACK_ABORT
  else:
    ctx.scan_result = CL_CLEAN
    ctx.virname = ""
    return CALLBACK_CONTINUE


#[
  Print infected file for ClamAV
]#
proc fscanner_on_malware_found_clam*(fd: cint, virname: cstring, context: pointer) {.cdecl.} =
  let
    ctx = cast[ptr FileScanCtx](context)
    # Show virname for heur detection
    virus_name = if isEmptyOrWhitespace($ctx.virname): virname else: ctx.virname

  ctx.file_infected += 1
  print_file_infected($virus_name, ctx.virt_scan_object)


#[
  Disable print message for ClamAV
]#
proc fscanner_slient_message_clam*(severity: cl_msg, fullmsg: cstring, msg: cstring, context: pointer) {.cdecl.} =
  discard


#[
  When Yara engine is nil, and ClamAV is enabled,
  Clam will scan anyway.
  This function will count scanned files by ClamAV
]#
proc fscanner_cb_inc_count*(fd: cint, scan_result: cint, virname: cstring, context: pointer): cl_error_t {.cdecl.} =
  let
    ctx = cast[ptr FileScanCtx](context)

  progress_bar_scan_file(ctx.scan_object)
  ctx.file_scanned += 1


#[
  Scan file descriptor with Yara
  When ClamAV Engine is defined, it will be called later
  # TODO use Yara scanner
]#
proc fscanner_cb_file_inspection*(fd: cint, file_type: cstring, ancestors: ptr cstring, parent_file_size: uint,
  file_name: cstring; file_size: uint, file_buffer: cstring, recursion_level: uint32, layer_attributes: uint32,
  context: pointer): cl_error_t {.cdecl.} =
  #[
    Only use Yara scan when file_type is various types like PE, ELF, text, ...
    Arcoding to LibClamAV's scanners.c#L4624, there are some file types triggers scan function. There are some unknown
    file types like
    1. CL_TYPE_TEXT_ASCII
    2. CL_TYPE_TEXT_UTF16BE
    3. CL_TYPE_TEXT_UTF16LE
  ]#
  # TODO dig ClamAV's code to improve accuracy of file scanning. Idea: Do not scan compressed files
  #[
    ClamAV doesn't scan CL_TYPE_TEXT_ASCII?
  ]#
  # TODO improve ram usage. Current function is using 54mb (compare to 46mb when use pre-cache) for same files
  # TODO create a rule to combine text_ascii with the scan memory to prevent false positive

  # if $file_type in [
  #   "CL_TYPE_TEXT_UTF8",
  #   "CL_TYPE_MSEXE",
  #   "CL_TYPE_ELF",
  #   "CL_TYPE_MACHO_UNIBIN",
  #   "CL_TYPE_BINARY_DATA",
  #   "CL_TYPE_HTML",
  #   "CL_TYPE_TEXT_ASCII"
  # ]:
  let
    ctx = cast[ptr FileScanCtx](context)

  if ctx.scan_result == CL_VIRUS:
    return CL_VIRUS

  ctx.virt_scan_object = ctx.scan_object

  if not isEmptyOrWhitespace($file_name):
    let
      inner_file_name = splitPath($file_name).tail

    if inner_file_name != splitPath(ctx.scan_object).tail:
      if "//" in ctx.scan_object:
        ctx.virt_scan_object = ctx.scan_object & "/" & inner_file_name
      else:
        ctx.virt_scan_object = ctx.scan_object & "//" & inner_file_name

  discard yr_rules_scan_fd(ctx.yara.rules, fd, SCAN_FLAGS_FAST_MODE, fscanner_on_malware_found_yara, context, YR_SCAN_TIMEOUT)

  if ctx.scan_result == CL_VIRUS:
    # FIX multiple files marked as previous signature. However, it might raise error using multiple callbacks to detect malware
    ctx.scan_result = CL_CLEAN
    return CL_VIRUS

  return CL_CLEAN


#[
  Call ClamAV's scan file callback.
]#
proc fscanner_scan_file*(scan_ctx: var FileScanCtx, scan_path: string, virname: var cstring, scanned: var uint) =
  scan_ctx.file_scanned += 1
  scan_ctx.scan_object = scan_path

  progress_bar_scan_file(scan_ctx.virt_scan_object)
  discard cl_scanfile_callback(cstring(scan_ctx.scan_object), addr(virname), addr(scanned), scan_ctx.clam.engine, addr(scan_ctx.clam.options), addr(scan_ctx))


#[
  Replacement of os.walkDirRec using posix's readdir.
  Input: dir (a list of dir should be handled by a function above)
  Job: Do read every nodes of current dir
  1. If node is a file or symlink of a file, call file scan
  2. If node is a folder or symlink of a folder, call walk_dir rec
  3. Do heuristic scan for hidden nodes (via d_name)

  TODO improve logic to handle process in procfs too

  Linux's node types: https://www.gnu.org/software/libc/manual/html_node/Directory-Entries.html
]#
proc fscanner_walk_dir_rec*(scan_ctx: var FileScanCtx, scan_dir: string, virname: var cstring, scanned: var uint) =
  var
    p_dir = opendir(cstring(scan_dir))
    ptr_dir: ptr Dirent
    next_node_name: string
    current_node_name: string
    full_node_path: string

  while true:
    ptr_dir = readdir(p_dir)

    if ptr_dir == nil:
      # FIXME hidden file in last node will not be detected because of this break
      break

    current_node_name = $cast[cstring](addr(ptr_dir.d_name))
    if current_node_name == "." or current_node_name == "..":
      continue

    full_node_path = if scan_dir.endsWith("/"): scan_dir & current_node_name else: scan_dir & "/" & current_node_name

    if not isEmptyOrWhiteSpace(next_node_name) and next_node_name != current_node_name:
      discard # TODO show this is a hidden node

    if ptr_dir.d_reclen >= 256:
      # Name of current node is too long. We can't parse next_node_name, or we might have a crash
      next_node_name = ""
    else:
      # d_reclen = len(current_node_name) + sizeof(chunk_bytes). casting a string at next position can get the name of next node
      next_node_name = $cast[cstring](addr(ptr_dir.d_name[ptr_dir.d_reclen]))

    case ptr_dir.d_type
      of DT_DIR:
        # Recursive walk. Current node is a folder so it should ends with "/"
        fscanner_walk_dir_rec(scan_ctx, full_node_path & "/", virname, scanned)
      of DT_REG:
        # Regular file, call scan file
        fscanner_scan_file(scan_ctx, full_node_path, virname, scanned)
      of DT_LNK:
        # Either link of file or link of dir. Must handle this
        # if getSymlinkFileKind(full_node_path) == pcLinkToDir:
        #   fscanner_walk_dir_rec(full_node_path & "/")
        discard
      of DT_UNKNOWN:
        # The type is unknown. Only some filesystems have full support to return the type of the file, others might always return this value. Debug first
        fscanner_scan_file(scan_ctx, full_node_path, virname, scanned)
      else:
        # DT_FIFO, DT_SOCK, DT_CHR (A character device), DT_BLK (A block device). Research first
        discard

  discard p_dir.closedir()
