#[
  Parse free desktop entries
  https://specifications.freedesktop.org/desktop-entry-spec/desktop-entry-spec-latest.html#recognized-keys
]#
import strutils
import parseutils
import os

type
  FreeDesktopEntry = object
    exec: string
    tryExec: string
    path: string


proc parse_xdg_execute_command(path: string): FreeDesktopEntry =
  var
    entry: FreeDesktopEntry

  for line in lines(path):
    if line.startsWith("Exec="):
      entry.exec = line.captureBetween('=', '\n', 4)
    elif line.startsWith("TryExec="):
      entry.tryExec = line.captureBetween('=', '\n', 7)
    elif line.startsWith("Path="):
      entry.path = line.captureBetween('=', '\n', 4)
  return entry


proc parse_command_to_execute(entry_cmd: string): seq[string] =
  return parseCmdLine(entry_cmd)


proc find_exec_path_to_scan(exec_entry, path: string): string =
  # Not absolute path, we find binary
  if not exec_entry.startsWith("/"):
    # If entry has custom working dir, we find it
    if not isEmptyOrWhitespace(path):
      let absolutePath = if not path.endsWith("/"): path & "/" & exec_entry else: path & exec_entry
      if fileExists(absolutePath):
        return absolutePath
      else:
        return ""
    # Else, find from $PATH
    else:
      return findExe(exec_entry)
  else:
    return exec_entry


proc binary_is_not_interpreter(path: string): bool =
  # TODO check if program is interpreter
  return true


proc parse_scan_objects(file_list, buffer_list: var seq[string], exec_cmd, path: string) =
  let
    exec_command = parse_command_to_execute(exec_cmd)

  if len(exec_command) == 0:
    return

  let
    executable_file = find_exec_path_to_scan(exec_command[0], path)
  if binary_is_not_interpreter(executable_file):
    if not isEmptyOrWhitespace(executable_file):
      file_list.add(executable_file)
  else:
    buffer_list.add(exec_cmd)


proc parse_scan_objects_from_entry(file_list, buffer_list: var seq[string], entry: FreeDesktopEntry) =
  if not isEmptyOrWhitespace(entry.exec):
    parse_scan_objects(file_list, buffer_list, entry.exec, entry.path)
  if not isEmptyOrWhitespace(entry.tryExec):
    parse_scan_objects(file_list, buffer_list, entry.tryExec, entry.path)


proc parse_xdg_entry*(file_list, buffer_list: var seq[string], path: string) =
  let
    entry = parse_xdg_execute_command(path)
  parse_scan_objects_from_entry(file_list, buffer_list, entry)
