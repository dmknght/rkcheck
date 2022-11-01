import os
import unicode


proc progress_bar_scan_file*(path: string) =
  #[
    Progress bar on CLi. Move this function to a callback lib if switch to GUI
    Do not call eraseLine here. We keep showing this line until it's finished.
    Call eraseLine after scan is done
    https://nim-lang.org/docs/terminal.html
  ]#
  # If path is too long -> can't erase stdout. We try print only file name
  let file_name = splitPath(path).tail
  if len(file_name) < 50:
    stdout.write("[S] " & file_name)
  stdout.flushFile()


proc progress_bar_scan_proc*(pid: uint, path: string) =
  if len(path) >= 50:
    let file_name = splitPath(path).tail
    if len(file_name) < 50:
      stdout.write("[S] " & $pid & " " & file_name)
  else:
    stdout.write("[S] " & $pid & " " & path)
  stdout.flushFile()


proc progress_bar_flush*() =
  #[
    Remove last line. Use terminal escape https://stackoverflow.com/a/1508589
      \e[2K: Erase current line. Use \33[2K in C (maybe Py)
      \r: Move cursor to first pos in line
  ]#
  stdout.write("\e[2K\r")
