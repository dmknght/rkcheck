import posix


proc find_hidden_files(find_dir: string) =
  # FIXME: if there are 2 hidden files like aaaa, aaab -> likely this loop will miss aaab and skip to aaac. It's technical issue
  # FIXME: missing hidden file in /dev/shm with perfctl linux rootkit
  var
    f_dir = opendir(cstring(find_dir))
    save_node_name: string
  
  while true:
    var
      r_dir: ptr Dirent = readdir(f_dir)

    if r_dir == nil:
      break

    # Compare name of current node with save name from previous loop (which suppose to be name of this node if no function hooking)
    # FIXME: if the name of next node is too long, only starts with is correct (which also can cause false positive)
    #  FIXED BY PARSING
    if save_node_name != "" and save_node_name != $cast[cstring](addr(r_dir.d_name)):
      echo "Malware: ", save_node_name

    # If r_dir.d_reclen < 256 then the name of current node is short enough so next part has name of next node
    # We parse the name and try comparing it with the name of node in next loop
    if r_dir.d_reclen >= 256:
      save_node_name = ""
    else:
      # Parse name of next node using location
      # FIXME: validate value if next node's name is very long so it doesnt end with NULL
      save_node_name = $cast[cstring](addr(r_dir.d_name[r_dir.d_reclen]))

  discard f_dir.closedir()

find_hidden_files("/dev/shm/")
