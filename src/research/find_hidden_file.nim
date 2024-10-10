import posix
import strutils


proc find_hidden_files(find_dir: string) =
  # FIXME: if there are 2 hidden files like aaaa, aaab -> likely this loop will miss aaab and skip to aaac. It's technical issue
  # FIXME: if the node before malware has the name too long, this script can't get the name of next node hence can't detect
  var
    f_dir = opendir(cstring(find_dir))
    save_node_name: string
  
  while true:
    var
      r_dir: ptr Dirent = readdir(f_dir)

    if r_dir == nil:
      # FIXED: missing hidden file in /dev/shm with perfctl linux rootkit. Reason: hidden file is the last link in node
      # FIXME false positive (?) /usr/bin/make-first-existing-target (belong to package `make`)
      if not isEmptyOrWhiteSpace(save_node_name):
        echo "Malware: ", save_node_name
      break

    # Compare name of current node with save name from previous loop (which suppose to be name of this node if no function hooking)
    # FIXED: if the name of next node is too long, only starts with is correct (which also can cause false positive). Parse using cast[cstring] fixed it (no NULL)
    if save_node_name != "" and save_node_name != $cast[cstring](addr(r_dir.d_name)):
      echo "Malware: ", save_node_name

    # If r_dir.d_reclen < 256 then the name of current node is short enough so next part has name of next node
    # We parse the name and try comparing it with the name of node in next loop
    if r_dir.d_reclen >= 256:
      save_node_name = ""
    else:
      # Parse name of next node using location
      # FIXED: validate value if next node's name is very long so it doesnt end with NULL
      save_node_name = $cast[cstring](addr(r_dir.d_name[r_dir.d_reclen]))

  discard f_dir.closedir()

find_hidden_files("/dev/shm/")
