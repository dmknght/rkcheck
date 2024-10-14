import posix
import strutils


proc find_hidden_files(find_dir: string) =
  #[
    Find hidden file / folder by node's d_name comparsion
    1. Get name of current node
    2. Get the name of next node in d_name (d_name[255] could contain next node's name depends on lenght)
      # BUG: either 1 name is too long -> can't get the value -> bypass
    3. Compare the name from d_name with current node's name (if hidden by malware -> different)
      # BUG: if 2 hidden nodes are next to each other, the 2nd hidden won't be detected
    4. If current node is nil (previous node was last node) then break. (next node's name from previous loop should be null)
      # BUG:If current folder has too many node, it will show false positive at step 4.
  ]#
  var
    f_dir = opendir(cstring(find_dir))
    save_node_name: string
    wrong_reclen = false

  while true:
    var
      r_dir: ptr Dirent = readdir(f_dir)

    if r_dir == nil:
      if not isEmptyOrWhiteSpace(save_node_name) and not wrong_reclen:
        echo "Malware (last): ", save_node_name
      break

    # Compare name of current node with save name from previous loop (which suppose to be name of this node if no function hooking)
    if save_node_name != "" and save_node_name != $cast[cstring](addr(r_dir.d_name)):
      echo "Malware: ", save_node_name

    # If r_dir.d_reclen < 256 then the name of current node is short enough so next part has name of next node
    # We parse the name and try comparing it with the name of node in next loop
    if r_dir.d_reclen >= 256:
      save_node_name = ""
    else:
      # Parse name of next node using location
      save_node_name = $cast[cstring](addr(r_dir.d_name[r_dir.d_reclen]))
      # From output of d_name, last node in folder that has so many nodes will has d_reclen > actual value
      # This is a fast method to check this logic happen.
      # Need to check carefully with multiple systems because input value is unpredictable
      let tmp_string_from_chunk = $cast[cstring](addr(r_dir.d_name[r_dir.d_reclen - 1]))
      wrong_reclen = tmp_string_from_chunk.endswith(save_node_name) and tmp_string_from_chunk != save_node_name

  discard f_dir.closedir()

find_hidden_files("/usr/bin/")
