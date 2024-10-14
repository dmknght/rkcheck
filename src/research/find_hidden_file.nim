import posix
import strutils


# {.emit: """

# #include <dirent.h>


# unsigned short calculate_reclen(char *filename) {
#     // Calculate normal size
#     size_t reclen = offsetof(struct dirent, d_name) + strlen(filename) + 1;

#     // Calculate the real size based on system's arch
#     reclen = (reclen + sizeof(void*) - 1) & ~(sizeof(void*) - 1);

#     return (unsigned short)reclen;
# }
# """.}


# proc calculate_reclen(file_name: cstring): cushort {.importc: "calculate_reclen".}


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
    # wrong_reclen = false
    # actual_reclen: cushort

  while true:
    var
      r_dir: ptr Dirent = readdir(f_dir)

    if r_dir == nil:
      # if not isEmptyOrWhiteSpace(save_node_name): # and not wrong_reclen:
      #   echo "Malware (last): ", save_node_name
      break

    # Compare name of current node with save name from previous loop (which suppose to be name of this node if no function hooking)
    # let str_file_name = $cast[cstring](addr(r_dir.d_name))

    # if save_node_name != "" and save_node_name != str_file_name:
    if save_node_name != "" and save_node_name != $cast[cstring](addr(r_dir.d_name)):
      echo "Malware: ", save_node_name

    # If r_dir.d_reclen < 256 then the name of current node is short enough so next part has name of next node
    # We parse the name and try comparing it with the name of node in next loop
    if r_dir.d_reclen >= 256:
      save_node_name = ""
    else:
      save_node_name = $cast[cstring](addr(r_dir.d_name[r_dir.d_reclen]))
      # actual_reclen = calculate_reclen(cstring(str_file_name))
      # wrong_reclen = actual_reclen != r_dir.d_reclen
      # save_node_name = if wrong_reclen: $cast[cstring](addr(r_dir.d_name[actual_reclen])) else: $cast[cstring](addr(r_dir.d_name[r_dir.d_reclen]))

  discard f_dir.closedir()

find_hidden_files("/dev/shm")
