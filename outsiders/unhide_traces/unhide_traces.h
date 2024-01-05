#define NETLINK_USER 31
#define MAX_PAYLOAD 1024 /* maximum payload size*/

struct pid_info {
  pid_t pid;
  unsigned char comm_len;
  char comm[16];
};
