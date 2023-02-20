#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "unhide_traces.h"

// Those variables need to be global, otherwise client crashes
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

extern void rkrev_find_hidden_proc(pid_t pid, char *comm);
extern void rkrev_find_hidden_module(char *module_name);


void rkrev_check_hidden_procs() {
  struct pid_info proc_info;
  char *buf;

  do {
    recvmsg(sock_fd, &msg, 0);
    memcpy(&proc_info, NLMSG_DATA(nlh), nlh->nlmsg_len);
    buf = (char *)realloc(buf, proc_info.comm_len);
    strncpy(buf, proc_info.comm, proc_info.comm_len);
    rkrev_find_hidden_proc(proc_info.pid, buf);
  }
  while (proc_info.pid != 0);
}


void rkrev_check_hidden_mods() {
  do {
    recvmsg(sock_fd, &msg, 0);
    rkrev_find_hidden_module(NLMSG_DATA(nlh));
  } while (strcmp(NLMSG_DATA(nlh), ""));
}


int main()
{
  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
  if (sock_fd < 0)
    return -1;

  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid(); /* self pid */

  bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.nl_family = AF_NETLINK;
  dest_addr.nl_pid = 0; /* For Linux Kernel */
  dest_addr.nl_groups = 0; /* unicast */

  nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
  memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
  nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_flags = 0;

  strcpy(NLMSG_DATA(nlh), "");

  iov.iov_base = (void *)nlh;
  iov.iov_len = nlh->nlmsg_len;
  msg.msg_name = (void *)&dest_addr;
  msg.msg_namelen = sizeof(dest_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if (sendmsg(sock_fd, &msg, 0) != 0) {
    printf("Failed to connect to kernel module! Make sure it's loaded\n");
  }
  else {
    rkrev_check_hidden_procs();
    rkrev_check_hidden_mods();
    printf("Scan completed!\n");
  }
  close(sock_fd);
}
