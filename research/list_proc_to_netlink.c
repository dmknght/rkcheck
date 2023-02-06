/*
  This module is the modificaiton of get_list_of_procs that transfer the result to the Netlink therefore userspace application can get the result
  https://stackoverflow.com/questions/3299386/how-to-use-netlink-socket-to-communicate-with-a-kernel-module
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#define NETLINK_USER 31
// #define MAX_PID 4194304

struct sock *nl_sk = NULL;


static void get_list_procs(pid_t list_procs[])
{
    struct task_struct *task_list;
    unsigned int proc_count = 0;

    for_each_process(task_list) {
      // task_list->comm (Command?, which should show name)
      // task_list->pid -> pid
      // TODO get pid to a list and send to pid
      list_procs[proc_count] = task_list->pid;
      proc_count++;
    }
    list_procs[proc_count + 1] = "\0";
}


static void module_handle_connection(struct sk_buff *skb)
{

  struct nlmsghdr *nlh;
  struct sk_buff *skb_out;
  int resp_err_code;
  int client_pid;
  pid_t *list_procs[2048]; // FIXME what if the size is bigger? Maybe use flexible_array from kernel?
  int msg_size;

  // TODO check data to get the actual request: get list of procs / modules?
  nlh = (struct nlmsghdr *)skb->data;
  /*
    if (nlh == GET_PROC) {
      get_list_procs(list_procs);
      msg_size = sizeof(list_procs);
    }
    elseif (nlh == GET_MODULES) {
      get_list_modules()
    }
    else {
      return
    }

    send_message
  */
  // printk(KERN_INFO "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
  client_pid = nlh->nlmsg_pid; /*pid of sending process */

  get_list_procs(list_procs);
  msg_size = sizeof(list_procs); // TODO is this actual size?
  skb_out = nlmsg_new(msg_size, 0);

  if (!skb_out) {
    printk(KERN_ERR "Failed to allocate new skb\n");
    return;
  }

  nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
  NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
  // Copy the message to the buffer
  memcpy(nlmsg_data(nlh), list_procs, msg_size);
  // Send message to process
  resp_err_code = nlmsg_unicast(nl_sk, skb_out, client_pid);

  if (resp_err_code < 0)
    printk(KERN_INFO "Error while sending bak to user\n");
}


static int get_proc_init(void)
{

  struct netlink_kernel_cfg cfg = {
    .input = module_handle_connection,
  };

  nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
  if (!nl_sk) {
    printk(KERN_ALERT "Error creating socket.\n");
    return -10;
  }

  return 0;
}


static void get_proc_exit(void)
{
  netlink_kernel_release(nl_sk);
}

module_init(get_proc_init);
module_exit(get_proc_exit);


MODULE_LICENSE("GPL");