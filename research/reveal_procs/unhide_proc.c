/*
  This module is the modificaiton of get_list_of_procs that transfer the result to the Netlink therefore userspace application can get the result
  https://stackoverflow.com/questions/3299386/how-to-use-netlink-socket-to-communicate-with-a-kernel-module
  https://embeddedguruji.blogspot.com/2018/12/linux-kernel-driver-to-print-all.html
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#define NETLINK_USER 31

struct sock *nl_sk = NULL;


static void module_handle_send_proc_list(struct nlmsghdr *netlnk_message, int client_pid)
{
  /*
    Send the list of PIDs to client
  */
  int msg_size;
  int resp_err_code;

  unsigned int proc_count = 0;

  struct sk_buff *skb_out;
  struct task_struct *task_list;

  pid_t *list_procs = (pid_t *)kmalloc_array(1, sizeof(pid_t), GFP_USER);

  // It's really hard to handle memory passing to a function so use a for loop here instead
  for_each_process(task_list) {
    list_procs[proc_count] = task_list->pid;
    proc_count++;
    list_procs = (pid_t *)krealloc_array(list_procs, proc_count + 1, sizeof(pid_t), GFP_USER);
  }

  // Craft new message
  msg_size = proc_count * sizeof(pid_t);
  skb_out = nlmsg_new(msg_size, 0);

  if (!skb_out) {
    printk(KERN_ERR "Failed to allocate new skb\n");
    return;
  }

  // Send message to netlink buffer
  netlnk_message = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
  NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
  // Copy the message to the buffer
  memcpy(nlmsg_data(netlnk_message), list_procs, msg_size);
  // Send message to process
  resp_err_code = nlmsg_unicast(nl_sk, skb_out, client_pid);

  if (resp_err_code < 0)
    printk(KERN_INFO "Error while sending bak to user\n");
}


static void module_handle_connection(struct sk_buff *skb)
{

  struct nlmsghdr *netlnk_message;
  int client_pid;

  // TODO check data to get the actual request: get list of procs / modules?
  netlnk_message = (struct nlmsghdr *)skb->data;
  client_pid = netlnk_message->nlmsg_pid;
  /*
    if (nlh == GET_PROC) {
      module_handle_send_proc_list(nlh, client_pid);
    }
    elseif (nlh == GET_MODULES) {
      module_handle_send_loaded_list(nlh, client_pid);
    }
    else {
      return
    }

    send_message
  */
  module_handle_send_proc_list(netlnk_message, client_pid);
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
MODULE_AUTHOR("Nong Hoang Tu");
