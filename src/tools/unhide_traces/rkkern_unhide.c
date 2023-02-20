/*
  A kernel module to get processes and modules from kernel
  Then send the data to client to check if anything is being hidden by rootkit
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched/signal.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>


#define NETLINK_USER 31

struct sock *nl_sk = NULL;

struct pid_info {
  pid_t pid;
  unsigned char comm_len;
  char comm[TASK_COMM_LEN]; // 16
};

static struct kprobe kp = {
  .symbol_name = "kallsyms_lookup_name"
};

typedef void *(*kallsyms_lookup_name_t)(const char *name);


static void revealer_send_proc_info(struct nlmsghdr *netlnk_message, struct pid_info proc_info, pid_t client_pid) {
  size_t msg_size;
  int resp_err_code;
  struct sk_buff *skb_out;

  msg_size = sizeof(proc_info);
  skb_out = nlmsg_new(msg_size, 0);

  if (!skb_out) {
    printk(KERN_ERR "Failed to allocate new skb\n");
    return;
  }

  // Send message to netlink buffer
  netlnk_message = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
  NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
  // Copy the message to the buffer
  memcpy(nlmsg_data(netlnk_message), &proc_info, msg_size);
  // Send message to process
  resp_err_code = nlmsg_unicast(nl_sk, skb_out, client_pid);

  if (resp_err_code < 0)
    printk(KERN_INFO "Error while sending bak to user\n");
}


static void revealer_send_module_info(struct nlmsghdr *netlnk_message, const char *module_name, pid_t client_pid) {
  size_t msg_size;
  int resp_err_code;
  struct sk_buff *skb_out;

  msg_size = strlen(module_name) * sizeof(char) + 1;
  skb_out = nlmsg_new(msg_size, 0);

  if (!skb_out) {
    printk(KERN_ERR "Failed to allocate new skb\n");
    return;
  }

  // Send message to netlink buffer
  netlnk_message = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
  NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
  // Copy the message to the buffer
  memcpy(nlmsg_data(netlnk_message), module_name, msg_size);
  // Send message to process
  resp_err_code = nlmsg_unicast(nl_sk, skb_out, client_pid);

  if (resp_err_code < 0)
    printk(KERN_INFO "Error while sending back to user\n");
}


static void revealer_get_modules(struct nlmsghdr *netlnk_message, pid_t client_pid)
{
  struct kobject *kobj_pos, *kobj_tmp;
  struct kset *mod_kset;
  kallsyms_lookup_name_t kallsyms_lookup_name;

  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
  mod_kset = kallsyms_lookup_name("module_kset");

  // https://archive.kernel.org/oldlinux/htmldocs/kernel-api/API-list-for-each-entry-safe.html
  list_for_each_entry_safe(kobj_pos, kobj_tmp, &mod_kset->list, entry) {
    if (!kobj_tmp->name)
    {
      break;
    }
    if (atomic_read(&kobj_tmp->sd->count) < 10)
    {
      // There are some modules are not in procfs (/proc/modules). We ignore them by
      // kernfs_node->count
      continue;
    }

    revealer_send_module_info(netlnk_message, kobj_tmp->name, client_pid);
  }

  revealer_send_module_info(netlnk_message, "", client_pid);
  unregister_kprobe(&kp);
}


static void revealer_get_procs(struct nlmsghdr *netlnk_message, pid_t client_pid)
{
  /*
    Send the list of PIDs to client
  */
  struct task_struct *task_list;
  struct pid_info proc_info;

  for_each_process(task_list) {
    proc_info.pid = task_list->pid;
    proc_info.comm_len = strlen(task_list->comm);
    strncpy(proc_info.comm, task_list->comm, proc_info.comm_len);
    // Craft new message and send to the client
    revealer_send_proc_info(netlnk_message, proc_info, client_pid);
  }
  // Send pid = 0 to client so it stops the loop
  proc_info.pid = 0;
  revealer_send_proc_info(netlnk_message, proc_info, client_pid);
}


static void revealer_netlink_handler(struct sk_buff *skb)
{

  struct nlmsghdr *netlnk_message;
  pid_t client_pid;

  // TODO do we need data?
  netlnk_message = (struct nlmsghdr *)skb->data;
  client_pid = netlnk_message->nlmsg_pid;
  revealer_get_procs(netlnk_message, client_pid);
  revealer_get_modules(netlnk_message, client_pid);
}


static int revealer_module_init(void)
{

  struct netlink_kernel_cfg cfg = {
    .input = revealer_netlink_handler,
  };

  nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
  if (!nl_sk) {
    printk(KERN_ALERT "Error creating socket.\n");
    return -10;
  }

  return 0;
}


static void revealer_module_finit(void)
{
  netlink_kernel_release(nl_sk);
}


module_init(revealer_module_init);
module_exit(revealer_module_finit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Get processes and modules from kernel");
MODULE_AUTHOR("Nong Hoang Tu");
