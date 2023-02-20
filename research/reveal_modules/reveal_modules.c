/*
  This module is the modificaiton of get_list_of_procs that transfer the result to the Netlink therefore userspace application can get the result
  Makefile (edit kern.o to the file name of .c source)
obj-m += kern.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean:w

*/

#include <linux/kprobes.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>


#define NETLINK_USER 31

struct sock *nl_sk = NULL;
static struct kprobe kp = {
  .symbol_name = "kallsyms_lookup_name"
};

typedef void *(*kallsyms_lookup_name_t)(const char *name);


static void send_msg_to_client(struct nlmsghdr *netlnk_message, const char *module_name, pid_t client_pid) {
  int msg_size;
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


static void module_handle_send_list_modules(struct nlmsghdr *netlnk_message, pid_t client_pid)
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
      /*
        There are some modules are not in procfs (/proc/modules). We ignore them by
        kernfs_node->count
      */
      continue;
    }

    send_msg_to_client(netlnk_message, kobj_tmp->name, client_pid);
  }

  send_msg_to_client(netlnk_message, "", client_pid);
  unregister_kprobe(&kp);
}


static void module_handle_connection(struct sk_buff *skb)
{

  struct nlmsghdr *netlnk_message;
  pid_t client_pid;

  netlnk_message = (struct nlmsghdr *)skb->data;
  client_pid = netlnk_message->nlmsg_pid;
  module_handle_send_list_modules(netlnk_message, client_pid);
}


static int init_reveal_module(void)
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

static void finit_reveal_module(void)
{
  netlink_kernel_release(nl_sk);
}

MODULE_LICENSE("GPL");
module_init(init_reveal_module);
module_exit(finit_reveal_module);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nong Hoang Tu");
