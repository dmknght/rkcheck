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

static struct kprobe kp = {
  .symbol_name = "kallsyms_lookup_name"
};

typedef void *(*kallsyms_lookup_name_t)(const char *name);


static int test_tasks_init(void)
{
  struct kobject *cur, *tmp;
  struct kset *mod_kset;
  kallsyms_lookup_name_t kallsyms_lookup_name;

  pr_info("%s: In init\n", __func__);

  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

  mod_kset = kallsyms_lookup_name("module_kset");
  list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry) {
    struct module_kobject *kobj = container_of(tmp, struct module_kobject, kobj);
    if (!kobject_name(tmp))
      break;
    pr_info("Name: %s", kobj->mod->name);
  }

  unregister_kprobe(&kp);
  return 0;
}

static void test_tasks_exit(void)
{
  pr_info("%s: In exit\n", __func__);
}

MODULE_LICENSE("GPL");
module_init(test_tasks_init);
module_exit(test_tasks_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nong Hoang Tu");
